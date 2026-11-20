//! cryptod, the service. See the library for what it does; this is the
//! part that needs Peios: the Registry, files' security descriptors, peer
//! tokens and KMES.
//!
//! # Order at start
//!
//! 1. Read the list of what libpcrypto grades. Without it no policy can be
//!    checked, so cryptod stops, and peinit reports it.
//! 2. Compile the key and publish both copies. A compile that fails keeps
//!    whatever copies are already there, and is recorded.
//! 3. Listen for reports and for the posture, then tell peinit it's ready.
//!
//! Then it waits: on the key, which it compiles again a moment after it
//! stops changing, so that an administrator setting several values doesn't
//! publish the policy halfway, which new processes would keep for life; on
//! reports; and on requests for the posture.

use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::{Duration, Instant};

use peios::event::{EventPolicy, Tier};
use peios::file::SecInfo;
use peios::registry::Key;
use peios::security::sddl;
use peios::token::{Token, TokenAccess};

use cryptod::compile::{self, Compiled};
use cryptod::events::{self, Peer};
use cryptod::known::{self, Known};
use cryptod::posture::{self, Posture};
use cryptod::registry::{self, Registry};
use cryptod::report::{self, Report};

/// How long the key must be still before it's compiled again.
const SETTLE: Duration = Duration::from_millis(300);

/// How often a watch that couldn't be armed is tried again.
const RETRY: Duration = Duration::from_secs(15);

/// How many accepted report connections may wait for their datagram, and
/// how long each may.
const MAX_PENDING: usize = 256;
const PENDING_FOR: Duration = Duration::from_secs(1);

mod log {
    pub fn info(args: std::fmt::Arguments<'_>) {
        println!("{args}");
    }
    pub fn warn(args: std::fmt::Arguments<'_>) {
        eprintln!("warning: {args}");
    }
    pub fn error(args: std::fmt::Arguments<'_>) {
        eprintln!("error: {args}");
    }
}

fn main() {
    // A peer that closes first mustn't end the service.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let known = match fs::read_to_string(known::PATH)
        .map_err(|e| e.to_string())
        .and_then(|text| Known::parse(&text))
    {
        Ok(known) => known,
        Err(e) => {
            log::error(format_args!("reading {}: {e}", known::PATH));
            std::process::exit(1);
        }
    };
    match Token::open_self(true, TokenAccess::QUERY).and_then(|t| t.user()) {
        Ok(me) if me.to_string() == cryptod::SID => {}
        Ok(me) => log::error(format_args!(
            "running as {me}, not cryptod's service SID {}: libpcrypto won't trust the \
             policy copies this process writes. Its Identity must be Service.",
            cryptod::SID
        )),
        Err(e) => log::warn(format_args!("could not read cryptod's own identity ({e})")),
    }
    let policy = EventPolicy::open()
        .map_err(|e| log::warn(format_args!("could not open the event policy ({e}); standard records are written")))
        .ok();
    protect(Path::new("/run/cryptod"), &cryptod::directory_sddl());

    let mut service = Service {
        known,
        events: policy,
        compiled: Compiled {
            policy: Default::default(),
            dropped: Vec::new(),
            admit_non_fips: Vec::new(),
            defaults: true,
        },
        published: None,
        last_failure: None,
        posture: Posture::default(),
        watch: None,
        watch_retry: Instant::now(),
        settle: None,
        pending: Vec::new(),
    };
    service.compile(true);
    service.arm();

    let reports = match listen(report::SOCKET, libc::SOCK_SEQPACKET, &cryptod::report_sddl()) {
        Ok(fd) => fd,
        Err(e) => {
            log::error(format_args!("listening on {}: {e}", report::SOCKET));
            std::process::exit(1);
        }
    };
    let posture = match listen(posture::SOCKET, libc::SOCK_STREAM, &cryptod::posture_sddl()) {
        Ok(fd) => Some(fd),
        Err(e) => {
            log::warn(format_args!("listening on {}: {e}; no posture is served", posture::SOCKET));
            None
        }
    };
    notify(b"READY=1");
    log::info(format_args!("cryptod is ready"));

    loop {
        service.wait(&reports, posture.as_ref());
    }
}

struct Service {
    known: Known,
    events: Option<EventPolicy>,
    compiled: Compiled,
    /// The bytes last published, so an unchanged policy isn't again.
    published: Option<Vec<u8>>,
    last_failure: Option<(String, String)>,
    posture: Posture,
    watch: Option<Key>,
    watch_retry: Instant,
    /// When the key, having changed, is compiled again.
    settle: Option<Instant>,
    /// Accepted report connections whose datagram hasn't arrived.
    pending: Vec<(OwnedFd, Instant)>,
}

impl Service {
    /// Writes an essential record, or a standard one if the event policy
    /// lets it; logs one that can't be written.
    fn emit(&self, event_type: &str, tier: Tier, payload: peios::Result<Vec<u8>>) {
        let result = payload.and_then(|bytes| match (&self.events, tier) {
            (Some(policy), Tier::Standard) => policy.emit_with(event_type, tier, || bytes).map(|_| ()),
            _ => peios::event::emit(event_type, &bytes),
        });
        if let Err(e) = result {
            log::warn(format_args!("could not record {event_type}: {e}"));
        }
    }

    fn failed(&mut self, reason: &str, detail: &str, exception: Option<&str>) {
        log::error(format_args!("{detail}"));
        self.emit(
            events::POLICY_FAILED,
            Tier::Essential,
            events::policy_failed(reason, detail, exception, None),
        );
    }

    /// Compiles the key and publishes it, if it changed or `always`.
    fn compile(&mut self, always: bool) {
        let compiled = Registry::open()
            .map_err(compile::Failure::Unreadable)
            .and_then(|r| {
                compile::compile(&r, &self.known, &cryptod::check_program_security, &cryptod::parse_sddl)
            });
        let compiled = match compiled {
            Ok(c) => c,
            Err(failure) => {
                let detail = format!("{failure}; the policy already published is kept");
                self.failed(failure.reason(), &detail, None);
                self.last_failure = Some((failure.reason().into(), detail));
                return;
            }
        };
        let bytes = compiled.policy.encode();
        if !always && self.published.as_deref() == Some(bytes.as_slice()) {
            return;
        }
        for (name, why) in &compiled.dropped {
            let detail = format!("the exception {name} is ignored: {why}");
            self.failed(why.reason(), &detail, Some(name));
        }
        let mut current = false;
        for path in [cryptod::CURRENT, cryptod::LAST_KNOWN] {
            match write_copy(Path::new(path), &bytes) {
                Ok(()) => current |= path == cryptod::CURRENT,
                Err(e) => self.failed("write-failed", &format!("writing {path}: {e}"), None),
            }
        }
        if !current {
            self.last_failure = Some(("write-failed".into(), format!("{} wasn't written", cryptod::CURRENT)));
            return;
        }
        log::info(format_args!(
            "published the policy: reject below {}, warn below {}, {} exceptions",
            compiled.policy.reject_below.letter(),
            compiled.policy.warn_below.letter(),
            compiled.policy.exceptions.len()
        ));
        self.emit(events::POLICY_APPLIED, Tier::Standard, events::policy_applied(&compiled));
        self.published = Some(bytes);
        self.compiled = compiled;
        self.last_failure = None;
    }

    /// Arms the watch, on the key or, while it doesn't exist, its parent.
    fn arm(&mut self) {
        match registry::watch() {
            Ok(key) => self.watch = Some(key),
            Err(e) => {
                log::warn(format_args!("could not watch {} ({e}); trying again", compile::KEY));
                self.watch = None;
                self.watch_retry = Instant::now() + RETRY;
            }
        }
    }

    fn wait(&mut self, reports: &OwnedFd, posture: Option<&OwnedFd>) {
        let now = Instant::now();
        self.pending.retain(|(_, deadline)| *deadline > now);
        let mut deadline = self.settle;
        if self.watch.is_none() {
            deadline = Some(deadline.map_or(self.watch_retry, |d| d.min(self.watch_retry)));
        }
        if let Some((_, d)) = self.pending.iter().min_by_key(|(_, d)| *d) {
            deadline = Some(deadline.map_or(*d, |x| x.min(*d)));
        }
        let timeout = deadline.map_or(-1, |d| {
            i32::try_from(d.saturating_duration_since(now).as_millis()).unwrap_or(i32::MAX).max(1)
        });

        let mut fds = vec![poll_in(reports.as_raw_fd())];
        if let Some(p) = posture {
            fds.push(poll_in(p.as_raw_fd()));
        }
        let watch_slot = self.watch.as_ref().map(|w| {
            fds.push(poll_in(w.as_raw_fd()));
            fds.len() - 1
        });
        let first_pending = fds.len();
        fds.extend(self.pending.iter().map(|(fd, _)| poll_in(fd.as_raw_fd())));
        // SAFETY: a slice we own, its length, and poll(2) writes only `revents`.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };

        // Pending connections first, by index, before the list changes.
        let ready: Vec<usize> = (0..self.pending.len())
            .filter(|&i| fds[first_pending + i].revents != 0)
            .collect();
        for i in ready.into_iter().rev() {
            let (fd, _) = self.pending.swap_remove(i);
            self.receive(fd);
        }
        if fds[0].revents != 0 {
            self.accept_reports(reports);
        }
        if let Some(p) = posture
            && fds[1].revents != 0
        {
            self.serve_posture(p);
        }
        if let Some(slot) = watch_slot
            && fds[slot].revents != 0
        {
            self.drain_watch();
        }

        let now = Instant::now();
        if self.settle.is_some_and(|d| d <= now) {
            self.settle = None;
            log::info(format_args!("{} changed; compiling it again", compile::KEY));
            self.compile(false);
            self.arm();
        }
        if self.watch.is_none() && self.watch_retry <= now {
            self.arm();
            // What changed while unwatched.
            self.compile(false);
        }
    }

    fn drain_watch(&mut self) {
        let Some(watch) = &self.watch else { return };
        let mut buffer = vec![0u8; 16384];
        match watch.read_watch_events(&mut buffer) {
            Ok(events) if events.is_empty() => {}
            Ok(_) => self.settle = Some(Instant::now() + SETTLE),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                log::warn(format_args!("the watch on {} failed ({e}); re-arming", compile::KEY));
                self.settle = Some(Instant::now() + SETTLE);
                self.arm();
            }
        }
    }

    fn accept_reports(&mut self, listener: &OwnedFd) {
        loop {
            // SAFETY: a listening socket we own; no address is asked for.
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                return;
            }
            // SAFETY: accept4 returned a new descriptor, now owned here.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if !self.receive_now(&fd) {
                if self.pending.len() >= MAX_PENDING {
                    self.posture.limited += 1;
                    self.pending.remove(0);
                }
                self.pending.push((fd, Instant::now() + PENDING_FOR));
            }
        }
    }

    /// Receives the report on `fd`, if it has arrived: whether it was
    /// handled, so `fd` is done with.
    fn receive_now(&mut self, fd: &OwnedFd) -> bool {
        let mut buf = [0u8; report::MAX + 1];
        // SAFETY: a socket we own and a buffer of the length given.
        let n = unsafe {
            libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT)
        };
        if n < 0 {
            return io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock;
        }
        if n == 0 {
            return true;
        }
        let msg = &buf[..n as usize];
        let Some(report) = report::parse(msg, &self.known) else {
            self.posture.invalid += 1;
            return true;
        };
        let Some(peer) = peer(fd.as_fd()) else {
            self.posture.unattributed += 1;
            return true;
        };
        if !self.posture.admit(&peer.sid, Instant::now()) {
            return true;
        }
        self.relay(&peer, report);
        true
    }

    fn receive(&mut self, fd: OwnedFd) {
        self.receive_now(&fd);
    }

    fn relay(&mut self, peer: &Peer, report: Report) {
        match report {
            Report::Warned { id } => {
                self.posture.warned(&peer.sid, &id);
                self.emit(events::ALGORITHM_WARNED, Tier::Standard, events::algorithm_warned(peer, &id));
            }
            Report::ExceptionUsed { id, exception } => {
                self.posture.exception_used(&peer.sid, &id, &exception);
                self.emit(
                    events::EXCEPTION_USED,
                    Tier::Essential,
                    events::exception_used(peer, &id, &exception),
                );
            }
            Report::PolicyUnusable { problem } => {
                let detail = format!(
                    "a process couldn't use the policy ({}), so it fell back",
                    problem.reason()
                );
                self.emit(
                    events::POLICY_FAILED,
                    Tier::Essential,
                    events::policy_failed(problem.reason(), &detail, None, Some(peer)),
                );
            }
        }
    }

    fn serve_posture(&mut self, listener: &OwnedFd) {
        loop {
            // SAFETY: as in accept_reports.
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                return;
            }
            // SAFETY: a new descriptor, now owned here.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let failure = self.last_failure.as_ref().map(|(r, d)| (r.as_str(), d.as_str()));
            match self.posture.encode(&self.compiled, failure) {
                Ok(bytes) => {
                    let mut stream = std::os::unix::net::UnixStream::from(fd);
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let _ = stream.write_all(&bytes);
                }
                Err(e) => log::warn(format_args!("could not encode the posture: {e}")),
            }
        }
    }
}

/// Who's on the other end: the user of the token the kernel captured at
/// connect, and the pid it recorded then.
fn peer(fd: BorrowedFd<'_>) -> Option<Peer> {
    let sid = Token::open_peer(fd).and_then(|t| t.user()).ok()?;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a socket we own, and `cred` sized as given.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    let pid = if r == 0 { u32::try_from(cred.pid).unwrap_or(0) } else { 0 };
    Some(Peer { sid: sid.as_bytes().to_vec(), pid })
}

fn poll_in(fd: RawFd) -> libc::pollfd {
    libc::pollfd { fd, events: libc::POLLIN, revents: 0 }
}

/// A listening socket at `path`, replacing one a previous run left, with
/// the descriptor `sddl`.
fn listen(path: &str, kind: libc::c_int, sddl: &str) -> io::Result<OwnedFd> {
    let _ = fs::remove_file(path);
    // SAFETY: plain syscalls on a descriptor owned from creation.
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if path.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(path.bytes()) {
        *dst = src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast(), len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let sd = sddl::parse(sddl)?;
    peios::file::set_sd(None, Path::new(path), SecInfo::DACL, &sd, 0)?;
    // SAFETY: a bound socket we own.
    if unsafe { libc::listen(fd.as_raw_fd(), libc::SOMAXCONN) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Writes a copy whole, or not at all: to a new file beside it, given the
/// copy's descriptor, then renamed over it. A reader never sees a partial
/// copy, nor one with the descriptor the directory would have given it,
/// which libpcrypto might not trust.
fn write_copy(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let staged = dir.join(".policy.new");
    let _ = fs::remove_file(&staged);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let sd = sddl::parse(&cryptod::copy_sddl())?;
    peios::file::set_sd(None, &staged, SecInfo::DACL, &sd, 0)?;
    fs::rename(&staged, path)?;
    fs::File::open(dir)?.sync_all()
}

/// Sets `path`'s DACL to `sddl`, logging a failure: a directory readers
/// can't traverse hides the policy from them.
fn protect(path: &Path, sddl: &str) {
    let result = sddl::parse(sddl).and_then(|sd| peios::file::set_sd(None, path, SecInfo::DACL, &sd, 0));
    if let Err(e) = result {
        log::error(format_args!(
            "could not set the descriptor of {} ({e}); processes that can't traverse it \
             fall back to the default policy",
            path.display()
        ));
    }
}

/// Tells peinit, best-effort.
fn notify(payload: &[u8]) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let result = UnixDatagram::unbound().and_then(|s| {
        s.set_write_timeout(Some(Duration::from_secs(1)))?;
        s.send_to(payload, Path::new(&path)).map(|_| ())
    });
    if let Err(e) = result {
        log::warn(format_args!("notify: {e}"));
    }
}
