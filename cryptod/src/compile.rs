//! Compiling `Machine\System\Cryptography` into a [`Policy`].
//!
//! ```text
//! Machine\System\Cryptography
//!     Reject\  MinimumGrade (REG_SZ, U to A), FIPS (REG_DWORD)
//!     Warn\    MinimumGrade, FIPS
//!     Exceptions\
//!         Enabled, WarnByDefault, WarnAlways, AllowExceptionsToReject (REG_DWORD)
//!         <Owner>.<Purpose>\
//!             Algorithms      REG_MULTI_SZ of algorithms.toml ids, md5.hmac say
//!             ProgramSecurity REG_BINARY, a self-relative SD, or REG_SZ, SDDL
//!             Warn            REG_DWORD, else WarnByDefault
//! ```
//!
//! A value that's absent takes Peios's default. A setting that's present but
//! can't be read fails the whole compile: falling back to a default could
//! loosen a policy an administrator tightened, so the copies already
//! published are kept instead. Only an absent key, as on a first boot, means
//! the defaults.
//!
//! An exception that can't be applied as written loosens nothing: it's
//! dropped whole, and reported. That covers an unknown identifier, one on the
//! floor, a `ProgramSecurity` that isn't a security descriptor with a DACL,
//! and anything too long for the policy file.

use std::collections::BTreeSet;
use std::fmt;
use std::io;

use crate::known::Known;
use crate::policy::{Exception, Grade, Policy, valid_exception_name};

/// The key, relative to the Registry root.
pub const KEY: &str = "Machine\\System\\Cryptography";

/// The largest policy file libpcrypto reads is just under 1 MiB.
pub const FILE_MAX: usize = (1 << 20) - 1;

/// A Registry value, as far as the compiler reads one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Sz(String),
    Multi(Vec<String>),
    Dword(u32),
    Binary(Vec<u8>),
    /// Any other type, by number, or text that isn't UTF-8.
    Other(u32),
}

/// What the compiler reads the key through: the Registry, in one read
/// transaction, or a test's fixture. Paths are relative to [`KEY`], `""`
/// for the key itself.
pub trait Source {
    /// The subkeys of `path`, or `None` if there's no such key.
    fn subkeys(&self, path: &str) -> io::Result<Option<Vec<String>>>;
    /// The value `name` of `path`, or `None` if there's no such value or key.
    fn value(&self, path: &str, name: &str) -> io::Result<Option<Value>>;
}

/// Why the compile failed, so nothing was published.
#[derive(Debug)]
pub enum Failure {
    /// The Registry couldn't be read.
    Unreadable(io::Error),
    /// A setting was present but couldn't be read as one.
    Invalid { setting: String, why: String },
    /// The policy wouldn't fit the file libpcrypto reads.
    TooLarge(usize),
}

impl Failure {
    /// The event's `outcome.reason`.
    pub fn reason(&self) -> &'static str {
        match self {
            Failure::Unreadable(_) => "registry-unreadable",
            Failure::Invalid { .. } => "invalid-setting",
            Failure::TooLarge(_) => "too-large",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Unreadable(e) => write!(f, "reading {KEY}: {e}"),
            Failure::Invalid { setting, why } => write!(f, "{KEY}\\{setting}: {why}"),
            Failure::TooLarge(n) => write!(f, "the policy is {n} bytes, over the {FILE_MAX} libpcrypto reads"),
        }
    }
}

/// Why an exception was dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dropped {
    InvalidName,
    UnknownAlgorithm(String),
    FloorAlgorithm(String),
    NoAlgorithms,
    InvalidAlgorithms(String),
    InvalidProgramSecurity(String),
    InvalidWarn(String),
    TooLarge,
}

impl Dropped {
    /// The event's `outcome.reason`.
    pub fn reason(&self) -> &'static str {
        match self {
            Dropped::InvalidName => "invalid-exception-name",
            Dropped::UnknownAlgorithm(_) => "unknown-algorithm",
            Dropped::FloorAlgorithm(_) => "floor-algorithm",
            Dropped::NoAlgorithms => "no-algorithms",
            Dropped::InvalidAlgorithms(_) => "invalid-algorithms",
            Dropped::InvalidProgramSecurity(_) => "invalid-program-security",
            Dropped::InvalidWarn(_) => "invalid-setting",
            Dropped::TooLarge => "too-large",
        }
    }
}

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dropped::InvalidName => {
                write!(f, "its name isn't Owner.Purpose, in at most 255 printable ASCII bytes")
            }
            Dropped::UnknownAlgorithm(id) => write!(f, "libpcrypto grades no {id:?}"),
            Dropped::FloorAlgorithm(id) => write!(f, "{id} is on the floor, which nothing excepts"),
            Dropped::NoAlgorithms => write!(f, "it names no algorithms"),
            Dropped::InvalidAlgorithms(why) => write!(f, "Algorithms: {why}"),
            Dropped::InvalidProgramSecurity(why) => write!(f, "ProgramSecurity: {why}"),
            Dropped::InvalidWarn(why) => write!(f, "Warn: {why}"),
            Dropped::TooLarge => write!(f, "it's too long for the policy file"),
        }
    }
}

/// A compiled policy, and what was dropped from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub policy: Policy,
    /// Each dropped exception, by name, and why.
    pub dropped: Vec<(String, Dropped)>,
    /// The exceptions that admit entries FIPS doesn't approve. Under
    /// `Reject\FIPS` they mark the machine as not operating in a
    /// FIPS-approved mode.
    pub admit_non_fips: Vec<String>,
    /// Whether the key was absent, so these are Peios's defaults.
    pub defaults: bool,
}

/// Checks a `ProgramSecurity` SD: it must parse, and carry a DACL, as a NULL
/// or absent one would let every program use the exception. Supplied by the
/// caller, since parsing needs libpeios.
pub type SdCheck = dyn Fn(&[u8]) -> Result<(), String>;

/// Turns SDDL into a self-relative SD. Supplied by the caller, as above.
pub type SddlParse = dyn Fn(&str) -> Result<Vec<u8>, String>;

pub fn compile(
    source: &impl Source,
    known: &Known,
    check_sd: &SdCheck,
    parse_sddl: &SddlParse,
) -> Result<Compiled, Failure> {
    let mut policy = Policy::default();
    let Some(_) = source.subkeys("").map_err(Failure::Unreadable)? else {
        return Ok(Compiled { policy, dropped: Vec::new(), admit_non_fips: Vec::new(), defaults: true });
    };
    if let Some(g) = grade(source, "Reject", "MinimumGrade")? {
        policy.reject_below = g;
    }
    if let Some(b) = flag(source, "Reject", "FIPS")? {
        policy.reject_non_fips = b;
    }
    if let Some(g) = grade(source, "Warn", "MinimumGrade")? {
        policy.warn_below = g;
    }
    if let Some(b) = flag(source, "Warn", "FIPS")? {
        policy.warn_non_fips = b;
    }
    let enabled = flag(source, "Exceptions", "Enabled")?.unwrap_or(true);
    let warn_by_default = flag(source, "Exceptions", "WarnByDefault")?.unwrap_or(false);
    let warn_always = flag(source, "Exceptions", "WarnAlways")?.unwrap_or(false);
    if let Some(b) = flag(source, "Exceptions", "AllowExceptionsToReject")? {
        policy.exceptions_may_reject = b;
    }

    let mut dropped = Vec::new();
    let mut admit_non_fips = Vec::new();
    let names = if enabled {
        source.subkeys("Exceptions").map_err(Failure::Unreadable)?.unwrap_or_default()
    } else {
        Vec::new()
    };
    for name in names {
        let path = format!("Exceptions\\{name}");
        match exception(source, &path, &name, known, check_sd, parse_sddl)? {
            Ok((read, non_fips)) => {
                if non_fips {
                    admit_non_fips.push(name.clone());
                }
                policy.exceptions.push(Exception {
                    name: read.name,
                    warn: warn_always || read.warn.unwrap_or(warn_by_default),
                    program_security: read.program_security,
                    algorithms: read.algorithms,
                });
            }
            Err(why) => dropped.push((name, why)),
        }
    }
    if policy.exceptions.len() > usize::from(u16::MAX) {
        for e in policy.exceptions.drain(usize::from(u16::MAX)..) {
            dropped.push((e.name, Dropped::TooLarge));
        }
    }
    let size = policy.encode().len();
    if size > FILE_MAX {
        return Err(Failure::TooLarge(size));
    }
    Ok(Compiled { policy, dropped, admit_non_fips, defaults: false })
}

/// An exception as read: its own `Warn`, before `WarnByDefault` and
/// `WarnAlways`.
struct Read {
    name: String,
    warn: Option<bool>,
    program_security: Vec<u8>,
    algorithms: Vec<String>,
}

/// Reads one exception: `Err(Failure)` if the Registry couldn't be read,
/// `Ok(Err(why))` if it's dropped, else it and whether it admits an entry
/// FIPS doesn't approve.
fn exception(
    source: &impl Source,
    path: &str,
    name: &str,
    known: &Known,
    check_sd: &SdCheck,
    parse_sddl: &SddlParse,
) -> Result<Result<(Read, bool), Dropped>, Failure> {
    let value = |n: &str| source.value(path, n).map_err(Failure::Unreadable);
    if !valid_exception_name(name) {
        return Ok(Err(Dropped::InvalidName));
    }
    let algorithms = match value("Algorithms")? {
        Some(Value::Multi(ids)) => ids,
        Some(Value::Sz(id)) => vec![id],
        Some(_) => return Ok(Err(Dropped::InvalidAlgorithms("not REG_MULTI_SZ".into()))),
        None => Vec::new(),
    };
    let mut ids = BTreeSet::new();
    for id in algorithms.iter().map(|id| id.trim()).filter(|id| !id.is_empty()) {
        ids.insert(id.to_string());
    }
    if ids.is_empty() {
        return Ok(Err(Dropped::NoAlgorithms));
    }
    let mut non_fips = false;
    for id in &ids {
        match known.get(id) {
            None => return Ok(Err(Dropped::UnknownAlgorithm(id.clone()))),
            Some(entry) if entry.grade.is_none() => {
                return Ok(Err(Dropped::FloorAlgorithm(id.clone())));
            }
            Some(entry) => non_fips |= !entry.fips,
        }
    }
    let program_security = match value("ProgramSecurity")? {
        Some(Value::Binary(sd)) => sd,
        Some(Value::Sz(sddl)) => match parse_sddl(&sddl) {
            Ok(sd) => sd,
            Err(why) => return Ok(Err(Dropped::InvalidProgramSecurity(why))),
        },
        Some(_) => {
            return Ok(Err(Dropped::InvalidProgramSecurity(
                "neither REG_BINARY nor REG_SZ".into(),
            )));
        }
        None => return Ok(Err(Dropped::InvalidProgramSecurity("absent".into()))),
    };
    if let Err(why) = check_sd(&program_security) {
        return Ok(Err(Dropped::InvalidProgramSecurity(why)));
    }
    let warn = match value("Warn")? {
        None => None,
        Some(Value::Dword(v)) => Some(v != 0),
        Some(_) => return Ok(Err(Dropped::InvalidWarn("not REG_DWORD".into()))),
    };
    if program_security.len() > usize::from(u16::MAX)
        || ids.len() > usize::from(u16::MAX)
        || ids.iter().any(|id| id.len() > 255)
    {
        return Ok(Err(Dropped::TooLarge));
    }
    Ok(Ok((
        Read {
            name: name.to_string(),
            warn,
            program_security,
            algorithms: ids.into_iter().collect(),
        },
        non_fips,
    )))
}

fn invalid(path: &str, name: &str, why: &str) -> Failure {
    Failure::Invalid { setting: format!("{path}\\{name}"), why: why.into() }
}

fn grade(source: &impl Source, path: &str, name: &str) -> Result<Option<Grade>, Failure> {
    match source.value(path, name).map_err(Failure::Unreadable)? {
        None => Ok(None),
        Some(Value::Sz(text)) => Grade::parse(&text)
            .map(Some)
            .ok_or_else(|| invalid(path, name, &format!("{text:?} isn't a grade, U to A"))),
        Some(_) => Err(invalid(path, name, "not REG_SZ")),
    }
}

fn flag(source: &impl Source, path: &str, name: &str) -> Result<Option<bool>, Failure> {
    match source.value(path, name).map_err(Failure::Unreadable)? {
        None => Ok(None),
        Some(Value::Dword(v)) => Ok(Some(v != 0)),
        Some(_) => Err(invalid(path, name, "not REG_DWORD")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A key: each path's values, by name. A path present with no values is
    /// a key with none. `fail` makes every read fail.
    #[derive(Default)]
    struct Fixture {
        keys: BTreeMap<String, BTreeMap<String, Value>>,
        fail: bool,
    }

    impl Fixture {
        fn root() -> Fixture {
            let mut f = Fixture::default();
            f.keys.insert(String::new(), BTreeMap::new());
            f
        }

        fn set(&mut self, path: &str, name: &str, value: Value) -> &mut Fixture {
            let mut prefix = String::new();
            for part in path.split('\\') {
                if !prefix.is_empty() {
                    prefix.push('\\');
                }
                prefix.push_str(part);
                self.keys.entry(prefix.clone()).or_default();
            }
            self.keys.get_mut(path).unwrap().insert(name.into(), value);
            self
        }

        fn exception(&mut self, name: &str, ids: &[&str], sd: Value) -> &mut Fixture {
            let path = format!("Exceptions\\{name}");
            self.set(&path, "Algorithms", Value::Multi(ids.iter().map(|s| s.to_string()).collect()));
            self.set(&path, "ProgramSecurity", sd)
        }
    }

    impl Source for Fixture {
        fn subkeys(&self, path: &str) -> io::Result<Option<Vec<String>>> {
            if self.fail {
                return Err(io::Error::other("the Registry is down"));
            }
            if !self.keys.contains_key(path) {
                return Ok(None);
            }
            let prefix = if path.is_empty() { String::new() } else { format!("{path}\\") };
            Ok(Some(
                self.keys
                    .keys()
                    .filter_map(|k| k.strip_prefix(&prefix))
                    .filter(|rest| !rest.is_empty() && !rest.contains('\\'))
                    .map(str::to_string)
                    .collect(),
            ))
        }

        fn value(&self, path: &str, name: &str) -> io::Result<Option<Value>> {
            if self.fail {
                return Err(io::Error::other("the Registry is down"));
            }
            Ok(self.keys.get(path).and_then(|values| values.get(name)).cloned())
        }
    }

    fn known() -> Known {
        Known::parse(
            "md5.hmac\tD\t0\nmd5.digest\tU\t0\nsha1.hmac\tC\t1\nenc-null.encrypt\tfloor\t0\n",
        )
        .unwrap()
    }

    fn sd(bytes: &[u8]) -> Result<(), String> {
        if bytes == b"no-dacl" { Err("no DACL".into()) } else { Ok(()) }
    }

    fn sddl(text: &str) -> Result<Vec<u8>, String> {
        if text == "bad" { Err("not SDDL".into()) } else { Ok(format!("sd:{text}").into_bytes()) }
    }

    fn run(f: &Fixture) -> Result<Compiled, Failure> {
        compile(f, &known(), &sd, &sddl)
    }

    fn sz(s: &str) -> Value {
        Value::Sz(s.into())
    }

    #[test]
    fn an_absent_key_is_peioss_defaults() {
        let c = run(&Fixture::default()).unwrap();
        assert!(c.defaults);
        assert_eq!(c.policy, Policy::default());
    }

    #[test]
    fn an_empty_key_is_the_defaults_too_but_not_marked_absent() {
        let c = run(&Fixture::root()).unwrap();
        assert!(!c.defaults);
        assert_eq!(c.policy, Policy::default());
    }

    #[test]
    fn thresholds_and_switches_are_read() {
        let mut f = Fixture::root();
        f.set("Reject", "MinimumGrade", sz("c"))
            .set("Reject", "FIPS", Value::Dword(1))
            .set("Warn", "MinimumGrade", sz("B"))
            .set("Warn", "FIPS", Value::Dword(0))
            .set("Exceptions", "AllowExceptionsToReject", Value::Dword(0));
        let p = run(&f).unwrap().policy;
        assert_eq!(p.reject_below, Grade::C);
        assert!(p.reject_non_fips);
        assert_eq!(p.warn_below, Grade::B);
        assert!(!p.warn_non_fips);
        assert!(!p.exceptions_may_reject);
    }

    #[test]
    fn a_setting_that_cant_be_read_fails_the_compile_rather_than_loosening() {
        for (path, name, value) in [
            ("Reject", "MinimumGrade", sz("E")),
            ("Reject", "MinimumGrade", Value::Dword(2)),
            ("Reject", "FIPS", sz("yes")),
            ("Warn", "MinimumGrade", sz("")),
            ("Exceptions", "Enabled", Value::Binary(vec![1])),
        ] {
            let mut f = Fixture::root();
            f.set(path, name, value);
            assert!(
                matches!(run(&f), Err(Failure::Invalid { .. })),
                "{path}\\{name} was accepted"
            );
        }
    }

    #[test]
    fn a_registry_that_cant_be_read_fails_the_compile() {
        let f = Fixture { fail: true, ..Fixture::default() };
        assert!(matches!(run(&f), Err(Failure::Unreadable(_))));
    }

    #[test]
    fn an_exception_is_compiled_from_sddl_or_a_binary_sd() {
        let mut f = Fixture::root();
        f.exception("Radius.PacketAuth", &["md5.hmac", " md5.digest ", "md5.hmac"], sz("D:(A;;0x1;;;WD)"))
            .exception("Authd.Ntlm", &["sha1.hmac"], Value::Binary(b"raw".to_vec()));
        let c = run(&f).unwrap();
        assert!(c.dropped.is_empty());
        let by_name = |n: &str| c.policy.exceptions.iter().find(|e| e.name == n).unwrap().clone();
        let radius = by_name("Radius.PacketAuth");
        assert_eq!(radius.algorithms, ["md5.digest", "md5.hmac"]);
        assert_eq!(radius.program_security, b"sd:D:(A;;0x1;;;WD)");
        assert!(!radius.warn);
        assert_eq!(by_name("Authd.Ntlm").program_security, b"raw");
        // MD5 isn't FIPS-approved; HMAC-SHA-1 is.
        assert_eq!(c.admit_non_fips, ["Radius.PacketAuth"]);
    }

    #[test]
    fn warn_falls_back_to_warn_by_default_and_warn_always_overrides_it() {
        let mut f = Fixture::root();
        f.exception("A.Own", &["md5.hmac"], sz("x"))
            .set("Exceptions\\A.Own", "Warn", Value::Dword(0))
            .exception("B.Default", &["md5.hmac"], sz("x"))
            .set("Exceptions", "WarnByDefault", Value::Dword(1));
        let warn = |c: &Compiled, n: &str| c.policy.exceptions.iter().find(|e| e.name == n).unwrap().warn;
        let c = run(&f).unwrap();
        assert!(!warn(&c, "A.Own"));
        assert!(warn(&c, "B.Default"));
        f.set("Exceptions", "WarnAlways", Value::Dword(1));
        let c = run(&f).unwrap();
        assert!(warn(&c, "A.Own"));
    }

    #[test]
    fn an_exception_that_cant_apply_as_written_is_dropped_whole() {
        // Each exception, how it's written, and why it's dropped.
        type Case = (&'static str, Box<dyn Fn(&mut Fixture)>, &'static str);
        let cases: Vec<Case> = vec![
            ("Radius.Typo", Box::new(|f| { f.exception("Radius.Typo", &["md5.hmac", "md5.hmca"], sz("x")); }), "unknown-algorithm"),
            ("Radius.Null", Box::new(|f| { f.exception("Radius.Null", &["md5.hmac", "enc-null.encrypt"], sz("x")); }), "floor-algorithm"),
            ("Radius.Empty", Box::new(|f| { f.exception("Radius.Empty", &[" "], sz("x")); }), "no-algorithms"),
            ("Radius.Sddl", Box::new(|f| { f.exception("Radius.Sddl", &["md5.hmac"], sz("bad")); }), "invalid-program-security"),
            ("Radius.Open", Box::new(|f| { f.exception("Radius.Open", &["md5.hmac"], Value::Binary(b"no-dacl".to_vec())); }), "invalid-program-security"),
            ("Radius.None", Box::new(|f| { f.set("Exceptions\\Radius.None", "Algorithms", Value::Multi(vec!["md5.hmac".into()])); }), "invalid-program-security"),
            ("Radius.Kind", Box::new(|f| { f.exception("Radius.Kind", &["md5.hmac"], Value::Dword(1)); }), "invalid-program-security"),
            ("Radius.Warn", Box::new(|f| { f.exception("Radius.Warn", &["md5.hmac"], sz("x")).set("Exceptions\\Radius.Warn", "Warn", sz("no")); }), "invalid-setting"),
            ("NoPurpose", Box::new(|f| { f.exception("NoPurpose", &["md5.hmac"], sz("x")); }), "invalid-exception-name"),
            (".Purpose", Box::new(|f| { f.exception(".Purpose", &["md5.hmac"], sz("x")); }), "invalid-exception-name"),
            ("Radius.Packet Auth", Box::new(|f| { f.exception("Radius.Packet Auth", &["md5.hmac"], sz("x")); }), "invalid-exception-name"),
        ];
        for (name, build, reason) in cases {
            let mut f = Fixture::root();
            build(&mut f);
            f.exception("Kept.Fine", &["md5.digest"], sz("x"));
            let c = run(&f).unwrap();
            assert_eq!(c.policy.exceptions.len(), 1, "{name} wasn't dropped");
            assert_eq!(c.policy.exceptions[0].name, "Kept.Fine");
            assert_eq!(c.dropped.len(), 1);
            assert_eq!(c.dropped[0].0, name);
            assert_eq!(c.dropped[0].1.reason(), reason, "{name}");
        }
    }

    #[test]
    fn disabled_exceptions_compile_to_none() {
        let mut f = Fixture::root();
        f.exception("Radius.PacketAuth", &["md5.hmac"], sz("x"))
            .set("Exceptions", "Enabled", Value::Dword(0));
        let c = run(&f).unwrap();
        assert!(c.policy.exceptions.is_empty());
        assert!(c.dropped.is_empty());
    }
}
