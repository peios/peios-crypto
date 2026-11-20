//! What weak crypto is in use, since cryptod started: the posture report,
//! and the per-user limit on how fast reports are relayed.
//!
//! Usage is kept by the reporting token's user SID: which exceptions it used
//! for which entries, and which entries it was warned about, each counted by
//! the processes that reported it. Every table is bounded, and what's turned
//! away is counted, so that a flood of reports costs memory it can't grow.
//!
//! The report is one MessagePack map, served on a socket only SYSTEM and
//! Administrators may connect to; a command that prints it can come later.

use std::collections::BTreeMap;
use std::time::Instant;

use peios::msgpack::Writer;

use crate::compile::Compiled;

pub const SOCKET: &str = "/run/cryptod/posture";

/// How many users' usage is kept, and how many exceptions per user.
const MAX_USERS: usize = 4096;
const MAX_EXCEPTIONS: usize = 256;

/// Each user may have this many reports relayed at once, refilled at
/// `RATE` a second: enough for every process a user starts to report all
/// it uses, and too few for one user to flood the event store.
const BURST: f64 = 512.0;
const RATE: f64 = 8.0;

#[derive(Default, Debug)]
struct Usage {
    /// Exception, then entry, then the reports of its use.
    exceptions: BTreeMap<String, BTreeMap<String, u64>>,
    /// Entry, then the reports of its warning.
    warned: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Default, Debug)]
pub struct Posture {
    usage: BTreeMap<Vec<u8>, Usage>,
    buckets: BTreeMap<Vec<u8>, Bucket>,
    /// Reports turned away: over a user's rate, from a peer with no
    /// readable identity, not a report libpcrypto could send, or beyond a
    /// table's bound.
    pub limited: u64,
    pub unattributed: u64,
    pub invalid: u64,
    pub overflow: u64,
}

impl Posture {
    /// Whether `sid` may have one more report relayed `now`.
    pub fn admit(&mut self, sid: &[u8], now: Instant) -> bool {
        if !self.buckets.contains_key(sid) && self.buckets.len() >= MAX_USERS {
            // Forget the users whose allowance has refilled: they're
            // indistinguishable from ones never seen.
            self.buckets.retain(|_, b| refill(*b, now).tokens < BURST);
            if self.buckets.len() >= MAX_USERS {
                self.limited += 1;
                return false;
            }
        }
        let bucket = self.buckets.entry(sid.to_vec()).or_insert(Bucket { tokens: BURST, at: now });
        *bucket = refill(*bucket, now);
        if bucket.tokens < 1.0 {
            self.limited += 1;
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }

    fn user(&mut self, sid: &[u8]) -> Option<&mut Usage> {
        if !self.usage.contains_key(sid) && self.usage.len() >= MAX_USERS {
            self.overflow += 1;
            return None;
        }
        Some(self.usage.entry(sid.to_vec()).or_default())
    }

    pub fn warned(&mut self, sid: &[u8], id: &str) {
        if let Some(u) = self.user(sid) {
            *u.warned.entry(id.to_string()).or_default() += 1;
        }
    }

    pub fn exception_used(&mut self, sid: &[u8], id: &str, exception: &str) {
        let Some(u) = self.user(sid) else { return };
        if !u.exceptions.contains_key(exception) && u.exceptions.len() >= MAX_EXCEPTIONS {
            self.overflow += 1;
            return;
        }
        *u.exceptions.entry(exception.to_string()).or_default().entry(id.to_string()).or_default() += 1;
    }

    /// The report: the policy in force, its FIPS status, what's in use by
    /// whom, and what was turned away. `last_failure` is the reason and
    /// detail of a compile that failed since `policy` was published.
    pub fn encode(&self, policy: &Compiled, last_failure: Option<(&str, &str)>) -> peios::Result<Vec<u8>> {
        let p = &policy.policy;
        let mut w = Writer::new();
        w.write_map(4);

        w.write_str("policy").write_map(9);
        w.write_str("reject-below").write_str(p.reject_below.letter());
        w.write_str("warn-below").write_str(p.warn_below.letter());
        w.write_str("reject-non-fips").write_bool(p.reject_non_fips);
        w.write_str("warn-non-fips").write_bool(p.warn_non_fips);
        w.write_str("exceptions-may-reject").write_bool(p.exceptions_may_reject);
        w.write_str("defaults").write_bool(policy.defaults);
        w.write_str("exceptions").write_array(p.exceptions.len() as u32);
        for e in &p.exceptions {
            w.write_map(3);
            w.write_str("name").write_str(&e.name);
            w.write_str("warn").write_bool(e.warn);
            w.write_str("algorithms").write_array(e.algorithms.len() as u32);
            for id in &e.algorithms {
                w.write_str(id);
            }
        }
        w.write_str("dropped").write_array(policy.dropped.len() as u32);
        for (name, why) in &policy.dropped {
            w.write_map(3);
            w.write_str("name").write_str(name);
            w.write_str("reason").write_str(why.reason());
            w.write_str("detail").write_str(&why.to_string());
        }
        w.write_str("last-failure");
        match last_failure {
            Some((reason, detail)) => {
                w.write_map(2);
                w.write_str("reason").write_str(reason);
                w.write_str("detail").write_str(detail);
            }
            None => {
                w.write_nil();
            }
        }

        // FIPS can be asked for, but the module isn't validated
        // (PEI-1722), so the machine never operates in an approved mode.
        let non_fips = if p.reject_non_fips { policy.admit_non_fips.as_slice() } else { &[] };
        w.write_str("fips").write_map(4);
        w.write_str("requested").write_bool(p.reject_non_fips);
        w.write_str("approved-mode").write_bool(false);
        w.write_str("reasons").write_array(1 + u32::from(!non_fips.is_empty()));
        w.write_str("module-not-validated");
        if !non_fips.is_empty() {
            w.write_str("exceptions-admit-non-fips");
        }
        w.write_str("exceptions-admitting-non-fips").write_array(non_fips.len() as u32);
        for name in non_fips {
            w.write_str(name);
        }

        w.write_str("use").write_array(self.usage.len() as u32);
        for (sid, u) in &self.usage {
            w.write_map(3);
            w.write_str("sid").write_bin(sid);
            w.write_str("exceptions").write_map(u.exceptions.len() as u32);
            for (name, ids) in &u.exceptions {
                w.write_str(name).write_map(ids.len() as u32);
                for (id, n) in ids {
                    w.write_str(id).write_uint(*n);
                }
            }
            w.write_str("warned").write_map(u.warned.len() as u32);
            for (id, n) in &u.warned {
                w.write_str(id).write_uint(*n);
            }
        }

        w.write_str("turned-away").write_map(4);
        w.write_str("rate-limited").write_uint(self.limited);
        w.write_str("unattributed").write_uint(self.unattributed);
        w.write_str("invalid").write_uint(self.invalid);
        w.write_str("overflow").write_uint(self.overflow);
        w.to_bytes()
    }
}

fn refill(b: Bucket, now: Instant) -> Bucket {
    let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
    Bucket { tokens: (b.tokens + elapsed * RATE).min(BURST), at: now }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_user_is_limited_to_its_burst_then_its_rate() {
        let mut p = Posture::default();
        let t = Instant::now();
        for _ in 0..BURST as usize {
            assert!(p.admit(b"alice", t));
        }
        assert!(!p.admit(b"alice", t));
        assert!(p.admit(b"bob", t), "one user's flood doesn't limit another");
        assert!(p.admit(b"alice", t + Duration::from_millis(250)));
        assert_eq!(p.limited, 1);
    }

    #[test]
    fn usage_is_counted_by_user_and_bounded() {
        let mut p = Posture::default();
        p.exception_used(b"radiusd", "md5.hmac", "Radius.PacketAuth");
        p.exception_used(b"radiusd", "md5.hmac", "Radius.PacketAuth");
        p.warned(b"radiusd", "md5.digest");
        let u = &p.usage[b"radiusd".as_slice()];
        assert_eq!(u.exceptions["Radius.PacketAuth"]["md5.hmac"], 2);
        assert_eq!(u.warned["md5.digest"], 1);
        for i in 0..MAX_EXCEPTIONS + 3 {
            p.exception_used(b"mallory", "md5.hmac", &format!("Junk.{i}"));
        }
        assert_eq!(p.usage[b"mallory".as_slice()].exceptions.len(), MAX_EXCEPTIONS);
        assert_eq!(p.overflow, 3);
    }

    #[test]
    fn the_report_encodes() {
        let mut p = Posture::default();
        p.warned(b"x", "md5.digest");
        let compiled = Compiled {
            policy: Default::default(),
            dropped: vec![],
            admit_non_fips: vec![],
            defaults: true,
        };
        let bytes = p.encode(&compiled, Some(("too-large", "the policy is big"))).unwrap();
        let mut r = peios::msgpack::Reader::new(&bytes);
        assert_eq!(r.read_map().unwrap(), 4);
    }
}
