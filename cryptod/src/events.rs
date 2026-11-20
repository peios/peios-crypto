//! The records cryptod writes, under the platform root `cryptod`.
//!
//! - `cryptod.policy.applied` (standard): a policy was compiled and
//!   published, for processes started from now on.
//! - `cryptod.policy.failed` (essential): a compile failed, so the copies
//!   already published were kept; an exception was dropped; or a process
//!   reported a copy it couldn't use, so it fell back.
//! - `cryptod.algorithm.warned` (standard): a process's first use of an
//!   entry the policy warns about.
//! - `cryptod.exception.used` (essential): a process's first use of an
//!   exception, warned or not, so that an audit always finds weak crypto in
//!   use.
//!
//! A process's report names it by the token and pid the kernel captured
//! when it connected, never by anything in the report. What cryptod does
//! on its own authority names cryptod's own user. The fields are in
//! `docs/cryptod.evman`.

use std::collections::BTreeMap;

use peios::msgpack::Writer;

use crate::compile::Compiled;
use crate::policy::Grade;

pub const POLICY_APPLIED: &str = "cryptod.policy.applied";
pub const POLICY_FAILED: &str = "cryptod.policy.failed";
pub const ALGORITHM_WARNED: &str = "cryptod.algorithm.warned";
pub const EXCEPTION_USED: &str = "cryptod.exception.used";

/// A field's value.
#[derive(Clone, Copy, Debug)]
pub enum F<'a> {
    Str(&'a str),
    Uint(u64),
    Bool(bool),
    Bin(&'a [u8]),
}

/// A record's payload from its fields, by dotted path: `subject.token.sid`
/// is the `sid` of the `token` map of the `subject` map.
pub fn payload(fields: &[(&str, F<'_>)]) -> peios::Result<Vec<u8>> {
    enum Node<'a> {
        Leaf(F<'a>),
        Map(BTreeMap<&'a str, Node<'a>>),
    }
    let mut root = BTreeMap::new();
    for (path, value) in fields {
        let mut parts: Vec<&str> = path.split('.').collect();
        let leaf = parts.pop().expect("a field has a name");
        let mut map = &mut root;
        for part in parts {
            map = match map.entry(part).or_insert_with(|| Node::Map(BTreeMap::new())) {
                Node::Map(m) => m,
                Node::Leaf(_) => panic!("{path} is inside a field"),
            };
        }
        let previous = map.insert(leaf, Node::Leaf(*value));
        assert!(previous.is_none(), "{path} is given twice");
    }
    fn write(w: &mut Writer, map: &BTreeMap<&str, Node<'_>>) {
        w.write_map(map.len() as u32);
        for (key, node) in map {
            w.write_str(key);
            match node {
                Node::Map(m) => write(w, m),
                Node::Leaf(F::Str(s)) => {
                    w.write_str(s);
                }
                Node::Leaf(F::Uint(n)) => {
                    w.write_uint(*n);
                }
                Node::Leaf(F::Bool(b)) => {
                    w.write_bool(*b);
                }
                Node::Leaf(F::Bin(b)) => {
                    w.write_bin(b);
                }
            }
        }
    }
    let mut w = Writer::new();
    write(&mut w, &root);
    w.to_bytes()
}

/// Who acted: for a report, the user of the token the kernel captured when
/// the process connected, and its pid; for what cryptod does on its own
/// authority, cryptod's own user, and no pid, as the header names cryptod.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Peer {
    pub sid: Vec<u8>,
    pub pid: Option<u32>,
}

fn subject<'a>(peer: Option<&'a Peer>, fields: &mut Vec<(&'static str, F<'a>)>) {
    if let Some(peer) = peer {
        fields.push(("subject.token.sid", F::Bin(&peer.sid)));
        if let Some(pid) = peer.pid {
            fields.push(("subject.process.pid", F::Uint(u64::from(pid))));
        }
    }
}

fn algorithm<'a>(id: &'a str, grade: Option<Grade>, fields: &mut Vec<(&'static str, F<'a>)>) {
    fields.push(("object.crypto-algorithm.id", F::Str(id)));
    if let Some(g) = grade {
        fields.push(("object.crypto-algorithm.grade", F::Str(g.letter())));
    }
}

/// A policy published. `own` is cryptod's own user, if it could be read.
pub fn policy_applied(c: &Compiled, own: Option<&Peer>) -> peios::Result<Vec<u8>> {
    let p = &c.policy;
    let mut fields = vec![
        ("object.crypto-policy.reject-below", F::Str(p.reject_below.letter())),
        ("object.crypto-policy.warn-below", F::Str(p.warn_below.letter())),
        ("object.crypto-policy.reject-non-fips", F::Bool(p.reject_non_fips)),
        ("object.crypto-policy.warn-non-fips", F::Bool(p.warn_non_fips)),
        ("object.crypto-policy.exceptions-may-reject", F::Bool(p.exceptions_may_reject)),
        ("object.crypto-policy.exception-count", F::Uint(p.exceptions.len() as u64)),
        ("object.crypto-policy.defaults", F::Bool(c.defaults)),
    ];
    subject(own, &mut fields);
    payload(&fields)
}

/// A failure: `reason` and `detail`, the exception it concerns, if any, and
/// who acted: the process that reported it, or cryptod.
pub fn policy_failed(
    reason: &str,
    detail: &str,
    exception: Option<&str>,
    who: Option<&Peer>,
) -> peios::Result<Vec<u8>> {
    let mut fields = vec![("outcome.reason", F::Str(reason))];
    if !detail.is_empty() {
        fields.push(("outcome.detail", F::Str(detail)));
    }
    if let Some(name) = exception {
        fields.push(("object.crypto-exception.name", F::Str(name)));
    }
    subject(who, &mut fields);
    payload(&fields)
}

pub fn algorithm_warned(peer: &Peer, id: &str, grade: Option<Grade>) -> peios::Result<Vec<u8>> {
    let mut fields = Vec::new();
    algorithm(id, grade, &mut fields);
    subject(Some(peer), &mut fields);
    payload(&fields)
}

pub fn exception_used(
    peer: &Peer,
    id: &str,
    grade: Option<Grade>,
    exception: &str,
) -> peios::Result<Vec<u8>> {
    let mut fields = vec![("object.crypto-exception.name", F::Str(exception))];
    algorithm(id, grade, &mut fields);
    subject(Some(peer), &mut fields);
    payload(&fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::msgpack::{Reader, Type};

    /// The payload as dotted paths and printed values, sorted.
    fn flat(bytes: &[u8]) -> Vec<(String, String)> {
        fn walk(r: &mut Reader<'_>, prefix: &str, out: &mut Vec<(String, String)>) {
            let n = r.read_map().unwrap();
            for _ in 0..n {
                let key = r.read_str().unwrap().to_owned();
                let path = if prefix.is_empty() { key } else { format!("{prefix}.{key}") };
                match r.peek().unwrap() {
                    Type::Map => walk(r, &path, out),
                    Type::Str => out.push((path, r.read_str().unwrap().to_owned())),
                    Type::Int => out.push((path, r.read_uint().unwrap().to_string())),
                    Type::Bool => out.push((path, r.read_bool().unwrap().to_string())),
                    Type::Bin => out.push((path, format!("{:?}", r.read_bin().unwrap()))),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        let mut r = Reader::new(bytes);
        let mut out = Vec::new();
        walk(&mut r, "", &mut out);
        assert_eq!(r.remaining(), 0);
        out
    }

    fn pairs(want: &[(&str, &str)]) -> Vec<(String, String)> {
        want.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn an_exceptions_use_names_the_process_the_algorithm_and_the_exception() {
        let peer = Peer { sid: vec![1, 0], pid: Some(42) };
        let bytes = exception_used(&peer, "md5.hmac", Some(Grade::D), "Radius.PacketAuth").unwrap();
        assert_eq!(
            flat(&bytes),
            pairs(&[
                ("object.crypto-algorithm.grade", "D"),
                ("object.crypto-algorithm.id", "md5.hmac"),
                ("object.crypto-exception.name", "Radius.PacketAuth"),
                ("subject.process.pid", "42"),
                ("subject.token.sid", "[1, 0]"),
            ])
        );
    }

    #[test]
    fn cryptods_own_records_name_it_without_a_pid() {
        let own = Peer { sid: vec![1, 5], pid: None };
        let bytes = policy_failed("invalid-setting", "", None, Some(&own)).unwrap();
        assert_eq!(
            flat(&bytes),
            pairs(&[("outcome.reason", "invalid-setting"), ("subject.token.sid", "[1, 5]")])
        );
    }

    #[test]
    fn a_failure_carries_only_what_it_has() {
        let bytes = policy_failed("too-large", "", None, None).unwrap();
        assert_eq!(flat(&bytes), pairs(&[("outcome.reason", "too-large")]));
    }
}
