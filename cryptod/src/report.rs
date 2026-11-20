//! What a process using libpcrypto reports, as `runtime/machine.c` sends it:
//! one SEQPACKET datagram per report on `/run/cryptod/report`.
//!
//! ```text
//! u8               kind: 1 warned, 2 exception used, 3 policy unusable
//! u8               the problem, for kind 3, else 0
//! u8-prefixed      the entry's id, md5.hmac say, or empty for kind 3
//! u8-prefixed      the exception's name, for kind 2, else empty
//! ```
//!
//! Reports are the sender's own word. Its identity comes from the socket,
//! never from the report; what it says is checked only against what
//! libpcrypto could have sent, so nothing invented reaches an event.

use crate::known::Known;

pub const SOCKET: &str = "/run/cryptod/report";

/// The largest report the runtime sends.
pub const MAX: usize = 4 + 255 + 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    /// The first use of an entry the policy warns about.
    Warned { id: String },
    /// The first use of an exception, for `id`.
    ExceptionUsed { id: String, exception: String },
    /// A policy copy the process couldn't use, so it fell back.
    PolicyUnusable { problem: Problem },
}

/// Why a process couldn't use a policy copy, as `machine.c` numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    Unreadable = 1,
    Insecure = 2,
    Malformed = 3,
    Version = 4,
    Token = 5,
}

impl Problem {
    /// The event's `outcome.reason`.
    pub fn reason(self) -> &'static str {
        match self {
            Problem::Unreadable => "copy-unreadable",
            Problem::Insecure => "copy-insecure",
            Problem::Malformed => "copy-malformed",
            Problem::Version => "copy-version",
            Problem::Token => "token-unreadable",
        }
    }

    fn from_u8(v: u8) -> Option<Problem> {
        Some(match v {
            1 => Problem::Unreadable,
            2 => Problem::Insecure,
            3 => Problem::Malformed,
            4 => Problem::Version,
            5 => Problem::Token,
            _ => return None,
        })
    }
}

/// Reads one report, or `None` if it isn't one libpcrypto could have sent.
pub fn parse(msg: &[u8], known: &Known) -> Option<Report> {
    let (&kind, rest) = msg.split_first()?;
    let (&problem, rest) = rest.split_first()?;
    let (id, rest) = prefixed(rest)?;
    let (name, rest) = prefixed(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let id = std::str::from_utf8(id).ok()?;
    let name = std::str::from_utf8(name).ok()?;
    match (kind, problem) {
        (1, 0) if name.is_empty() && known.get(id).is_some() => Some(Report::Warned { id: id.into() }),
        (2, 0) if valid_name(name) && known.get(id).is_some() => {
            Some(Report::ExceptionUsed { id: id.into(), exception: name.into() })
        }
        (3, p) if id.is_empty() && name.is_empty() => {
            Problem::from_u8(p).map(|problem| Report::PolicyUnusable { problem })
        }
        _ => None,
    }
}

fn prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    let len = usize::from(len);
    (rest.len() >= len).then(|| rest.split_at(len))
}

/// An exception's name as the compiler accepts one, printable ASCII here
/// as it'll be written into events.
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.contains('.') && name.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Known {
        Known::parse("md5.hmac\tD\t0\nmd5.digest\tU\t0\n").unwrap()
    }

    fn msg(kind: u8, problem: u8, id: &str, name: &str) -> Vec<u8> {
        let mut m = vec![kind, problem, id.len() as u8];
        m.extend_from_slice(id.as_bytes());
        m.push(name.len() as u8);
        m.extend_from_slice(name.as_bytes());
        m
    }

    #[test]
    fn each_kind_libpcrypto_sends_is_read() {
        let k = known();
        assert_eq!(parse(&msg(1, 0, "md5.digest", ""), &k), Some(Report::Warned { id: "md5.digest".into() }));
        assert_eq!(
            parse(&msg(2, 0, "md5.hmac", "Radius.PacketAuth"), &k),
            Some(Report::ExceptionUsed { id: "md5.hmac".into(), exception: "Radius.PacketAuth".into() })
        );
        assert_eq!(
            parse(&msg(3, 2, "", ""), &k),
            Some(Report::PolicyUnusable { problem: Problem::Insecure })
        );
    }

    #[test]
    fn anything_libpcrypto_couldnt_have_sent_is_refused() {
        let k = known();
        for bad in [
            vec![],
            vec![1, 0],
            msg(1, 0, "md5.hmca", ""),
            msg(1, 1, "md5.digest", ""),
            msg(1, 0, "md5.digest", "Extra.Name"),
            msg(2, 0, "md5.hmac", ""),
            msg(2, 0, "md5.hmac", "Bad name\n.x"),
            msg(3, 9, "", ""),
            msg(3, 0, "", ""),
            msg(3, 1, "md5.hmac", ""),
            msg(4, 0, "", ""),
            [msg(1, 0, "md5.digest", ""), vec![0]].concat(),
            vec![1, 0, 20, b'm'],
        ] {
            assert_eq!(parse(&bad, &k), None, "{bad:?}");
        }
    }
}
