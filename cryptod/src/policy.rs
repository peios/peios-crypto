//! The compiled policy: what libpcrypto reads, in the file format version 1
//! that `runtime/machine.c` reads.
//!
//! ```text
//! "PEIOSCPL"          magic
//! u16                 version, 1
//! u8 u8               reject_below, warn_below: 0 (U) to 4 (A)
//! u8                  flags: REJECT_NON_FIPS, WARN_NON_FIPS, EXCEPTIONS_MAY_REJECT
//! u16                 exception count, then each exception:
//!   u8-prefixed       its name, Owner.Purpose
//!   u8                flags: EXCEPTION_WARN
//!   u16-prefixed      ProgramSecurity, a self-relative SD
//!   u16               id count, then each u8-prefixed id, md5.hmac say
//! ```
//!
//! Integers are big-endian. The compiler resolves `Enabled`,
//! `WarnByDefault` and `WarnAlways`, so the file holds only what applies,
//! and it checks every length fits before a policy reaches here.

pub const MAGIC: &[u8; 8] = b"PEIOSCPL";
pub const VERSION: u16 = 1;

const REJECT_NON_FIPS: u8 = 0x01;
const WARN_NON_FIPS: u8 = 0x02;
const EXCEPTIONS_MAY_REJECT: u8 = 0x04;
const EXCEPTION_WARN: u8 = 0x01;

/// A grade on Peios's ladder, U (practically broken) to A.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade {
    U = 0,
    D = 1,
    C = 2,
    B = 3,
    A = 4,
}

impl Grade {
    /// The grade a Registry value or algorithms.tsv names, in either case.
    pub fn parse(text: &str) -> Option<Grade> {
        match text.trim() {
            "U" | "u" => Some(Grade::U),
            "D" | "d" => Some(Grade::D),
            "C" | "c" => Some(Grade::C),
            "B" | "b" => Some(Grade::B),
            "A" | "a" => Some(Grade::A),
            _ => None,
        }
    }

    pub fn letter(self) -> &'static str {
        match self {
            Grade::U => "U",
            Grade::D => "D",
            Grade::C => "C",
            Grade::B => "B",
            Grade::A => "A",
        }
    }
}

/// Whether `name` is an exception's name: `Owner.Purpose`, printable ASCII
/// with no spaces, at most 255 bytes. The compiler publishes only such
/// names, and cryptod relays only reports of such names, so that the use of
/// every exception it publishes can be recorded.
pub fn valid_exception_name(name: &str) -> bool {
    let Some((owner, purpose)) = name.split_once('.') else {
        return false;
    };
    name.len() <= 255
        && !owner.is_empty()
        && !purpose.is_empty()
        && !purpose.ends_with('.')
        && name.bytes().all(|b| b.is_ascii_graphic())
}

/// One exception, as it applies: the programs its ProgramSecurity grants
/// may use the algorithms it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exception {
    pub name: String,
    pub warn: bool,
    pub program_security: Vec<u8>,
    pub algorithms: Vec<String>,
}

/// The machine's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub reject_below: Grade,
    pub warn_below: Grade,
    pub reject_non_fips: bool,
    pub warn_non_fips: bool,
    pub exceptions_may_reject: bool,
    pub exceptions: Vec<Exception>,
}

impl Default for Policy {
    /// Peios's defaults, agreed on PEI-1721: reject only the floor, warn
    /// below C, FIPS off, exceptions allowed to override rejection.
    fn default() -> Policy {
        Policy {
            reject_below: Grade::U,
            warn_below: Grade::C,
            reject_non_fips: false,
            warn_non_fips: false,
            exceptions_may_reject: true,
            exceptions: Vec::new(),
        }
    }
}

impl Policy {
    /// The policy file. Every length must fit its prefix, as the compiler
    /// guarantees: a policy that doesn't is a bug, and panics.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.push(self.reject_below as u8);
        out.push(self.warn_below as u8);
        let mut flags = 0;
        if self.reject_non_fips {
            flags |= REJECT_NON_FIPS;
        }
        if self.warn_non_fips {
            flags |= WARN_NON_FIPS;
        }
        if self.exceptions_may_reject {
            flags |= EXCEPTIONS_MAY_REJECT;
        }
        out.push(flags);
        out.extend_from_slice(&count16(self.exceptions.len()).to_be_bytes());
        for e in &self.exceptions {
            short(&mut out, e.name.as_bytes());
            out.push(if e.warn { EXCEPTION_WARN } else { 0 });
            out.extend_from_slice(&count16(e.program_security.len()).to_be_bytes());
            out.extend_from_slice(&e.program_security);
            out.extend_from_slice(&count16(e.algorithms.len()).to_be_bytes());
            for id in &e.algorithms {
                short(&mut out, id.as_bytes());
            }
        }
        out
    }
}

fn count16(n: usize) -> u16 {
    u16::try_from(n).expect("the compiler bounds every count to 65535")
}

fn short(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(u8::try_from(bytes.len()).expect("the compiler bounds every name to 255 bytes"));
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_encode_to_a_header_alone() {
        let bytes = Policy::default().encode();
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[8..], &[0, 1, 0, 2, EXCEPTIONS_MAY_REJECT, 0, 0]);
    }

    /// The vector `tests/machine_policy.c` gives libpcrypto, byte for byte:
    /// if this changes, so must that, or the two have diverged.
    #[test]
    fn an_exception_encodes_each_field_with_its_prefix() {
        let policy = Policy {
            reject_below: Grade::C,
            warn_below: Grade::B,
            reject_non_fips: false,
            warn_non_fips: false,
            exceptions_may_reject: true,
            exceptions: vec![Exception {
                name: "Radius.PacketAuth".into(),
                warn: true,
                program_security: vec![1, 2, 3],
                algorithms: vec!["md5.hmac".into(), "md5.digest".into()],
            }],
        };
        let bytes = policy.encode();
        let mut want = MAGIC.to_vec();
        want.extend_from_slice(&[0, 1, 2, 3, EXCEPTIONS_MAY_REJECT, 0, 1]);
        want.push(17);
        want.extend_from_slice(b"Radius.PacketAuth");
        want.extend_from_slice(&[EXCEPTION_WARN, 0, 3, 1, 2, 3, 0, 2]);
        want.push(8);
        want.extend_from_slice(b"md5.hmac");
        want.push(10);
        want.extend_from_slice(b"md5.digest");
        assert_eq!(bytes, want);
    }

    #[test]
    fn exception_names_are_owner_dot_purpose_in_printable_ascii() {
        assert!(valid_exception_name("Radius.PacketAuth"));
        assert!(valid_exception_name("Pkg.Legacy.Md5"));
        for bad in ["NoPurpose", ".Purpose", "Owner.", "Radius.Packet Auth", "Radius.Paket\u{e9}", ""] {
            assert!(!valid_exception_name(bad), "{bad:?}");
        }
        assert!(!valid_exception_name(&format!("A.{}", "x".repeat(254))));
    }

    #[test]
    fn grades_parse_in_either_case_and_nothing_else() {
        assert_eq!(Grade::parse("b"), Some(Grade::B));
        assert_eq!(Grade::parse(" A "), Some(Grade::A));
        assert_eq!(Grade::parse("E"), None);
        assert_eq!(Grade::parse("floor"), None);
        assert!(Grade::U < Grade::A);
    }
}
