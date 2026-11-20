//! cryptod: the machine's crypto policy service (PEI-1721, M4).
//!
//! It compiles `Machine\System\Cryptography` into the policy file
//! libpcrypto reads, at start and whenever the key changes, and relays what
//! processes report of their weak crypto as KMES events, under the platform
//! root `cryptod`. Most processes can't emit events themselves.
//!
//! The library is everything that can be tested on a host: the compiler,
//! the file it writes, the reports it reads, the records it writes and the
//! posture it keeps. The service itself is `main.rs`.

pub mod compile;
pub mod events;
pub mod known;
pub mod policy;
pub mod posture;
pub mod registry;
pub mod report;

use peios::security::{SdView, sddl};

/// cryptod's service SID: S-1-5-80 and the SHA-1 of "CRYPTOD" in UTF-16LE,
/// as five little-endian sub-authorities, the platform's rule. libpcrypto
/// trusts a policy copy only if it, or SYSTEM, owns it, and no one else may
/// change it (`runtime/machine.c`).
pub const SID: &str = "S-1-5-80-2691053820-547492864-353945177-641201782-1210658655";

/// Where the copies are: the current one, under `/run`, and the one kept
/// across reboots, which early-boot processes read.
pub const CURRENT: &str = "/run/cryptod/policy";
pub const LAST_KNOWN: &str = "/var/state/cryptod/policy";

/// What a published copy grants: full access to SYSTEM and cryptod alone,
/// and reading to everyone, confined applications among them, strict ones
/// too. A process that can't read the policy falls back to the defaults,
/// which would loosen a tightened one.
pub fn copy_sddl() -> String {
    format!("D:P(A;;FA;;;SY)(A;;FA;;;{SID})(A;;FR;;;WD)(A;;FR;;;AC)(A;;FR;;;S-1-15-2-2)")
}

/// What cryptod's directories grant: as a copy, with traversal.
pub fn directory_sddl() -> String {
    format!(
        "D:P(A;;FA;;;SY)(A;;FA;;;{SID})(A;;0x1200a9;;;WD)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)"
    )
}

/// The report socket: everyone may connect, which needs writing.
pub fn report_sddl() -> String {
    format!(
        "D:P(A;;FA;;;SY)(A;;FA;;;{SID})(A;;0x12019f;;;WD)(A;;0x12019f;;;AC)(A;;0x12019f;;;S-1-15-2-2)"
    )
}

/// The posture socket: SYSTEM and Administrators only, as it says which
/// programs use what.
pub fn posture_sddl() -> String {
    format!("D:P(A;;FA;;;SY)(A;;FA;;;{SID})(A;;0x12019f;;;BA)")
}

/// Checks an exception's `ProgramSecurity`: it must be a self-relative SD,
/// with a DACL, as a NULL or absent one would let every program use it.
pub fn check_program_security(sd: &[u8]) -> Result<(), String> {
    let view = SdView::parse(sd).map_err(|e| format!("not a security descriptor ({e})"))?;
    match view.dacl() {
        Some(_) => Ok(()),
        None => Err("it has no DACL, so every program could use the exception".into()),
    }
}

/// An exception's `ProgramSecurity` given as SDDL, as a self-relative SD.
pub fn parse_sddl(text: &str) -> Result<Vec<u8>, String> {
    sddl::parse(text)
        .map(|sd| sd.as_bytes().to_vec())
        .map_err(|e| format!("not SDDL ({e})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_security_needs_a_dacl() {
        let open = parse_sddl("O:SYG:SY").unwrap();
        assert!(check_program_security(&open).is_err());
        let granted = parse_sddl("O:SYG:SYD:(A;;0x1;;;S-1-5-80-1-2-3-4-5)").unwrap();
        assert!(check_program_security(&granted).is_ok());
        assert!(check_program_security(b"junk").is_err());
        assert!(parse_sddl("D:(A;;").is_err());
    }

    #[test]
    fn every_descriptor_cryptod_sets_parses() {
        for sddl in [copy_sddl(), directory_sddl(), report_sddl(), posture_sddl()] {
            parse_sddl(&sddl).unwrap_or_else(|e| panic!("{sddl}: {e}"));
        }
    }
}
