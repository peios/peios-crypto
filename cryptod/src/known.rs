//! What libpcrypto grades, from the list peios-crypto installs beside it
//! (`share/peios-crypto/algorithms.tsv`): each entry's id, its grade or
//! `floor`, and whether FIPS approves it. cryptod checks policies against it,
//! so that it never has to load libpcrypto itself.

use std::collections::HashMap;

use crate::policy::Grade;

pub const PATH: &str = "/usr/share/peios-crypto/algorithms.tsv";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `None` for an entry on the floor, which nothing can except.
    pub grade: Option<Grade>,
    pub fips: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Known(HashMap<String, Entry>);

impl Known {
    /// Parses the list; a malformed line is an error, as the list is
    /// generated and a bad one means a broken installation.
    pub fn parse(text: &str) -> Result<Known, String> {
        let mut entries = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let entry = match fields.as_slice() {
                [id, grade, fips] if !id.is_empty() => {
                    let grade = match *grade {
                        "floor" => None,
                        other => Some(Grade::parse(other).ok_or_else(|| {
                            format!("line {}: unknown grade {other:?}", number + 1)
                        })?),
                    };
                    let fips = match *fips {
                        "0" => false,
                        "1" => true,
                        other => return Err(format!("line {}: fips is {other:?}", number + 1)),
                    };
                    (id.to_string(), Entry { grade, fips })
                }
                _ => return Err(format!("line {}: not id, grade and fips", number + 1)),
            };
            entries.insert(entry.0, entry.1);
        }
        if entries.is_empty() {
            return Err("the list is empty".into());
        }
        Ok(Known(entries))
    }

    pub fn get(&self, id: &str) -> Option<Entry> {
        self.0.get(id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_reads_grades_the_floor_and_fips() {
        let known = Known::parse("md5.hmac\tD\t0\nenc-null.encrypt\tfloor\t0\nsha256.digest\tB\t1\n")
            .unwrap();
        assert_eq!(known.get("md5.hmac"), Some(Entry { grade: Some(Grade::D), fips: false }));
        assert_eq!(known.get("enc-null.encrypt"), Some(Entry { grade: None, fips: false }));
        assert_eq!(known.get("sha256.digest"), Some(Entry { grade: Some(Grade::B), fips: true }));
        assert_eq!(known.get("md5"), None);
    }

    #[test]
    fn a_malformed_list_is_refused() {
        assert!(Known::parse("").is_err());
        assert!(Known::parse("md5.hmac\tE\t0\n").is_err());
        assert!(Known::parse("md5.hmac\tD\n").is_err());
        assert!(Known::parse("md5.hmac\tD\tyes\n").is_err());
    }
}
