//! `Machine\System\Cryptography` read through the Registry, in one read-only
//! transaction, so that a compile sees one snapshot of the key however an
//! administrator is changing it.

use std::io;

use peios::registry::{Key, KeyAccess, NotifyFilter, OpenFlags, RegValue, Transaction, ValueType};

use crate::compile::{KEY, Source, Value};

const READ: KeyAccess = KeyAccess::QUERY_VALUE.union(KeyAccess::ENUMERATE_SUB_KEYS);

pub struct Registry {
    txn: Transaction,
    root: Option<Key>,
}

/// `None` for a key or value that isn't there.
fn optional<T>(result: peios::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl Registry {
    /// A snapshot of the key, which may be absent.
    pub fn open() -> io::Result<Registry> {
        let txn = Transaction::begin_read_only()?;
        let root = optional(Key::open_transacted(None, KEY, READ, OpenFlags::empty(), Some(&txn)))?;
        Ok(Registry { txn, root })
    }

    fn with_key<T>(&self, path: &str, f: impl FnOnce(&Key) -> io::Result<T>) -> io::Result<Option<T>> {
        let Some(root) = &self.root else {
            return Ok(None);
        };
        if path.is_empty() {
            return f(root).map(Some);
        }
        match optional(Key::open_transacted(Some(root), path, READ, OpenFlags::empty(), Some(&self.txn)))? {
            Some(key) => f(&key).map(Some),
            None => Ok(None),
        }
    }
}

fn decode(v: RegValue) -> Value {
    let text = |data: &[u8]| String::from_utf8(data.to_vec()).ok();
    match v.ty {
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
            text(&v.data[..end]).map_or(Value::Other(v.ty.0), Value::Sz)
        }
        ValueType::MULTI_SZ => v
            .data
            .split(|&b| b == 0)
            .filter(|part| !part.is_empty())
            .map(text)
            .collect::<Option<Vec<_>>>()
            .map_or(Value::Other(v.ty.0), Value::Multi),
        ValueType::DWORD => match <[u8; 4]>::try_from(v.data.as_slice()) {
            Ok(bytes) => Value::Dword(u32::from_le_bytes(bytes)),
            Err(_) => Value::Other(v.ty.0),
        },
        ValueType::BINARY => Value::Binary(v.data),
        other => Value::Other(other.0),
    }
}

impl Source for Registry {
    fn subkeys(&self, path: &str) -> io::Result<Option<Vec<String>>> {
        self.with_key(path, |key| {
            key.subkeys(Some(&self.txn))
                .map(|sub| sub.map(|s| String::from_utf8_lossy(&s.name).into_owned()).map_err(io::Error::from))
                .collect()
        })
    }

    fn value(&self, path: &str, name: &str) -> io::Result<Option<Value>> {
        Ok(self
            .with_key(path, |key| optional(key.query_value(name.as_bytes(), Some(&self.txn))))?
            .flatten()
            .map(decode))
    }
}

/// A watch on the key's subtree, or on `Machine\System` while the key
/// doesn't exist yet, so that creating it is seen too. Non-blocking.
pub fn watch() -> io::Result<Key> {
    let (path, subtree) = match Key::open(None, KEY, KeyAccess::NOTIFY, OpenFlags::empty()) {
        Ok(key) => {
            key.notify(NotifyFilter::ALL, true)?;
            key.set_nonblocking(true)?;
            return Ok(key);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => ("Machine\\System", false),
        Err(e) => return Err(e.into()),
    };
    let key = Key::open(None, path, KeyAccess::NOTIFY, OpenFlags::empty())?;
    key.notify(NotifyFilter::ALL, subtree)?;
    key.set_nonblocking(true)?;
    Ok(key)
}

/// Whether `watch()` is on the key itself rather than its parent.
pub fn exists() -> bool {
    Key::open(None, KEY, KeyAccess::NOTIFY, OpenFlags::empty()).is_ok()
}
