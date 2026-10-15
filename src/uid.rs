//! Keeper UIDs: random bytes on the wire, URL-safe unpadded base64 everywhere a user sees them.

use std::borrow::Borrow;
use std::str::FromStr;

use crate::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uid(String);

impl From<&[u8]> for Uid {
    fn from(bytes: &[u8]) -> Self {
        Self(b64_encode(bytes))
    }
}

/// Only strings that decode as base64 are UIDs, so the wire form can always be recovered.
impl FromStr for Uid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self::from(b64_decode(s)?.as_slice()))
    }
}

impl From<&Uid> for Vec<u8> {
    fn from(uid: &Uid) -> Self {
        b64_decode(&uid.0).expect("a Uid is only ever built from bytes or validated base64")
    }
}

impl std::fmt::Display for Uid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Uid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Lets `BTreeMap<Uid, _>` / `HashMap<Uid, _>` be queried with the `&str` a user typed.
impl Borrow<str> for Uid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_roundtrip_and_padding_is_tolerated() {
        let bytes = [7u8; 16];
        let uid = Uid::from(&bytes[..]);
        assert_eq!(uid.to_string().len(), 22);
        assert_eq!(Vec::<u8>::from(&uid), bytes);
        assert_eq!(format!("{uid}==").parse::<Uid>().unwrap(), uid);
        assert!("not base64!".parse::<Uid>().is_err());
    }
}
