//! Keeper UIDs: random bytes on the wire, URL-safe unpadded base64 everywhere a user sees them.

use std::borrow::Borrow;
use std::str::FromStr;

use crate::prelude::*;

/// Exclude base64url's punctuation prefixes for use as bare CLI arguments.
pub(crate) fn random_bytes<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> [u8; 16] {
    let mut bytes = [0; 16];
    rand::RngCore::fill_bytes(rng, &mut bytes);
    let [first, ..] = &mut bytes;
    if *first & 0xf8 == 0xf8 {
        *first &= 0x7f;
    }
    bytes
}

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
        let uid = Uid::from(bytes.as_slice());
        assert_eq!(uid.to_string().len(), 22);
        assert_eq!(Vec::<u8>::from(&uid), bytes);
        assert_eq!(format!("{uid}==").parse::<Uid>().unwrap(), uid);
        assert!("not base64!".parse::<Uid>().is_err());
    }

    #[test]
    fn generated_bytes_avoid_option_prefix_without_changing_entropy() {
        use rand::SeedableRng;

        for seed in 0..256 {
            let mut raw_rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut generated_rng = raw_rng.clone();
            let mut raw = [0; 16];
            rand::RngCore::fill_bytes(&mut raw_rng, &mut raw);

            let generated = random_bytes(&mut generated_rng);
            let encoded = Uid::from(generated.as_slice());
            assert!(!encoded.as_ref().starts_with('-') && !encoded.as_ref().starts_with('_'));
            assert!(generated.iter().skip(1).eq(raw.iter().skip(1)));
            let [generated_first, ..] = generated;
            let [raw_first, ..] = raw;
            assert_eq!(generated_first & 0x7f, raw_first & 0x7f);
            let raw_uid = Uid::from(raw.as_slice());
            if !matches!(raw_uid.as_ref().as_bytes(), [b'-' | b'_', ..]) {
                assert_eq!(generated, raw);
            }
        }
    }
}
