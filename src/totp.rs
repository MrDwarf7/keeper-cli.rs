//! RFC 6238 codes from `otpauth://totp/...` URLs stored in records.

use std::str::FromStr;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::prelude::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(Error::Generic(format!("unsupported TOTP algorithm {value}"))),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Code {
    value:         String,
    pub remaining: u64,
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Totp {
    secret:    Vec<u8>,
    algorithm: Algorithm,
    digits:    u32,
    period:    u64,
}

impl FromStr for Totp {
    type Err = Error;

    fn from_str(source: &str) -> Result<Self> {
        let url = reqwest::Url::parse(source).map_err(|_| Error::Generic("not an otpauth://totp URL".into()))?;
        if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
            return Err(Error::Generic("not an otpauth://totp URL".into()));
        }
        let mut totp = Self {
            secret:    Vec::new(),
            algorithm: Algorithm::default(),
            digits:    6,
            period:    30,
        };
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    let normalized = value
                        .chars()
                        .filter(|c| !matches!(c, ' ' | '=' | '-'))
                        .map(|c| c.to_ascii_uppercase())
                        .collect::<String>();
                    totp.secret = data_encoding::BASE32_NOPAD
                        .decode(normalized.as_bytes())
                        .map_err(|e| Error::Generic(format!("invalid TOTP secret: {e}")))?;
                }
                "algorithm" => totp.algorithm = value.parse()?,
                "digits" => {
                    totp.digits = value
                        .parse()
                        .map_err(|_| Error::Generic("invalid TOTP digits".into()))?;
                    if !(1..=10).contains(&totp.digits) {
                        return Err(Error::Generic("TOTP digits must be between 1 and 10".into()));
                    }
                }
                "period" => {
                    totp.period = value
                        .parse()
                        .map_err(|_| Error::Generic("invalid TOTP period".into()))?;
                    if totp.period == 0 {
                        return Err(Error::Generic("TOTP period must be nonzero".into()));
                    }
                }
                _ => {}
            }
        }
        if totp.secret.is_empty() {
            return Err(Error::Generic("TOTP URL has no secret".into()));
        }
        Ok(totp)
    }
}

impl Totp {
    /// Returns the code for `unix_time` and the seconds it remains valid.
    pub fn code_at(&self, unix_time: u64) -> Code {
        let counter = (unix_time / self.period).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => Digest::Sha1(hmac::<Hmac<Sha1>>(&self.secret, &counter).into()),
            Algorithm::Sha256 => Digest::Sha256(hmac::<Hmac<Sha256>>(&self.secret, &counter).into()),
            Algorithm::Sha512 => Digest::Sha512(hmac::<Hmac<Sha512>>(&self.secret, &counter).into()),
        };
        let offset = match digest {
            Digest::Sha1([.., last]) | Digest::Sha256([.., last]) | Digest::Sha512([.., last]) => {
                (last & 0x0f) as usize
            }
        };
        let binary = digest
            .as_ref()
            .iter()
            .skip(offset)
            .take(4)
            .fold(0u32, |value, byte| (value << 8) | u32::from(*byte))
            & 0x7fff_ffff;
        let code = u64::from(binary) % 10u64.pow(self.digits);
        Code {
            value:     format!("{code:0width$}", width = self.digits as usize),
            remaining: self.period - unix_time % self.period,
        }
    }

    pub fn code_now(&self) -> Result<Code> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Generic(e.to_string()))?
            .as_secs();
        Ok(self.code_at(now))
    }
}

enum Digest {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }
}

fn hmac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> hmac::digest::Output<M> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes()
}
#[cfg(test)]
mod tests {
    use super::*;

    fn url(secret: &[u8], algorithm: &str) -> String {
        format!(
            "otpauth://totp/Test:alice?secret={}&algorithm={algorithm}&digits=8&period=30",
            data_encoding::BASE32_NOPAD.encode(secret)
        )
    }

    #[test]
    fn rfc6238_appendix_b_vectors() {
        let cases = [
            (
                "SHA1",
                b"12345678901234567890".as_slice(),
                [(59, "94287082"), (1111111109, "07081804"), (20000000000, "65353130")],
            ),
            (
                "SHA256",
                b"12345678901234567890123456789012",
                [(59, "46119246"), (1111111109, "68084774"), (20000000000, "77737706")],
            ),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234",
                [(59, "90693936"), (1111111109, "25091201"), (20000000000, "47863826")],
            ),
        ];
        for (algorithm, secret, vectors) in cases {
            let totp = url(secret, algorithm).parse::<Totp>().unwrap();
            for (time, expected) in vectors {
                assert_eq!(totp.code_at(time).to_string(), expected, "{algorithm} at {time}");
            }
        }
    }

    #[test]
    fn defaults_lowercase_secret_and_remaining_window() {
        let totp = "otpauth://totp/x?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq"
            .parse::<Totp>()
            .unwrap();
        let code = totp.code_at(59);
        assert_eq!(code.to_string().len(), 6);
        assert_eq!(code.remaining, 1);
        assert!("https://example.com".parse::<Totp>().is_err());
        assert!("otpauth://totp/x?issuer=a".parse::<Totp>().is_err());
    }

    #[test]
    fn query_values_are_decoded_and_base32_is_lenient() {
        let totp = "otpauth://totp/x?secret=gezd%20gnbv-gy3tqojqgezdgnbvgy3tqojq%3D%3D&algorithm=sha%32%35%36"
            .parse::<Totp>()
            .unwrap();
        assert_eq!(totp.algorithm, Algorithm::Sha256);
    }

    #[test]
    fn invalid_digits_and_period_are_rejected() {
        let base = "otpauth://totp/x?secret=gezdgnbvgy3tqojq";
        for digits in ["nope", "0", "11"] {
            assert!(format!("{base}&digits={digits}").parse::<Totp>().is_err());
        }
        for period in ["nope", "0"] {
            assert!(format!("{base}&period={period}").parse::<Totp>().is_err());
        }
    }
}
