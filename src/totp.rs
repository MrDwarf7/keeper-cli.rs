//! RFC 6238 codes from `otpauth://totp/...` URLs stored in records.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::prelude::*;

#[derive(Debug, PartialEq, Eq)]
pub struct Totp {
    secret:    Vec<u8>,
    algorithm: String,
    digits:    u32,
    period:    u64,
}

impl Totp {
    pub fn parse(url: &str) -> Result<Self> {
        let query = url
            .strip_prefix("otpauth://")
            .and_then(|rest| rest.split_once('?'))
            .map(|(_, q)| q)
            .ok_or_else(|| Error::Generic("not an otpauth:// URL".into()))?;
        let mut totp = Self {
            secret:    Vec::new(),
            algorithm: "SHA1".into(),
            digits:    6,
            period:    30,
        };
        for (key, value) in query.split('&').filter_map(|kv| kv.split_once('=')) {
            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    let normalized: String = value
                        .chars()
                        .filter(|c| !matches!(c, ' ' | '=' | '-'))
                        .collect::<String>()
                        .to_ascii_uppercase();
                    totp.secret = data_encoding::BASE32_NOPAD
                        .decode(normalized.as_bytes())
                        .map_err(|e| Error::Generic(format!("invalid TOTP secret: {e}")))?;
                }
                "algorithm" => totp.algorithm = value.to_ascii_uppercase(),
                "digits" => totp.digits = value.parse().unwrap_or(6),
                "period" => totp.period = value.parse().ok().filter(|&p| p > 0).unwrap_or(30),
                _ => {}
            }
        }
        if totp.secret.is_empty() {
            return Err(Error::Generic("TOTP URL has no secret".into()));
        }
        Ok(totp)
    }

    /// Returns the code for `unix_time` and the seconds it remains valid.
    pub fn code_at(&self, unix_time: u64) -> Result<(String, u64)> {
        let counter = (unix_time / self.period).to_be_bytes();
        let digest = match self.algorithm.as_str() {
            "SHA1" => hmac::<Hmac<Sha1>>(&self.secret, &counter),
            "SHA256" => hmac::<Hmac<Sha256>>(&self.secret, &counter),
            "SHA512" => hmac::<Hmac<Sha512>>(&self.secret, &counter),
            other => return Err(Error::Generic(format!("unsupported TOTP algorithm {other}"))),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
        let code = u64::from(binary) % 10u64.pow(self.digits);
        Ok((
            format!("{code:0width$}", width = self.digits as usize),
            self.period - unix_time % self.period,
        ))
    }

    pub fn code_now(&self) -> Result<(String, u64)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Generic(e.to_string()))?
            .as_secs();
        self.code_at(now)
    }
}

fn hmac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
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
            ("SHA1", &b"12345678901234567890"[..], [(59, "94287082"), (1111111109, "07081804"), (20000000000, "65353130")]),
            ("SHA256", b"12345678901234567890123456789012", [(59, "46119246"), (1111111109, "68084774"), (20000000000, "77737706")]),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234",
                [(59, "90693936"), (1111111109, "25091201"), (20000000000, "47863826")],
            ),
        ];
        for (alg, secret, vectors) in cases {
            let totp = Totp::parse(&url(secret, alg)).unwrap();
            for (t, expected) in vectors {
                assert_eq!(totp.code_at(t).unwrap().0, expected, "{alg} at {t}");
            }
        }
    }

    #[test]
    fn defaults_lowercase_secret_and_remaining_window() {
        let totp = Totp::parse("otpauth://totp/x?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq").unwrap();
        let (code, remaining) = totp.code_at(59).unwrap();
        assert_eq!(code.len(), 6);
        assert_eq!(remaining, 1);
        assert!(Totp::parse("https://example.com").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=a").is_err());
    }
}
