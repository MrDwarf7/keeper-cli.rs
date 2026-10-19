//! Keeper's encrypted REST transport. Every request body is an `ApiRequest` whose payload is
//! AES-GCM encrypted with a per-session transmission key; that key is itself sealed to one of
//! Keeper's published server keys (RSA for ids 1-6, P-256 for 7-18).
//!
//! Commander additionally supports ML-KEM hybrid ("QRC") key exchange. The server still
//! accepts the classic EC exchange, which is all this client implements.

use std::str::FromStr;

use prost::Message;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;

use crate::crypto;
use crate::error::ApiFailure;
use crate::prelude::*;
use crate::proto::authentication::{ApiRequest, ApiRequestPayload};

pub const CLIENT_VERSION: &str = "c18.1.0";
pub const LOCALE: &str = "en_US";
const DEFAULT_SERVER_KEY_ID: i32 = 7;
const MAX_THROTTLE_RETRIES: u32 = 3;

const RSA_SERVER_KEYS: [&str; 6] = [
    "MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfHOOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInnj4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-VxIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB",
    "MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQqYHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmYKP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvdWUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUslBnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpNArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB",
    "MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoIhubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUirgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYSHzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_NXn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wEAgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB",
    "MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eRFKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4HCYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJKMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB",
    "MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51HvsILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmHFSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVVhBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nOWdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB",
    "MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqLAvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9vw8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB",
];

const EC_SERVER_KEYS: [&str; 12] = [
    "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM",
    "BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ",
    "BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g",
    "BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg",
    "BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk",
    "BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY",
    "BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI",
    "BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE",
    "BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8",
    "BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c",
    "BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU",
    "BNhngQqTT1bPKxGuB6FhbPTAeNVFl8PKGGSGo5W06xWIReutm6ix6JPivqnbvkydY-1uDQTr-5e6t70G01Bb5JA",
];

/// A validated Keeper endpoint. Region names and production/dev/QA hosts normalize here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host(String);

impl Default for Host {
    fn default() -> Self {
        Self("keepersecurity.com".into())
    }
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(server: &str) -> Result<Self> {
        let input = server.trim();
        let host = match input.strip_prefix("https://") {
            Some(host) => host,
            None if input.contains("://") => return Err(Error::Generic(format!("invalid Keeper server {input:?}"))),
            None => input,
        }
        .split('/')
        .next()
        .unwrap_or_default();
        let region = host.to_ascii_uppercase().replace('-', "_");
        let resolved = match region.as_str() {
            "US" => "keepersecurity.com",
            "EU" => "keepersecurity.eu",
            "AU" => "keepersecurity.com.au",
            "CA" => "keepersecurity.ca",
            "JP" => "keepersecurity.jp",
            "GOV" => "govcloud.keepersecurity.us",
            "US_DEV" => "dev.keepersecurity.com",
            "EU_DEV" => "dev.keepersecurity.eu",
            "AU_DEV" => "dev.keepersecurity.com.au",
            "CA_DEV" => "dev.keepersecurity.ca",
            "JP_DEV" => "dev.keepersecurity.jp",
            "GOV_DEV" => "govcloud.dev.keepersecurity.us",
            "US_QA" => "qa.keepersecurity.com",
            "EU_QA" => "qa.keepersecurity.eu",
            "AU_QA" => "qa.keepersecurity.com.au",
            "CA_QA" => "qa.keepersecurity.ca",
            "JP_QA" => "qa.keepersecurity.jp",
            "GOV_QA" => "govcloud.qa.keepersecurity.us",
            _ => {
                [
                    "keepersecurity.com",
                    "keepersecurity.eu",
                    "keepersecurity.com.au",
                    "keepersecurity.ca",
                    "keepersecurity.jp",
                    "govcloud.keepersecurity.us",
                    "dev.keepersecurity.com",
                    "dev.keepersecurity.eu",
                    "dev.keepersecurity.com.au",
                    "dev.keepersecurity.ca",
                    "dev.keepersecurity.jp",
                    "govcloud.dev.keepersecurity.us",
                    "qa.keepersecurity.com",
                    "qa.keepersecurity.eu",
                    "qa.keepersecurity.com.au",
                    "qa.keepersecurity.ca",
                    "qa.keepersecurity.jp",
                    "govcloud.qa.keepersecurity.us",
                ]
                .into_iter()
                .find(|known| known.eq_ignore_ascii_case(host))
                .ok_or_else(|| Error::Generic(format!("unknown Keeper server {input:?}")))?
            }
        };
        Ok(Self(resolved.into()))
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct RestContext {
    pub host:         Host,
    transmission_key: Vec<u8>,
    server_key_id:    i32,
    #[cfg(test)]
    test_endpoint:    Option<String>,
    http:             reqwest::blocking::Client,
}

impl RestContext {
    pub fn new(server: &str) -> Result<Self> {
        Ok(Self {
            host:                       server.parse()?,
            transmission_key:           crypto::random_bytes(32),
            server_key_id:              DEFAULT_SERVER_KEY_ID,
            #[cfg(test)]
            test_endpoint:              None,
            http:                       reqwest::blocking::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(15))
                .timeout(std::time::Duration::from_secs(300))
                .build()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(endpoint: reqwest::Url, transmission_key: [u8; 32]) -> Result<Self> {
        let host = endpoint.host_str().unwrap_or_default();
        let loopback = if host.eq_ignore_ascii_case("localhost") {
            true
        } else {
            match host.parse::<std::net::IpAddr>() {
                Ok(address) => address.is_loopback(),
                Err(source) => {
                    return Err(Error::Context {
                        context: "test REST endpoint host must be a literal loopback IP".into(),
                        source:  Box::new(Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, source))),
                    });
                }
            }
        };
        if endpoint.scheme() != "http"
            || !loopback
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || !matches!(endpoint.path(), "" | "/")
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::Generic("test REST endpoint must be an explicit loopback HTTP origin".into()));
        }
        Ok(Self {
            host:                       "US".parse()?,
            transmission_key:           transmission_key.into(),
            server_key_id:              DEFAULT_SERVER_KEY_ID,
            #[cfg(test)]
            test_endpoint:              Some(endpoint.origin().ascii_serialization()),
            http:                       reqwest::blocking::Client::builder()
                .no_proxy()
                .connect_timeout(std::time::Duration::from_secs(15))
                .timeout(std::time::Duration::from_secs(300))
                .build()?,
        })
    }

    fn seal_transmission_key(&self) -> Result<Vec<u8>> {
        match self.server_key_id {
            id @ 1..=6 => {
                let public_key = rsa::RsaPublicKey::from_pkcs1_der(&b64_decode(
                    RSA_SERVER_KEYS
                        .get((id - 1) as usize)
                        .ok_or_else(|| Error::api("invalid_key_id", format!("Key ID \"{id}\" is not valid.")))?,
                )?)
                .map_err(|_| Error::Crypto("invalid RSA public key".into()))?;
                public_key
                    .encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, &self.transmission_key)
                    .map_err(|_| Error::Crypto("RSA encryption failed".into()))
            }
            id @ 7..=18 => {
                let public_key = p256::PublicKey::from_sec1_bytes(&b64_decode(
                    EC_SERVER_KEYS
                        .get((id - 7) as usize)
                        .ok_or_else(|| Error::api("invalid_key_id", format!("Key ID \"{id}\" is not valid.")))?,
                )?)
                .map_err(|_| Error::Crypto("invalid EC public key".into()))?;
                crypto::encrypt_ec(&self.transmission_key, &public_key)
            }
            id => Err(Error::api("invalid_key_id", format!("Key ID \"{id}\" is not valid."))),
        }
    }

    pub fn execute<M: Message>(&mut self, endpoint: &str, session_token: &[u8], request: &M) -> Result<Vec<u8>> {
        self.execute_payload(
            endpoint,
            &ApiRequestPayload {
                payload: request.encode_to_vec(),
                encrypted_session_token: session_token.to_vec(),
                ..Default::default()
            },
        )
    }

    /// Sends an already framed payload for the legacy JSON command endpoint.
    pub(crate) fn execute_payload(&mut self, endpoint: &str, payload: &ApiRequestPayload) -> Result<Vec<u8>> {
        #[cfg(test)]
        let url = if let Some(base) = self.test_endpoint.as_ref() {
            format!("{base}/api/rest/{endpoint}")
        } else if endpoint.starts_with("https://") {
            endpoint.to_owned()
        } else {
            format!("https://{}/api/rest/{endpoint}", self.host)
        };
        #[cfg(not(test))]
        let url = if endpoint.starts_with("https://") {
            endpoint.to_owned()
        } else {
            format!("https://{}/api/rest/{endpoint}", self.host)
        };
        let mut throttle_retries = 0;
        loop {
            let request = ApiRequest {
                encrypted_transmission_key: self.seal_transmission_key()?,
                public_key_id: self.server_key_id,
                locale: LOCALE.into(),
                encrypted_payload: crypto::encrypt_aes_v2(&payload.encode_to_vec(), &self.transmission_key)?,
                ..Default::default()
            };
            let response = self
                .http
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .body(request.encode_to_vec())
                .send()?;
            let status = response.status();
            let status_code = status.as_u16();
            let reason = status.canonical_reason().unwrap_or("HTTP error").to_owned();
            let is_json = response
                .headers()
                .get("Content-Type")
                .map(|value| value.to_str())
                .transpose()
                .map_err(|source| {
                    Error::Context {
                        context: "reading REST response Content-Type".into(),
                        source:  Box::new(Error::HeaderValue(source)),
                    }
                })?
                .is_some_and(|value| value.starts_with("application/json"));
            let body = response.bytes()?;

            if status_code == 200 {
                if is_json {
                    return Err(parse_failure(&body).into());
                }
                return if body.is_empty() {
                    Ok(Vec::new())
                } else {
                    crypto::decrypt_aes_v2(&body, &self.transmission_key)
                };
            }
            if !is_json {
                return Err(Error::api(status_code.to_string(), reason));
            }

            let failure = parse_failure(&body);
            if status_code == 401
                && failure.error == "key"
                && let Some(key_id) = failure.key_id.filter(|&id| id != self.server_key_id)
            {
                self.server_key_id = key_id;
                continue;
            }
            if matches!(status_code, 403 | 429) && failure.error == "throttled" {
                throttle_retries += 1;
                if throttle_retries > MAX_THROTTLE_RETRIES {
                    return Err(failure.into());
                }
                let wait = throttle_delay(&failure.message, throttle_retries);
                eprintln!("Throttled (attempt {throttle_retries}/{MAX_THROTTLE_RETRIES}), retrying in {wait} seconds");
                std::thread::sleep(std::time::Duration::from_secs(wait));
                continue;
            }
            return Err(failure.into());
        }
    }
}

fn parse_failure(body: &[u8]) -> ApiFailure {
    // Some endpoints wrap the error object in a one-element array.
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let value = match value {
        serde_json::Value::Array(mut items) if !items.is_empty() => items.swap_remove(0),
        other => other,
    };
    serde_json::from_value(value).unwrap_or_else(|_| {
        ApiFailure {
            error: "unknown".into(),
            message: String::from_utf8_lossy(body).into_owned(),
            ..Default::default()
        }
    })
}

/// Honors the server's "try again in N seconds/minutes" hint (capped at 5 minutes) but never
/// waits less than an exponential 30s backoff.
fn throttle_delay(message: &str, attempt: u32) -> u64 {
    let lower = message.to_lowercase();
    let hinted = lower
        .split_whitespace()
        .zip(lower.split_whitespace().skip(1))
        .find_map(|(number, unit)| {
            let n: u64 = number.parse().ok()?;
            if unit.starts_with("minute") {
                Some(n * 60)
            } else if unit.starts_with("second") {
                Some(n)
            } else {
                None
            }
        });
    hinted.unwrap_or(60).min(300).max(30 * 2u64.pow(attempt - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_server_key_parses() {
        for key in RSA_SERVER_KEYS {
            rsa::RsaPublicKey::from_pkcs1_der(&b64_decode(key).unwrap()).unwrap();
        }
        for key in EC_SERVER_KEYS {
            p256::PublicKey::from_sec1_bytes(&b64_decode(key).unwrap()).unwrap();
        }
    }

    #[test]
    fn malformed_response_content_type_preserves_header_error_source() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            let mut total = None;
            while total.is_none_or(|total| request.len() < total) {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "REST client closed before sending its request");
                request.extend_from_slice(chunk.get(..read).expect("read count fits chunk"));
                if total.is_none()
                    && let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let (headers, _) = request.split_at_checked(head_end).expect("header delimiter was found");
                    let headers = String::from_utf8_lossy(headers).to_lowercase();
                    let body_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .map_or(0, |length| length.trim().parse().unwrap());
                    total = Some(
                        head_end
                            .checked_add(4)
                            .and_then(|header| header.checked_add(body_length))
                            .expect("REST request length fits usize"),
                    );
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: \xff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let mut rest = RestContext::for_test(reqwest::Url::parse(&endpoint).unwrap(), [7; 32]).unwrap();
        let error = rest
            .execute("vault/files_download", &[1], &crate::proto::records::FilesGetRequest::default())
            .unwrap_err();
        assert!(matches!(
            error,
            crate::Error::Context { source, .. } if matches!(*source, crate::Error::HeaderValue(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn host_resolves_regions_and_rejects_unknown_values() {
        assert_eq!("EU".parse::<Host>().unwrap().to_string(), "keepersecurity.eu");
        assert_eq!("us-dev".parse::<Host>().unwrap().to_string(), "dev.keepersecurity.com");
        assert_eq!(
            "https://govcloud.keepersecurity.us/api/v2/"
                .parse::<Host>()
                .unwrap()
                .to_string(),
            "govcloud.keepersecurity.us"
        );
        assert!("".parse::<Host>().is_err());
        assert!("unknown.example.com".parse::<Host>().is_err());
    }

    #[test]
    fn throttle_delay_respects_hint_cap_and_backoff_floor() {
        assert_eq!(throttle_delay("Please try again in 2 minutes", 1), 120);
        assert_eq!(throttle_delay("try again in 10 seconds", 1), 30);
        assert_eq!(throttle_delay("try again in 10 seconds", 3), 120);
        assert_eq!(throttle_delay("try again in 30 minutes", 1), 300);
        assert_eq!(throttle_delay("throttled", 1), 60);
    }
}
