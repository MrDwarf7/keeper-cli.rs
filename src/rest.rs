//! Keeper's encrypted REST transport. Every request body is an `ApiRequest` whose payload is
//! AES-GCM encrypted with a per-session transmission key; that key is itself sealed to one of
//! Keeper's published server keys (RSA for ids 1-6, P-256 for 7-18).
//!
//! Commander additionally supports ML-KEM hybrid ("QRC") key exchange. The server still
//! accepts the classic EC exchange, which is all this client implements.

use std::time::Duration;

use prost::Message;
use serde::Deserialize;

use crate::crypto;
use crate::prelude::*;
use crate::proto::authentication::{ApiRequest, ApiRequestPayload};

pub const CLIENT_VERSION: &str = "c18.1.0";
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

/// JSON error body returned with HTTP 4xx/5xx.
#[derive(Debug, Default, Deserialize)]
pub struct ApiFailure {
    #[serde(default, alias = "result_code")]
    pub error:           String,
    #[serde(default)]
    pub message:         String,
    #[serde(default)]
    pub additional_info: Option<String>,
    #[serde(default)]
    pub key_id:          Option<i32>,
    #[serde(default)]
    pub region_host:     Option<String>,
}

impl From<ApiFailure> for Error {
    fn from(f: ApiFailure) -> Self {
        Error::api(f.error, f.message)
    }
}

pub enum Response {
    Ok(Vec<u8>),
    Failed(ApiFailure),
}

pub struct RestContext {
    pub server_base:  String,
    transmission_key: Vec<u8>,
    pub server_key_id: i32,
    pub locale:       String,
    http:             reqwest::blocking::Client,
}

/// `keepersecurity.eu` and `https://keepersecurity.eu/api/v2/` both mean the same server.
pub fn server_host(server: &str) -> String {
    let without_scheme = server.split_once("://").map_or(server, |(_, rest)| rest);
    without_scheme.split('/').next().unwrap_or_default().to_owned()
}

impl RestContext {
    pub fn new(server: &str) -> Result<Self> {
        Ok(Self {
            server_base:      format!("https://{}/api/rest/", server_host(server)),
            transmission_key: crypto::random_bytes(32),
            server_key_id:    DEFAULT_SERVER_KEY_ID,
            locale:           "en_US".into(),
            http:             reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(300))
                .build()?,
        })
    }

    pub fn set_server(&mut self, server: &str) {
        self.server_base = format!("https://{}/api/rest/", server_host(server));
    }

    pub fn host(&self) -> String {
        server_host(&self.server_base)
    }

    fn seal_transmission_key(&self) -> Result<Vec<u8>> {
        match self.server_key_id {
            id @ 1..=6 => crypto::encrypt_rsa(
                &self.transmission_key,
                &crypto::load_rsa_public_key(&b64_decode(RSA_SERVER_KEYS[id as usize - 1])?)?,
            ),
            id @ 7..=18 => crypto::encrypt_ec(
                &self.transmission_key,
                &crypto::load_ec_public_key(&b64_decode(EC_SERVER_KEYS[id as usize - 7])?)?,
            ),
            id => Err(Error::api("invalid_key_id", format!("Key ID \"{id}\" is not valid."))),
        }
    }

    pub fn execute(&mut self, endpoint: &str, payload: &ApiRequestPayload) -> Result<Response> {
        let url = if endpoint.starts_with("https://") {
            endpoint.to_owned()
        } else {
            format!("{}{}", self.server_base, endpoint)
        };
        let mut throttle_retries = 0;
        loop {
            let request = ApiRequest {
                encrypted_transmission_key: self.seal_transmission_key()?,
                public_key_id: self.server_key_id,
                locale: self.locale.clone(),
                encrypted_payload: crypto::encrypt_aes_v2(&payload.encode_to_vec(), &self.transmission_key)?,
                ..Default::default()
            };
            let rs = self
                .http
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .body(request.encode_to_vec())
                .send()?;
            let status = rs.status().as_u16();
            let is_json = rs
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/json"));
            let body = rs.bytes()?;

            if status == 200 {
                if is_json {
                    return Ok(Response::Failed(parse_failure(&body)));
                }
                return Ok(Response::Ok(if body.is_empty() {
                    Vec::new()
                } else {
                    crypto::decrypt_aes_v2(&body, &self.transmission_key)?
                }));
            }
            if !is_json {
                return Err(Error::api(status.to_string(), String::from_utf8_lossy(&body).into_owned()));
            }

            let failure = parse_failure(&body);
            if status == 401 && failure.error == "key" {
                if let Some(key_id) = failure.key_id.filter(|&id| id != self.server_key_id) {
                    self.server_key_id = key_id;
                    continue;
                }
            }
            if matches!(status, 403 | 429) && failure.error == "throttled" {
                throttle_retries += 1;
                if throttle_retries > MAX_THROTTLE_RETRIES {
                    return Err(failure.into());
                }
                let wait = throttle_delay(&failure.message, throttle_retries);
                eprintln!("Throttled (attempt {throttle_retries}/{MAX_THROTTLE_RETRIES}), retrying in {wait} seconds");
                std::thread::sleep(Duration::from_secs(wait));
                continue;
            }
            return Ok(Response::Failed(failure));
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
    serde_json::from_value(value).unwrap_or_else(|_| ApiFailure {
        error:   "unknown".into(),
        message: String::from_utf8_lossy(body).into_owned(),
        ..Default::default()
    })
}

/// Honors the server's "try again in N seconds/minutes" hint (capped at 5 minutes) but never
/// waits less than an exponential 30s backoff.
fn throttle_delay(message: &str, attempt: u32) -> u64 {
    let lower = message.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let hinted = words.windows(2).find_map(|w| {
        let n: u64 = w[0].parse().ok()?;
        if w[1].starts_with("minute") {
            Some(n * 60)
        } else if w[1].starts_with("second") {
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
            crypto::load_rsa_public_key(&b64_decode(key).unwrap()).unwrap();
        }
        for key in EC_SERVER_KEYS {
            crypto::load_ec_public_key(&b64_decode(key).unwrap()).unwrap();
        }
    }

    #[test]
    fn server_host_normalizes_region_inputs() {
        assert_eq!(server_host("keepersecurity.eu"), "keepersecurity.eu");
        assert_eq!(server_host("https://keepersecurity.com/api/v2/"), "keepersecurity.com");
        assert_eq!(server_host("https://govcloud.keepersecurity.us/api/rest/"), "govcloud.keepersecurity.us");
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
