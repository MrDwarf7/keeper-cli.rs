pub use crate::error::{Error, Result};

/// Keeper encodes every UID and binary blob as unpadded URL-safe base64.
pub fn b64_encode(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// Accepts padded or unpadded input, as Commander's decoder does.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.trim_end_matches('=').as_bytes())
        .map_err(|e| Error::Generic(format!("invalid base64 '{s}': {e}")))
}
