pub use crate::error::{Error, Result};

/// Keeper encodes every UID and binary blob as unpadded URL-safe base64.
pub fn b64_encode(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// Accepts padded or unpadded input, as Commander's decoder does.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.trim_end_matches('=').as_bytes())
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_errors_preserve_their_source_without_echoing_input() {
        let input = "private-encoded-key!";
        let original = data_encoding::BASE64URL_NOPAD.decode(input.as_bytes()).unwrap_err();
        let error = b64_decode(input).unwrap_err();
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<data_encoding::DecodeError>()
            .unwrap();
        assert_eq!(source, &original);
        assert!(!error.to_string().contains(input));
        assert!(!format!("{error:?}").contains(input));
    }
}
