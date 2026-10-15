// in-crate result type
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Generic(String),

    /// An error reported by the Keeper API (`result_code` / `error` plus message).
    #[error("{code}: {message}")]
    Api { code: String, message: String },

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("not logged in")]
    NotLoggedIn,

    #[error("cancelled")]
    Cancelled,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error("malformed server response: {0}")]
    Decode(#[from] prost::DecodeError),
}

impl Error {
    pub fn api(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Api {
            code:    code.into(),
            message: message.into(),
        }
    }
}
