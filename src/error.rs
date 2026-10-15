pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default, serde::Deserialize)]
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

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source:  Box<Error>,
    },

    #[error("attachment download failed with {} error(s)", .failures.len())]
    DownloadBatch { failures: Vec<Error> },

    #[error("{0}")]
    Generic(String),

    #[error("{0}")]
    Api(ApiFailure),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("invalid P-256 key: {0}")]
    P256(#[from] p256::elliptic_curve::Error),

    #[error("not logged in")]
    NotLoggedIn,

    #[error("cancelled")]
    Cancelled,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("integer conversion: {0}")]
    Integer(#[from] std::num::TryFromIntError),

    #[error("invalid integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("invalid base64 data: {0}")]
    Base64(#[from] data_encoding::DecodeError),

    #[error("allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error("malformed server response: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("unknown protocol enum value {}", .0.0)]
    UnknownEnum(#[from] prost::UnknownEnumValue),

    #[error("config: {0}")]
    Config(#[from] config::ConfigError),
}

impl From<ApiFailure> for Error {
    fn from(failure: ApiFailure) -> Self {
        Self::Api(failure)
    }
}

impl Error {
    pub fn api(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Api(ApiFailure {
            error: code.into(),
            message: message.into(),
            ..Default::default()
        })
    }
}
