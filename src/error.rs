use std::fmt;

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

impl fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
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
