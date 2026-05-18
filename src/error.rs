use thiserror::Error;

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("no license key set — provide BUNNY_LICENSE_KEY or BUNNY_OFFLINE_LICENSE_KEY")]
    NoLicenseKeySet,

    #[error("BUNNY_HOST environment variable is not set")]
    NoHostSet,

    #[error("license validation request failed with status {status}")]
    ValidationFailed { status: u16 },

    #[error("server response missing 'token' field")]
    MissingToken,

    #[error("JWT header is missing 'kid' claim")]
    MissingKeyId,

    #[error("no key in JWKS matches kid '{0}'")]
    KeyNotFound(String),

    #[error("algorithm '{0}' is not permitted — only asymmetric algorithms are accepted")]
    UnsupportedAlgorithm(String),

    #[error("license token has expired")]
    TokenExpired,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("failed to parse JWKS: {0}")]
    JwksParse(String),
}
