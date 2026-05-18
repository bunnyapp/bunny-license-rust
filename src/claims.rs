use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub sub: Option<String>,
    pub iat: Option<u64>,
    pub exp: u64,
    /// Entitlements granted to this customer.
    pub subscription: Value,
}
