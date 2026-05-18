mod claims;
mod error;

pub use claims::LicenseClaims;
pub use error::LicenseError;

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env};

// In tests, swap in a JWKS that contains the test RSA key so the offline path
// can be exercised end-to-end without touching the real bundled keys.
#[cfg(not(test))]
const OFFLINE_JWKS: &str = include_str!("keys/offline_jwks.json");
#[cfg(test)]
const OFFLINE_JWKS: &str = include_str!("keys/test_offline_jwks.json");

const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

const EXPECTED_ISSUER: &str = "https://auth.bunny.com";
const EXPECTED_AUDIENCE: &str = "bunny-license-key";

#[derive(Serialize)]
struct ValidateRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_fingerprint: Option<&'a str>,
}

#[derive(Deserialize)]
struct ValidateResponse {
    token: String,
}

/// Validate the Bunny license and return the verified JWT claims.
///
/// Checks `BUNNY_LICENSE_KEY` first (online mode), then falls back to
/// `BUNNY_OFFLINE_LICENSE_KEY` (offline / air-gapped mode).
/// Online mode also requires `BUNNY_HOST` to be set.
pub async fn validate_license(instance_fingerprint: Option<&str>) -> Result<LicenseClaims, LicenseError> {
    if let Ok(key) = env::var("BUNNY_LICENSE_KEY") {
        validate_online(&key, instance_fingerprint).await
    } else if let Ok(token) = env::var("BUNNY_OFFLINE_LICENSE_KEY") {
        validate_offline(&token)
    } else {
        Err(LicenseError::NoLicenseKeySet)
    }
}

fn build_client() -> Result<Client, LicenseError> {
    let accept_invalid = env::var("BUNNY_DANGER_ACCEPT_INVALID_CERTS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    Client::builder()
        .danger_accept_invalid_certs(accept_invalid)
        .build()
        .map_err(LicenseError::Http)
}

async fn validate_online(license_key: &str, instance_fingerprint: Option<&str>) -> Result<LicenseClaims, LicenseError> {
    let host = env::var("BUNNY_HOST").map_err(|_| LicenseError::NoHostSet)?;
    let client = build_client()?;

    let response = client
        .post(format!("{}/api/license/validate", host))
        .bearer_auth(license_key)
        .json(&ValidateRequest { instance_fingerprint })
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(LicenseError::ValidationFailed {
            status: status.as_u16(),
        });
    }

    let body: ValidateResponse = response
        .json()
        .await
        .map_err(|_| LicenseError::MissingToken)?;

    let jwks_response = client
        .get(format!("{}/api/.well-known/jwks.json", host))
        .send()
        .await?;

    let jwks: JwkSet = jwks_response
        .json()
        .await
        .map_err(|e| LicenseError::JwksParse(e.to_string()))?;

    verify_jwt(&body.token, &jwks)
}

fn validate_offline(token: &str) -> Result<LicenseClaims, LicenseError> {
    let jwks: JwkSet =
        serde_json::from_str(OFFLINE_JWKS).map_err(|e| LicenseError::JwksParse(e.to_string()))?;

    verify_jwt(token, &jwks)
}

fn verify_jwt(token: &str, jwks: &JwkSet) -> Result<LicenseClaims, LicenseError> {
    let header = decode_header(token)?;

    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(LicenseError::UnsupportedAlgorithm(format!(
            "{:?}",
            header.alg
        )));
    }

    let kid = header.kid.ok_or(LicenseError::MissingKeyId)?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| LicenseError::KeyNotFound(kid.clone()))?;

    let decoding_key = DecodingKey::from_jwk(jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    validation.required_spec_claims = HashSet::from(["exp".to_string()]);
    validation.set_issuer(&[EXPECTED_ISSUER]);
    validation.set_audience(&[EXPECTED_AUDIENCE]);

    decode::<LicenseClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => LicenseError::TokenExpired,
            _ => LicenseError::Jwt(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use serial_test::serial;
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_KID: &str = "test-key-1";
    const TEST_RSA_N: &str = "pzxnaqHr0kjYR5W3aYq_2QduN5oymUoH3YH6U4dk9W6lra2XmQaTidQs1xHVn79WZOs4CNgU_RvScalyEPaMt0SHta3rwMSdTk2ShfNA831jDwDFpjQGcyAWM3d4IowHFDC6cXkttNKNXGqoDQMq_qXfoHjYAkAVv2O9jyg7mJo8pZeeOxzj8vAtQlUFcDM2x3cHuGJl48DASC1cG2WI606ppz319c7gmwVKnay7vOQScek4ErJ3EMh9AypFHSju3fRVhjobFALO7xwta09CWTk25DHAd3mcYvLviGikOAPnI0bxEPZYS42IXmLG7GyNMa7sYhcvYNsK7m3YtWGbpQ";
    const TEST_PRIVATE_KEY: &str = include_str!("keys/test_private_key.pem");

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Builds a full valid claims payload including the required iss and aud.
    fn valid_claims_json() -> Value {
        let now = unix_now();
        json!({
            "sub": "cust_test",
            "iat": now,
            "exp": now + 3600,
            "iss": EXPECTED_ISSUER,
            "aud": EXPECTED_AUDIENCE,
            "subscription": { "plan": "pro", "seats": 10 }
        })
    }

    fn make_jwt(claims: &Value, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(str::to_string);
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn make_hs256_jwt(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        encode(&header, claims, &EncodingKey::from_secret(b"secret")).unwrap()
    }

    fn test_jwks_json() -> Value {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": TEST_KID,
                "n": TEST_RSA_N,
                "e": "AQAB"
            }]
        })
    }

    fn test_jwks() -> JwkSet {
        serde_json::from_value(test_jwks_json()).unwrap()
    }

    // ── verify_jwt (direct, no env vars, sync) ──────────────────────────────

    #[test]
    fn verify_valid_jwt_returns_claims() {
        let token = make_jwt(&valid_claims_json(), Some(TEST_KID));
        let result = verify_jwt(&token, &test_jwks()).unwrap();
        assert_eq!(result.subscription, json!({ "plan": "pro", "seats": 10 }));
        assert_eq!(result.sub.as_deref(), Some("cust_test"));
    }

    #[test]
    fn verify_expired_jwt_returns_token_expired() {
        let now = unix_now();
        let claims = json!({
            "sub": "cust_test",
            "iat": now - 7200,
            "exp": now - 3600,
            "iss": EXPECTED_ISSUER,
            "aud": EXPECTED_AUDIENCE,
            "subscription": {}
        });
        let token = make_jwt(&claims, Some(TEST_KID));
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::TokenExpired));
    }

    #[test]
    fn verify_hs256_jwt_returns_unsupported_algorithm() {
        let token = make_hs256_jwt(&valid_claims_json());
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn verify_unknown_kid_returns_key_not_found() {
        let token = make_jwt(&valid_claims_json(), Some("no-such-key"));
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::KeyNotFound(_)));
    }

    #[test]
    fn verify_missing_kid_returns_missing_key_id() {
        let token = make_jwt(&valid_claims_json(), None);
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::MissingKeyId));
    }

    #[test]
    fn verify_wrong_issuer_returns_jwt_error() {
        let mut claims = valid_claims_json();
        claims["iss"] = json!("https://evil.example.com");
        let token = make_jwt(&claims, Some(TEST_KID));
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::Jwt(_)));
    }

    #[test]
    fn verify_wrong_audience_returns_jwt_error() {
        let mut claims = valid_claims_json();
        claims["aud"] = json!("wrong-audience");
        let token = make_jwt(&claims, Some(TEST_KID));
        let err = verify_jwt(&token, &test_jwks()).unwrap_err();
        assert!(matches!(err, LicenseError::Jwt(_)));
    }

    // ── validate_license routing ─────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn no_env_vars_returns_no_license_key_set() {
        env::remove_var("BUNNY_LICENSE_KEY");
        env::remove_var("BUNNY_OFFLINE_LICENSE_KEY");
        let err = validate_license(None).await.unwrap_err();
        assert!(matches!(err, LicenseError::NoLicenseKeySet));
    }

    #[tokio::test]
    #[serial]
    async fn online_mode_without_host_returns_no_host_set() {
        env::set_var("BUNNY_LICENSE_KEY", "any-key");
        env::remove_var("BUNNY_HOST");
        let err = validate_license(None).await.unwrap_err();
        env::remove_var("BUNNY_LICENSE_KEY");
        assert!(matches!(err, LicenseError::NoHostSet));
    }

    // ── offline mode ─────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn offline_valid_jwt_returns_claims() {
        let token = make_jwt(&valid_claims_json(), Some(TEST_KID));
        env::remove_var("BUNNY_LICENSE_KEY");
        env::set_var("BUNNY_OFFLINE_LICENSE_KEY", &token);
        let result = validate_license(None).await;
        env::remove_var("BUNNY_OFFLINE_LICENSE_KEY");

        let claims = result.unwrap();
        assert_eq!(claims.subscription, json!({ "plan": "pro", "seats": 10 }));
    }

    #[tokio::test]
    #[serial]
    async fn offline_expired_jwt_returns_token_expired() {
        let now = unix_now();
        let claims = json!({
            "sub": "cust_test",
            "iat": now - 7200,
            "exp": now - 3600,
            "iss": EXPECTED_ISSUER,
            "aud": EXPECTED_AUDIENCE,
            "subscription": {}
        });
        let token = make_jwt(&claims, Some(TEST_KID));
        env::remove_var("BUNNY_LICENSE_KEY");
        env::set_var("BUNNY_OFFLINE_LICENSE_KEY", &token);
        let err = validate_license(None).await.unwrap_err();
        env::remove_var("BUNNY_OFFLINE_LICENSE_KEY");
        assert!(matches!(err, LicenseError::TokenExpired));
    }

    #[tokio::test]
    #[serial]
    async fn offline_unknown_kid_returns_key_not_found() {
        let token = make_jwt(&valid_claims_json(), Some("rotated-key-not-in-bundle"));
        env::remove_var("BUNNY_LICENSE_KEY");
        env::set_var("BUNNY_OFFLINE_LICENSE_KEY", &token);
        let err = validate_license(None).await.unwrap_err();
        env::remove_var("BUNNY_OFFLINE_LICENSE_KEY");
        assert!(matches!(err, LicenseError::KeyNotFound(_)));
    }

    // ── online mode (mock server) ─────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn online_server_returns_401_yields_validation_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/license/validate"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        env::set_var("BUNNY_LICENSE_KEY", "bad-key");
        env::set_var("BUNNY_HOST", server.uri());
        let err = validate_license(None).await.unwrap_err();
        env::remove_var("BUNNY_LICENSE_KEY");
        env::remove_var("BUNNY_HOST");

        assert!(matches!(err, LicenseError::ValidationFailed { status: 401 }));
    }

    #[tokio::test]
    #[serial]
    async fn online_valid_flow_returns_claims() {
        let server = MockServer::start().await;

        let token = make_jwt(&valid_claims_json(), Some(TEST_KID));

        Mock::given(method("POST"))
            .and(path("/api/license/validate"))
            .and(header("authorization", "Bearer valid-license-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_json()))
            .mount(&server)
            .await;

        env::set_var("BUNNY_LICENSE_KEY", "valid-license-key");
        env::set_var("BUNNY_HOST", server.uri());
        let result = validate_license(None).await;
        env::remove_var("BUNNY_LICENSE_KEY");
        env::remove_var("BUNNY_HOST");

        let claims = result.unwrap();
        assert_eq!(claims.subscription, json!({ "plan": "pro", "seats": 10 }));
        assert_eq!(claims.sub.as_deref(), Some("cust_test"));
    }

    #[tokio::test]
    #[serial]
    async fn online_sends_instance_fingerprint_in_body() {
        use wiremock::matchers::body_json;

        let server = MockServer::start().await;
        let token = make_jwt(&valid_claims_json(), Some(TEST_KID));

        Mock::given(method("POST"))
            .and(path("/api/license/validate"))
            .and(body_json(json!({ "instance_fingerprint": "device-abc-123" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_json()))
            .mount(&server)
            .await;

        env::set_var("BUNNY_LICENSE_KEY", "valid-license-key");
        env::set_var("BUNNY_HOST", server.uri());
        let result = validate_license(Some("device-abc-123")).await;
        env::remove_var("BUNNY_LICENSE_KEY");
        env::remove_var("BUNNY_HOST");

        result.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn online_expired_jwt_from_server_returns_token_expired() {
        let server = MockServer::start().await;

        let now = unix_now();
        let claims = json!({
            "sub": "cust_test",
            "iat": now - 7200,
            "exp": now - 3600,
            "iss": EXPECTED_ISSUER,
            "aud": EXPECTED_AUDIENCE,
            "subscription": {}
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        Mock::given(method("POST"))
            .and(path("/api/license/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_json()))
            .mount(&server)
            .await;

        env::set_var("BUNNY_LICENSE_KEY", "some-key");
        env::set_var("BUNNY_HOST", server.uri());
        let err = validate_license(None).await.unwrap_err();
        env::remove_var("BUNNY_LICENSE_KEY");
        env::remove_var("BUNNY_HOST");

        assert!(matches!(err, LicenseError::TokenExpired));
    }
}
