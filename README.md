# bunnyapp-license-rust

License validation SDK for Bunny subscriptions.

## Usage

```rust
use bunnyapp_license::{validate_license, LicenseClaims, LicenseError};

#[tokio::main]
async fn main() -> Result<(), LicenseError> {
    let claims: LicenseClaims = validate_license().await?;
    println!("subscription: {:?}", claims.subscription);
    Ok(())
}
```

A single call to `validate_license()` automatically selects the correct mode based on which environment variable is set.

## Environment variables

| Variable                    | Required         | Description                                              |
| --------------------------- | ---------------- | -------------------------------------------------------- |
| `BUNNY_HOST`                | Online mode only | Base URL of the Bunny API, e.g. `https://auth.bunny.com` |
| `BUNNY_LICENSE_KEY`         | Online mode      | License key sent to the API for validation               |
| `BUNNY_OFFLINE_LICENSE_KEY` | Offline mode     | Pre-issued JWT used in air-gapped environments           |

`BUNNY_LICENSE_KEY` takes precedence. If neither is set, `validate_license()` returns `LicenseError::NoLicenseKeySet`.

## Modes

### Online mode

Set `BUNNY_LICENSE_KEY` and `BUNNY_HOST`. The SDK will:

1. POST to `{BUNNY_HOST}/api/license/validate` with the key as a Bearer token.
2. Extract the JWT from the `{ "token": "..." }` response.
3. Fetch `{BUNNY_HOST}/api/.well-known/jwks.json` and verify the JWT signature.
4. Return the verified `LicenseClaims`.

### Offline / air-gapped mode

Set `BUNNY_OFFLINE_LICENSE_KEY` to the pre-issued JWT. The SDK will:

1. Verify the JWT signature against the keys bundled inside the SDK.
2. Return the verified `LicenseClaims`.

Only asymmetric algorithms (RS*, ES*, PS*) are accepted; symmetric (HS*) algorithms are rejected.

## Claims

```rust
pub struct LicenseClaims {
    pub sub: Option<String>,
    pub iat: Option<u64>,
    pub exp: u64,
    pub subscription: serde_json::Value,  // customer entitlements
}
```

## Testing

Run the full test suite:

```sh
cargo test
```

Useful variants:

```sh
cargo test verify_     # unit tests for JWT verification logic only
cargo test offline_    # offline mode tests only
cargo test online_     # online mode tests only (spins up a mock HTTP server)
```

The test suite covers both modes end-to-end without requiring a live Bunny API. Online tests use a `wiremock` mock server; offline tests use a separate test JWKS (`src/keys/test_offline_jwks.json`) that is swapped in at compile time via `#[cfg(test)]` so the production bundled keys are never touched by tests.

## Rotating offline keys

When Bunny rotates its signing keys, update the bundled JWKS and cut a new SDK release:

```sh
curl https://auth.bunny.com/api/.well-known/jwks.json \
  > src/keys/offline_jwks.json
```

Then rebuild and publish (see [Publishing](#publishing) below).

## Publishing

Bump the version in [Cargo.toml](Cargo.toml), then:

```sh
cargo test                     # all tests must pass
cargo publish --dry-run        # verify packaging
cargo publish                  # push to crates.io
```

Tag the release after publishing:

```sh
git tag v$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
git push origin --tags
```

The crate is published as [`bunnyapp-license`](https://crates.io/crates/bunnyapp-license).
