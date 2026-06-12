//! JWT issuance and verification (SPEC §2).

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub scope: String,
}

/// JWT `sub` of the authenticated caller, injected into request extensions.
#[derive(Clone)]
pub struct Actor(pub String);

/// Constant-time string equality (hash first so length is not observable).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    ha[..].ct_eq(&hb[..]).into()
}

pub fn issue_token(cfg: &crate::Config, sub: &str) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        iss: cfg.jwt_issuer.clone(),
        sub: sub.to_string(),
        iat: now,
        exp: now + cfg.jwt_ttl_seconds,
        scope: "keys:admin".to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::internal(format!("jwt encode: {e}")))
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("missing bearer token"))?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[state.cfg.jwt_issuer.as_str()]);
    validation.validate_exp = true;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::unauthorized("invalid or expired token"))?;

    req.extensions_mut().insert(Actor(data.claims.sub));
    Ok(next.run(req).await)
}
