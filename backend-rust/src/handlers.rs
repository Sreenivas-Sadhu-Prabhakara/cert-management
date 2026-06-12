//! HTTP handlers — endpoints, JSON shapes and state machine per SPEC §5–§7.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgExecutor, Row};
use uuid::Uuid;

use crate::auth::{constant_time_eq, issue_token, Actor};
use crate::chain::{self, ChainError};
use crate::crypto;
use crate::csr;
use crate::error::AppError;
use crate::AppState;

const STATUSES: [&str; 5] = ["CREATED", "READY_TO_PUBLISH", "ACTIVE", "COMPROMISED", "DELETED"];

// ---------------------------------------------------------------------------
// Row model and JSON shapes
// ---------------------------------------------------------------------------

struct KeyRow {
    id: Uuid,
    name: String,
    algorithm: String,
    status: String,
    public_key_pem: String,
    private_key_enc: Option<String>,
    fingerprint_sha256: String,
    certificate_chain_pem: Option<String>,
    cert_subject: Option<String>,
    cert_issuer: Option<String>,
    cert_serial: Option<String>,
    cert_not_before: Option<DateTime<Utc>>,
    cert_not_after: Option<DateTime<Utc>>,
    compromised_reason: Option<String>,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn map_key_row(row: &PgRow) -> Result<KeyRow, sqlx::Error> {
    Ok(KeyRow {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        algorithm: row.try_get("algorithm")?,
        status: row.try_get("status")?,
        public_key_pem: row.try_get("public_key_pem")?,
        private_key_enc: row.try_get("private_key_enc")?,
        fingerprint_sha256: row.try_get("fingerprint_sha256")?,
        certificate_chain_pem: row.try_get("certificate_chain_pem")?,
        cert_subject: row.try_get("cert_subject")?,
        cert_issuer: row.try_get("cert_issuer")?,
        cert_serial: row.try_get("cert_serial")?,
        cert_not_before: row.try_get("cert_not_before")?,
        cert_not_after: row.try_get("cert_not_after")?,
        compromised_reason: row.try_get("compromised_reason")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeySummary {
    id: Uuid,
    name: String,
    algorithm: String,
    status: String,
    fingerprint_sha256: String,
    has_certificate: bool,
    cert_not_after: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateInfo {
    subject: String,
    issuer: String,
    serial_number: String,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyDetail {
    id: Uuid,
    name: String,
    algorithm: String,
    status: String,
    public_key_pem: String,
    fingerprint_sha256: String,
    has_certificate: bool,
    certificate_chain_pem: Option<String>,
    certificate: Option<CertificateInfo>,
    cert_not_after: Option<DateTime<Utc>>,
    compromised_reason: Option<String>,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
}

impl KeyRow {
    fn to_summary(&self) -> KeySummary {
        KeySummary {
            id: self.id,
            name: self.name.clone(),
            algorithm: self.algorithm.clone(),
            status: self.status.clone(),
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            has_certificate: self.certificate_chain_pem.is_some(),
            cert_not_after: self.cert_not_after,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    fn to_detail(&self, private_key_pem: Option<String>) -> KeyDetail {
        let certificate = self.cert_subject.as_ref().map(|subject| CertificateInfo {
            subject: subject.clone(),
            issuer: self.cert_issuer.clone().unwrap_or_default(),
            serial_number: self.cert_serial.clone().unwrap_or_default(),
            not_before: self.cert_not_before,
            not_after: self.cert_not_after,
        });
        KeyDetail {
            id: self.id,
            name: self.name.clone(),
            algorithm: self.algorithm.clone(),
            status: self.status.clone(),
            public_key_pem: self.public_key_pem.clone(),
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            has_certificate: self.certificate_chain_pem.is_some(),
            certificate_chain_pem: self.certificate_chain_pem.clone(),
            certificate,
            cert_not_after: self.cert_not_after,
            compromised_reason: self.compromised_reason.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            private_key_pem,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventDto {
    id: i64,
    key_id: Uuid,
    event_type: String,
    actor: String,
    backend: String,
    detail: Option<Value>,
    occurred_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn parse_json<T: DeserializeOwned>(body: &Bytes) -> Result<T, AppError> {
    serde_json::from_slice(body)
        .map_err(|e| AppError::invalid_request(format!("malformed request body: {e}")))
}

/// SPEC §6: malformed UUIDs in the path behave like unknown ids -> 404.
fn parse_uuid(raw: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw).map_err(|_| AppError::not_found())
}

async fn fetch_key<'e, E: PgExecutor<'e>>(exec: E, id: Uuid) -> Result<KeyRow, AppError> {
    let row = sqlx::query("SELECT * FROM ssl_keys WHERE id = $1")
        .bind(id)
        .fetch_optional(exec)
        .await?
        .ok_or_else(AppError::not_found)?;
    Ok(map_key_row(&row)?)
}

async fn key_exists<'e, E: PgExecutor<'e>>(exec: E, id: Uuid) -> Result<bool, AppError> {
    let row = sqlx::query("SELECT 1 AS one FROM ssl_keys WHERE id = $1")
        .bind(id)
        .fetch_optional(exec)
        .await?;
    Ok(row.is_some())
}

async fn insert_audit<'e, E: PgExecutor<'e>>(
    exec: E,
    key_id: Uuid,
    event_type: &str,
    actor: &str,
    backend: &str,
    detail: Option<Value>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO key_audit_events (key_id, event_type, actor, backend, detail) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(key_id)
    .bind(event_type)
    .bind(actor)
    .bind(backend)
    .bind(detail)
    .execute(exec)
    .await?;
    Ok(())
}

fn decrypt_for(state: &AppState, row: &KeyRow) -> Result<String, AppError> {
    let enc = row
        .private_key_enc
        .as_deref()
        .ok_or_else(|| AppError::internal("private key material missing"))?;
    crypto::decrypt_private_key(&state.cfg.master_key, &row.id, enc)
        .map_err(|e| AppError::internal(format!("decrypt failed for {}: {e}", row.id)))
}

// ---------------------------------------------------------------------------
// Health + auth
// ---------------------------------------------------------------------------

pub async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "up", "backend": state.cfg.backend_name})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "down", "backend": state.cfg.backend_name})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRequest {
    client_id: String,
    client_secret: String,
}

pub async fn token(State(state): State<AppState>, body: Bytes) -> Result<Response, AppError> {
    let req: TokenRequest = parse_json(&body)?;
    let id_ok = constant_time_eq(&req.client_id, &state.cfg.auth_client_id);
    let secret_ok = constant_time_eq(&req.client_secret, &state.cfg.auth_client_secret);
    if !(id_ok & secret_ok) {
        return Err(AppError::unauthorized("invalid client credentials"));
    }
    let jwt = issue_token(&state.cfg, &req.client_id)?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "accessToken": jwt,
            "tokenType": "Bearer",
            "expiresIn": state.cfg.jwt_ttl_seconds,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyRequest {
    name: Option<String>,
    algorithm: Option<String>,
}

pub async fn create_key(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    body: Bytes,
) -> Result<Response, AppError> {
    let req: CreateKeyRequest = parse_json(&body)?;
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| AppError::invalid_request("name is required"))?
        .to_string();
    let algorithm = req
        .algorithm
        .filter(|a| crypto::ALGORITHMS.contains(&a.as_str()))
        .ok_or_else(|| {
            AppError::invalid_request(format!(
                "algorithm is required and must be one of {}",
                crypto::ALGORITHMS.join(", ")
            ))
        })?;

    let algo = algorithm.clone();
    let generated = tokio::task::spawn_blocking(move || crypto::generate_key(&algo))
        .await
        .map_err(|e| AppError::internal(format!("keygen task: {e}")))?
        .map_err(AppError::internal)?;

    // UUID before encryption: it is the AES-GCM AAD.
    let id = Uuid::new_v4();
    let enc = crypto::encrypt_private_key(&state.cfg.master_key, &id, &generated.private_pem)
        .map_err(AppError::internal)?;

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "INSERT INTO ssl_keys \
           (id, name, algorithm, status, public_key_pem, private_key_enc, \
            fingerprint_sha256, created_by) \
         VALUES ($1, $2, $3, 'CREATED', $4, $5, $6, $7) \
         RETURNING *",
    )
    .bind(id)
    .bind(&name)
    .bind(&algorithm)
    .bind(&generated.public_pem)
    .bind(&enc)
    .bind(&generated.fingerprint_sha256)
    .bind(&actor.0)
    .fetch_one(&mut *tx)
    .await?;
    let key = map_key_row(&row).map_err(AppError::from)?;
    insert_audit(
        &mut *tx,
        id,
        "KEY_GENERATED",
        &actor.0,
        &state.cfg.backend_name,
        Some(json!({"algorithm": algorithm})),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(key.to_detail(Some(generated.private_pem)))).into_response())
}

#[derive(Deserialize)]
pub struct ListQuery {
    status: Option<String>,
}

pub async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Response, AppError> {
    let rows = match &query.status {
        Some(status) => {
            if !STATUSES.contains(&status.as_str()) {
                return Err(AppError::invalid_request(format!(
                    "status must be one of {}",
                    STATUSES.join(", ")
                )));
            }
            sqlx::query("SELECT * FROM ssl_keys WHERE status = $1 ORDER BY created_at DESC")
                .bind(status)
                .fetch_all(&state.pool)
                .await?
        }
        None => {
            sqlx::query("SELECT * FROM ssl_keys ORDER BY created_at DESC")
                .fetch_all(&state.pool)
                .await?
        }
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(map_key_row(row).map_err(AppError::from)?.to_summary());
    }
    let total = items.len();
    Ok((StatusCode::OK, Json(json!({"items": items, "total": total}))).into_response())
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    let key = fetch_key(&state.pool, id).await?;
    Ok((StatusCode::OK, Json(key.to_detail(None))).into_response())
}

pub async fn get_private_key(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    let key = fetch_key(&state.pool, id).await?;
    if key.status == "COMPROMISED" || key.status == "DELETED" {
        return Err(AppError::invalid_state(format!(
            "private key is not retrievable while status is {}",
            key.status
        )));
    }
    let pem = decrypt_for(&state, &key)?;
    insert_audit(
        &state.pool,
        id,
        "PRIVATE_KEY_ACCESSED",
        &actor.0,
        &state.cfg.backend_name,
        None,
    )
    .await?;
    Ok((StatusCode::OK, Json(json!({"id": key.id, "privateKeyPem": pem}))).into_response())
}

// ---------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CsrSubject {
    common_name: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CsrRequest {
    subject: Option<CsrSubject>,
    sans: Option<Vec<String>>,
}

fn build_dn(subject: &CsrSubject) -> Result<String, AppError> {
    let cn = subject
        .common_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::invalid_request("subject.commonName is required"))?;
    let mut parts = vec![format!("CN={}", csr::escape_dn_value(cn))];
    let optional = [
        ("O", &subject.organization),
        ("OU", &subject.organizational_unit),
        ("L", &subject.locality),
        ("ST", &subject.state),
        ("C", &subject.country),
    ];
    for (attr, value) in optional {
        if let Some(v) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            if attr == "C" && v.chars().count() != 2 {
                return Err(AppError::invalid_request(
                    "subject.country must be a 2-letter code",
                ));
            }
            parts.push(format!("{attr}={}", csr::escape_dn_value(v)));
        }
    }
    Ok(parts.join(","))
}

pub async fn create_csr(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    let key = fetch_key(&state.pool, id).await?;
    if key.status == "COMPROMISED" || key.status == "DELETED" {
        return Err(AppError::invalid_state(format!(
            "cannot issue a CSR while status is {}",
            key.status
        )));
    }

    let req: CsrRequest = parse_json(&body)?;
    let subject = req
        .subject
        .ok_or_else(|| AppError::invalid_request("subject is required"))?;
    let dn = build_dn(&subject)?;
    let sans: Vec<String> = req
        .sans
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .collect();
    if sans.iter().any(|s| s.is_empty()) {
        return Err(AppError::invalid_request("sans must be non-empty DNS names"));
    }

    let private_pem = decrypt_for(&state, &key)?;
    let csr_pem = csr::build_csr(&key.algorithm, &private_pem, &dn, &sans).map_err(|e| match e {
        csr::CsrError::BadInput(m) => AppError::invalid_request(m),
        csr::CsrError::Internal(m) => AppError::internal(m),
    })?;

    insert_audit(
        &state.pool,
        id,
        "CSR_ISSUED",
        &actor.0,
        &state.cfg.backend_name,
        Some(json!({"subject": dn, "sans": sans})),
    )
    .await?;
    Ok((StatusCode::OK, Json(json!({"csrPem": csr_pem}))).into_response())
}

// ---------------------------------------------------------------------------
// Certificate upload
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateUploadRequest {
    certificate_chain_pem: Option<String>,
}

pub async fn upload_certificate(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;

    // Step 1: key must exist (404) and be CREATED/READY_TO_PUBLISH (409).
    let key = fetch_key(&state.pool, id).await?;
    if key.status != "CREATED" && key.status != "READY_TO_PUBLISH" {
        return Err(AppError::invalid_state(format!(
            "certificate upload is not allowed while status is {}",
            key.status
        )));
    }

    let req: CertificateUploadRequest = parse_json(&body)?;
    let chain_pem = req
        .certificate_chain_pem
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| AppError::invalid_request("certificateChainPem is required"))?;

    let expected_spki =
        crypto::spki_der_from_pem(&key.public_key_pem).map_err(AppError::internal)?;

    let leaf = match chain::validate_chain(&chain_pem, &expected_spki) {
        Ok(leaf) => leaf,
        Err(ChainError::InvalidPem) => {
            // Step 2 failure: 400, no audit (SPEC audits steps 3-6 only).
            return Err(AppError::invalid_pem(ChainError::InvalidPem.message()));
        }
        Err(e) => {
            // Steps 3-6: 422 + CERTIFICATE_REJECTED audit.
            insert_audit(
                &state.pool,
                id,
                "CERTIFICATE_REJECTED",
                &actor.0,
                &state.cfg.backend_name,
                Some(json!({"reason": e.code()})),
            )
            .await?;
            return Err(AppError::unprocessable(e.code(), e.message()));
        }
    };

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "UPDATE ssl_keys SET \
            certificate_chain_pem = $2, cert_subject = $3, cert_issuer = $4, \
            cert_serial = $5, cert_not_before = $6, cert_not_after = $7, \
            status = 'READY_TO_PUBLISH', updated_at = now() \
         WHERE id = $1 AND status = ANY($8) \
         RETURNING *",
    )
    .bind(id)
    .bind(&chain_pem)
    .bind(&leaf.subject)
    .bind(&leaf.issuer)
    .bind(&leaf.serial)
    .bind(leaf.not_before)
    .bind(leaf.not_after)
    .bind(vec!["CREATED".to_string(), "READY_TO_PUBLISH".to_string()])
    .fetch_optional(&mut *tx)
    .await?;
    let row = match row {
        Some(row) => row,
        None => {
            return Err(AppError::invalid_state(
                "certificate upload is not allowed in the current status",
            ))
        }
    };
    let key = map_key_row(&row).map_err(AppError::from)?;
    insert_audit(
        &mut *tx,
        id,
        "CERTIFICATE_UPLOADED",
        &actor.0,
        &state.cfg.backend_name,
        Some(json!({"subject": leaf.subject, "serialNumber": leaf.serial})),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::OK, Json(key.to_detail(None))).into_response())
}

// ---------------------------------------------------------------------------
// Transitions: activate / compromise / delete
// ---------------------------------------------------------------------------

/// Atomic compare-and-set: zero updated rows with an existing key -> 409.
#[allow(clippy::too_many_arguments)]
async fn transition(
    state: &AppState,
    actor: &Actor,
    id: Uuid,
    update_sql: &str,
    allowed_from: &[&str],
    extra_bind: Option<Option<String>>,
    event_type: &str,
    detail: Option<Value>,
    conflict_message: &str,
) -> Result<Option<KeyRow>, AppError> {
    let allowed: Vec<String> = allowed_from.iter().map(|s| s.to_string()).collect();
    let mut tx = state.pool.begin().await?;
    let mut query = sqlx::query(update_sql).bind(id).bind(allowed);
    if let Some(extra) = extra_bind {
        query = query.bind(extra);
    }
    let row = query.fetch_optional(&mut *tx).await?;
    match row {
        Some(row) => {
            let key = map_key_row(&row).map_err(AppError::from)?;
            insert_audit(&mut *tx, id, event_type, &actor.0, &state.cfg.backend_name, detail)
                .await?;
            tx.commit().await?;
            Ok(Some(key))
        }
        None => {
            drop(tx);
            if key_exists(&state.pool, id).await? {
                Err(AppError::invalid_state(conflict_message))
            } else {
                Err(AppError::not_found())
            }
        }
    }
}

pub async fn activate_key(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    let key = transition(
        &state,
        &actor,
        id,
        "UPDATE ssl_keys SET status = 'ACTIVE', updated_at = now() \
         WHERE id = $1 AND status = ANY($2) RETURNING *",
        &["READY_TO_PUBLISH"],
        None,
        "ACTIVATED",
        None,
        "only READY_TO_PUBLISH keys can be activated",
    )
    .await?
    .expect("transition returns Err on failure");
    Ok((StatusCode::OK, Json(key.to_detail(None))).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompromiseRequest {
    reason: Option<String>,
}

pub async fn compromise_key(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    let reason: Option<String> = if body.is_empty() {
        None
    } else {
        parse_json::<CompromiseRequest>(&body)?.reason
    };
    let detail = reason.as_ref().map(|r| json!({"reason": r}));
    let key = transition(
        &state,
        &actor,
        id,
        "UPDATE ssl_keys SET status = 'COMPROMISED', compromised_reason = $3, \
         updated_at = now() WHERE id = $1 AND status = ANY($2) RETURNING *",
        &["CREATED", "READY_TO_PUBLISH", "ACTIVE"],
        Some(reason.clone()),
        "COMPROMISED",
        detail,
        "key cannot be compromised in its current status",
    )
    .await?
    .expect("transition returns Err on failure");
    Ok((StatusCode::OK, Json(key.to_detail(None))).into_response())
}

pub async fn delete_key(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    transition(
        &state,
        &actor,
        id,
        "UPDATE ssl_keys SET status = 'DELETED', private_key_enc = NULL, \
         updated_at = now() WHERE id = $1 AND status = ANY($2) RETURNING *",
        &["CREATED", "READY_TO_PUBLISH", "ACTIVE"],
        None,
        "DELETED",
        None,
        "COMPROMISED or DELETED keys cannot be deleted",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

pub async fn get_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_uuid(&id)?;
    if !key_exists(&state.pool, id).await? {
        return Err(AppError::not_found());
    }
    let rows = sqlx::query(
        "SELECT id, key_id, event_type, actor, backend, detail, occurred_at \
         FROM key_audit_events WHERE key_id = $1 ORDER BY occurred_at ASC, id ASC",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(AuditEventDto {
            id: row.try_get("id").map_err(AppError::from)?,
            key_id: row.try_get("key_id").map_err(AppError::from)?,
            event_type: row.try_get("event_type").map_err(AppError::from)?,
            actor: row.try_get("actor").map_err(AppError::from)?,
            backend: row.try_get("backend").map_err(AppError::from)?,
            detail: row.try_get("detail").map_err(AppError::from)?,
            occurred_at: row.try_get("occurred_at").map_err(AppError::from)?,
        });
    }
    Ok((StatusCode::OK, Json(json!({"items": items}))).into_response())
}
