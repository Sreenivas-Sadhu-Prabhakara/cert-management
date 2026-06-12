mod auth;
mod chain;
mod crypto;
mod csr;
mod error;
mod handlers;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

pub struct Config {
    pub backend_name: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_ttl_seconds: i64,
    pub auth_client_id: String,
    pub auth_client_secret: String,
    pub master_key: [u8; 32],
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cfg: Arc<Config>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_required(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("missing required environment variable {name}");
            std::process::exit(1);
        }
    }
}

fn load_config() -> Config {
    let master_b64 = env_required("MASTER_KEY_B64");
    let master_raw = B64.decode(master_b64.trim()).unwrap_or_else(|e| {
        eprintln!("MASTER_KEY_B64 is not valid base64: {e}");
        std::process::exit(1);
    });
    let master_key: [u8; 32] = master_raw.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("MASTER_KEY_B64 must decode to exactly 32 bytes (got {})", v.len());
        std::process::exit(1);
    });
    Config {
        backend_name: env_or("BACKEND_NAME", "rust"),
        jwt_secret: env_required("JWT_SECRET"),
        jwt_issuer: env_or("JWT_ISSUER", "cert-mgmt"),
        jwt_ttl_seconds: env_or("JWT_TTL_SECONDS", "900").parse().unwrap_or_else(|_| {
            eprintln!("JWT_TTL_SECONDS must be an integer");
            std::process::exit(1);
        }),
        auth_client_id: env_or("AUTH_CLIENT_ID", "admin"),
        auth_client_secret: env_required("AUTH_CLIENT_SECRET"),
        master_key,
    }
}

/// Hand-rolled CORS per SPEC §3: OPTIONS preflight -> 204, headers on every response.
async fn cors_middleware(req: Request, next: Next) -> Response {
    let preflight = req.method() == Method::OPTIONS;
    let mut response = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Authorization, Content-Type"),
    );
    response
}

#[tokio::main]
async fn main() {
    let cfg = Arc::new(load_config());
    let port: u16 = env_or("PORT", "8084").parse().unwrap_or_else(|_| {
        eprintln!("PORT must be a number");
        std::process::exit(1);
    });

    let pg = PgConnectOptions::new()
        .host(&env_or("PGHOST", "localhost"))
        .port(env_or("PGPORT", "5434").parse().unwrap_or(5434))
        .database(&env_or("PGDATABASE", "certmgr"))
        .username(&env_or("PGUSER", "certmgr"))
        .password(&env_or("PGPASSWORD", "certmgr"));
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy_with(pg);

    let state = AppState { pool, cfg: cfg.clone() };

    let protected = Router::new()
        .route("/api/v1/keys", post(handlers::create_key).get(handlers::list_keys))
        .route("/api/v1/keys/{id}", get(handlers::get_key).delete(handlers::delete_key))
        .route("/api/v1/keys/{id}/private", get(handlers::get_private_key))
        .route("/api/v1/keys/{id}/csr", post(handlers::create_csr))
        .route("/api/v1/keys/{id}/certificate", post(handlers::upload_certificate))
        .route("/api/v1/keys/{id}/activate", post(handlers::activate_key))
        .route("/api/v1/keys/{id}/compromise", post(handlers::compromise_key))
        .route("/api/v1/keys/{id}/audit", get(handlers::get_audit))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/auth/token", post(handlers::token))
        .merge(protected)
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot bind :{port}: {e}");
            std::process::exit(1);
        });
    println!("cert-mgmt backend={} listening on :{port}", cfg.backend_name);
    axum::serve(listener, app).await.expect("server error");
}
