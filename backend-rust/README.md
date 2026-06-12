# cert-management — Rust backend (port 8084)

Axum + sqlx implementation of `../SPEC.md` against the shared Postgres (localhost:5434).

Build: `source "$HOME/.cargo/env" && cargo build --release`

Run: `set -a; source ../.env; set +a; export PORT=8084 BACKEND_NAME=rust; ./target/release/cert-mgmt-rust`

Verify: `../scripts/smoke.sh 8084` (needs OpenSSL 3.x on PATH).
