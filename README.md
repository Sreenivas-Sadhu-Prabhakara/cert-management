# Certificate Management Service

Lifecycle custody for SSL/TLS key pairs — generation, CSR issuance,
cryptographically verified certificate-chain ingestion, activation,
compromise handling, soft deletion, and an append-only audit trail —
implemented **four times against one contract**:

| Implementation | Port | Directory |
|---|---|---|
| Java / Spring Boot | 8081 | `backend-java/` |
| Go | 8082 | `backend-go/` |
| Node.js | 8083 | `backend-node/` |
| Rust | 8084 | `backend-rust/` |

All four serve the same OpenAPI contract (`contracts/openapi.yaml`) over the
same PostgreSQL schema (`db/init/01-schema.sql`) and pass the same lifecycle
test suite (`scripts/smoke.sh`). A Flutter UI (`ui/`) works against any of
them.

**Read `docs/HOW-TO.md`** for the full how-to, API walkthrough, and the
design rationale / Zero Trust mapping. `SPEC.md` is the normative
implementation specification.

## Run it

```bash
docker compose up -d            # Postgres :5434, schema auto-applied
cp .env.example .env            # then fill secrets (or keep generated .env)

# any/all backends:
(cd backend-java && set -a; source ../.env; set +a; PORT=8081 BACKEND_NAME=java mvn spring-boot:run)
(cd backend-go   && set -a; source ../.env; set +a; PORT=8082 BACKEND_NAME=go   go run .)
(cd backend-node && set -a; source ../.env; set +a; PORT=8083 BACKEND_NAME=node npm start)
(cd backend-rust && set -a; source ../.env; set +a; PORT=8084 BACKEND_NAME=rust cargo run)

# UI:
(cd ui && flutter run -d chrome)

# verify any backend end-to-end (needs OpenSSL 3.x on PATH):
./scripts/smoke.sh 8082
```

## Layout

```
SPEC.md                  normative implementation spec (all backends)
contracts/openapi.yaml   API contract
db/init/01-schema.sql    shared schema (+ append-only audit trigger)
docker-compose.yml       Postgres 16 on :5434
scripts/smoke.sh         30-check lifecycle conformance suite
docs/HOW-TO.md           how-to + zero-trust design rationale
backend-{java,go,node,rust}/   the four implementations
ui/                      Flutter (Material 3) client + in-app documentation
```
