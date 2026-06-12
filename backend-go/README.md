# backend-go — Certificate Management Service (Go, port 8082)

Build: `go build -o certmgr-go .` (Go 1.25+, module `certmgr-go`; stdlib crypto + pgx/jwt/uuid).

Run: `set -a; source ../.env; set +a; export PORT=8082 BACKEND_NAME=go; ./certmgr-go` (or `go run .`).

Verify: `../scripts/smoke.sh 8082` (needs OpenSSL 3.x on PATH) — should print `SMOKE PASSED`.
