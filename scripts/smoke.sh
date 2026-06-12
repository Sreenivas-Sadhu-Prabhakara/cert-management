#!/usr/bin/env bash
# Full-lifecycle smoke test for any backend: ./scripts/smoke.sh <port>
# Creates a throwaway OpenSSL CA, then drives: token -> generate -> CSR ->
# sign -> upload chain -> activate -> private retrieval -> audit -> negative
# cases -> compromise -> delete. Exits non-zero on first failure.
set -euo pipefail

PORT="${1:?usage: smoke.sh <port>}"
BASE="http://localhost:${PORT}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
set -a; source "${ROOT_DIR}/.env"; set +a

# needs OpenSSL 3.x (-copy_extensions); macOS /usr/bin/openssl is LibreSSL
OPENSSL="${OPENSSL:-openssl}"
"$OPENSSL" version | grep -q '^OpenSSL 3' || { echo "need OpenSSL 3.x on PATH (or set OPENSSL=...)"; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
PASS=0; FAIL=0

say()  { printf '\033[36m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '\033[32m   ok: %s\033[0m\n' "$*"; }
die()  { printf '\033[31m   FAIL: %s\033[0m\n' "$*"; exit 1; }

# jq-free JSON field extraction (string values / simple fields)
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" ; }

req() { # req METHOD PATH EXPECTED_STATUS [JSON_BODY] -> body on stdout, status checked
  local method="$1" path="$2" expect="$3" body="${4:-}"
  local args=(-s -o "${WORK}/resp.json" -w '%{http_code}' -X "$method" "${BASE}${path}" \
              -H "Authorization: Bearer ${TOKEN:-}" -H 'Content-Type: application/json')
  [[ -n "$body" ]] && args+=(-d "$body")
  local status
  status=$(curl "${args[@]}")
  [[ "$status" == "$expect" ]] || { cat "${WORK}/resp.json"; die "$method $path -> $status (expected $expect)"; }
  cat "${WORK}/resp.json"
}

say "health"
curl -sf "${BASE}/health" >/dev/null || die "backend on :${PORT} not reachable"
ok "GET /health"

say "auth"
status=$(curl -s -o "${WORK}/resp.json" -w '%{http_code}' -X POST "${BASE}/api/v1/auth/token" \
  -H 'Content-Type: application/json' -d "{\"clientId\":\"wrong\",\"clientSecret\":\"wrong\"}")
[[ "$status" == "401" ]] || die "bad credentials should 401, got $status"
ok "bad credentials -> 401"
TOKEN=$(curl -sf -X POST "${BASE}/api/v1/auth/token" -H 'Content-Type: application/json' \
  -d "{\"clientId\":\"${AUTH_CLIENT_ID}\",\"clientSecret\":\"${AUTH_CLIENT_SECRET}\"}" | jget "['accessToken']")
[[ -n "$TOKEN" ]] || die "no accessToken"
ok "token issued"
status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/keys")
[[ "$status" == "401" ]] || die "missing token should 401, got $status"
ok "missing token -> 401"

say "throwaway CA"
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${WORK}/ca.key" -out "${WORK}/ca.crt" -days 7 \
  -subj "/CN=Smoke Test CA/O=SmokeTest" >/dev/null 2>&1
ok "CA created"

run_lifecycle() { # run_lifecycle ALGO
  local algo="$1"
  say "lifecycle for ${algo}"
  local key; key=$(req POST /api/v1/keys 201 "{\"name\":\"smoke-${algo}-$$-${RANDOM}\",\"algorithm\":\"${algo}\"}")
  local id;  id=$(echo "$key" | jget "['id']")
  echo "$key" | jget "['privateKeyPem']" | grep -q 'BEGIN PRIVATE KEY' || die "creation response missing privateKeyPem"
  [[ "$(echo "$key" | jget "['status']")" == "CREATED" ]] || die "new key not CREATED"
  ok "generated ${id}"

  # activate before cert upload must fail
  req POST "/api/v1/keys/${id}/activate" 409 >/dev/null
  ok "activate before certificate -> 409"

  local csr; csr=$(req POST "/api/v1/keys/${id}/csr" 200 \
    '{"subject":{"commonName":"smoke.example.test","organization":"SmokeTest"},"sans":["smoke.example.test","alt.example.test"]}')
  echo "$csr" | jget "['csrPem']" > "${WORK}/${id}.csr"
  grep -q 'BEGIN CERTIFICATE REQUEST' "${WORK}/${id}.csr" || die "no CSR PEM"
  "$OPENSSL" req -in "${WORK}/${id}.csr" -noout -verify >/dev/null 2>&1 || die "CSR does not verify under openssl"
  ok "CSR issued and openssl-verified"

  "$OPENSSL" x509 -req -in "${WORK}/${id}.csr" -CA "${WORK}/ca.crt" -CAkey "${WORK}/ca.key" \
    -CAcreateserial -days 5 -copy_extensions copy -out "${WORK}/${id}.crt" >/dev/null 2>&1
  local chain; chain=$(cat "${WORK}/${id}.crt" "${WORK}/ca.crt" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')

  # wrong-key chain must be rejected as KEY_MISMATCH (sign a different key's CSR)
  "$OPENSSL" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "${WORK}/other.key" \
    -out "${WORK}/other.csr" -subj "/CN=other.example.test" >/dev/null 2>&1
  "$OPENSSL" x509 -req -in "${WORK}/other.csr" -CA "${WORK}/ca.crt" -CAkey "${WORK}/ca.key" \
    -CAcreateserial -days 5 -out "${WORK}/other.crt" >/dev/null 2>&1
  local wrong; wrong=$(cat "${WORK}/other.crt" "${WORK}/ca.crt" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
  local resp; resp=$(req POST "/api/v1/keys/${id}/certificate" 422 "{\"certificateChainPem\":${wrong}}")
  [[ "$(echo "$resp" | jget "['error']['code']")" == "KEY_MISMATCH" ]] || die "expected KEY_MISMATCH"
  ok "foreign certificate -> 422 KEY_MISMATCH"

  # broken chain (leaf + unrelated 'intermediate' that didn't sign it)
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "${WORK}/bogus.key" \
    -out "${WORK}/bogus.crt" -days 5 -subj "/CN=Smoke Test CA/O=SmokeTest" >/dev/null 2>&1
  local broken; broken=$(cat "${WORK}/${id}.crt" "${WORK}/bogus.crt" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
  resp=$(req POST "/api/v1/keys/${id}/certificate" 422 "{\"certificateChainPem\":${broken}}")
  [[ "$(echo "$resp" | jget "['error']['code']")" == "CHAIN_BROKEN" ]] || die "expected CHAIN_BROKEN"
  ok "broken chain -> 422 CHAIN_BROKEN"

  resp=$(req POST "/api/v1/keys/${id}/certificate" 200 "{\"certificateChainPem\":${chain}}")
  [[ "$(echo "$resp" | jget "['status']")" == "READY_TO_PUBLISH" ]] || die "not READY_TO_PUBLISH after upload"
  echo "$resp" | jget "['certificate']['subject']" | grep -qi 'smoke.example.test' || die "leaf subject not extracted"
  ok "valid chain accepted -> READY_TO_PUBLISH"

  resp=$(req POST "/api/v1/keys/${id}/activate" 200)
  [[ "$(echo "$resp" | jget "['status']")" == "ACTIVE" ]] || die "not ACTIVE"
  ok "activated"

  resp=$(req GET "/api/v1/keys/${id}/private" 200)
  echo "$resp" | jget "['privateKeyPem']" | grep -q 'BEGIN PRIVATE KEY' || die "private retrieval failed"
  ok "private key retrieved (audited)"

  resp=$(req GET "/api/v1/keys/${id}" 200)
  python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'privateKeyPem' not in d else 1)" <<<"$resp" \
    || die "GET /keys/{id} must not include privateKeyPem"
  ok "GET detail excludes private key"

  resp=$(req GET "/api/v1/keys/${id}/audit" 200)
  for ev in KEY_GENERATED CSR_ISSUED CERTIFICATE_REJECTED CERTIFICATE_UPLOADED ACTIVATED PRIVATE_KEY_ACCESSED; do
    echo "$resp" | grep -q "$ev" || die "audit missing ${ev}"
  done
  ok "audit trail complete"

  resp=$(req POST "/api/v1/keys/${id}/compromise" 200 '{"reason":"smoke test"}')
  [[ "$(echo "$resp" | jget "['status']")" == "COMPROMISED" ]] || die "not COMPROMISED"
  req GET "/api/v1/keys/${id}/private" 409 >/dev/null
  req DELETE "/api/v1/keys/${id}" 409 >/dev/null
  ok "compromised key: private blocked, delete blocked"

  # separate key for the delete path
  key=$(req POST /api/v1/keys 201 "{\"name\":\"smoke-del-$$-${RANDOM}\",\"algorithm\":\"EC_P256\"}")
  id=$(echo "$key" | jget "['id']")
  req DELETE "/api/v1/keys/${id}" 204 >/dev/null
  resp=$(req GET "/api/v1/keys/${id}" 200)
  [[ "$(echo "$resp" | jget "['status']")" == "DELETED" ]] || die "not DELETED"
  req GET "/api/v1/keys/${id}/private" 409 >/dev/null
  ok "soft delete: row kept, key material gone"
}

run_lifecycle "EC_P256"
run_lifecycle "RSA_2048"

say "list"
resp=$(req GET "/api/v1/keys?status=COMPROMISED" 200)
echo "$resp" | grep -q 'COMPROMISED' || die "status filter broken"
ok "list + status filter"

printf '\n\033[32mSMOKE PASSED (%s checks) on port %s\033[0m\n' "$PASS" "$PORT"
