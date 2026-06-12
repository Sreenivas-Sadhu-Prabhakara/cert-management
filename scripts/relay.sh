#!/usr/bin/env bash
# Cross-backend interchangeability proof: one key, four implementations.
#   token: java | generate: java | csr: go | chain upload: node | activate: rust
#   private-key read: rust (decrypts java's ciphertext) | delete: go
# Then GET the same key from all four backends and diff the normalized JSON.
# Requires all four backends running (8081-8084). Usage: ./scripts/relay.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
set -a; source "${ROOT_DIR}/.env"; set +a
OPENSSL="${OPENSSL:-openssl}"
"$OPENSSL" version | grep -q '^OpenSSL 3' || { echo "need OpenSSL 3.x on PATH"; exit 1; }

JAVA=http://localhost:8081 GO=http://localhost:8082
NODE=http://localhost:8083 RUST=http://localhost:8084
WORK="$(mktemp -d)"; trap 'rm -rf "${WORK}"' EXIT

say() { printf '\033[36m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m   ok: %s\033[0m\n' "$*"; }
die() { printf '\033[31m   FAIL: %s\033[0m\n' "$*"; exit 1; }
jget(){ python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

say "token issued by JAVA, honored by all four"
TOKEN=$(curl -sf -X POST $JAVA/api/v1/auth/token -H 'Content-Type: application/json' \
  -d "{\"clientId\":\"${AUTH_CLIENT_ID}\",\"clientSecret\":\"${AUTH_CLIENT_SECRET}\"}" | jget "['accessToken']")
AUTH="Authorization: Bearer ${TOKEN}"
for url in $GO $NODE $RUST; do
  curl -sf "$url/api/v1/keys" -H "$AUTH" >/dev/null || die "java-issued JWT rejected by $url"
done
ok "JWT interop"

say "generate on JAVA"
KEY=$(curl -sf -X POST $JAVA/api/v1/keys -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"name\":\"relay-$$\",\"algorithm\":\"EC_P256\"}")
ID=$(echo "$KEY" | jget "['id']")
ok "key ${ID} (CREATED)"

say "CSR from GO (go decrypts java's AES-GCM ciphertext)"
curl -sf -X POST $GO/api/v1/keys/$ID/csr -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"subject":{"commonName":"relay.example.test","organization":"Relay"},"sans":["relay.example.test"]}' \
  | jget "['csrPem']" > "${WORK}/relay.csr"
"$OPENSSL" req -in "${WORK}/relay.csr" -noout -verify >/dev/null 2>&1 || die "CSR invalid"
ok "CSR verified by openssl"

say "sign with throwaway CA, upload chain to NODE"
"$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${WORK}/ca.key" -out "${WORK}/ca.crt" -days 7 -subj "/CN=Relay CA" >/dev/null 2>&1
"$OPENSSL" x509 -req -in "${WORK}/relay.csr" -CA "${WORK}/ca.crt" -CAkey "${WORK}/ca.key" \
  -CAcreateserial -days 5 -copy_extensions copy -out "${WORK}/relay.crt" >/dev/null 2>&1
CHAIN=$(cat "${WORK}/relay.crt" "${WORK}/ca.crt" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))')
STATUS=$(curl -sf -X POST $NODE/api/v1/keys/$ID/certificate -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"certificateChainPem\":${CHAIN}}" | jget "['status']")
[[ "$STATUS" == "READY_TO_PUBLISH" ]] || die "expected READY_TO_PUBLISH, got $STATUS"
ok "node verified chain against java-stored public key -> READY_TO_PUBLISH"

say "activate on RUST"
STATUS=$(curl -sf -X POST $RUST/api/v1/keys/$ID/activate -H "$AUTH" | jget "['status']")
[[ "$STATUS" == "ACTIVE" ]] || die "expected ACTIVE, got $STATUS"
ok "ACTIVE"

say "private key from RUST (cross-implementation decrypt)"
curl -sf $RUST/api/v1/keys/$ID/private -H "$AUTH" | jget "['privateKeyPem']" | grep -q 'BEGIN PRIVATE KEY' \
  || die "rust could not decrypt java-encrypted private key"
ok "rust decrypted java's ciphertext"

say "response parity: GET the key from all four, diff normalized JSON"
for b in JAVA:$JAVA GO:$GO NODE:$NODE RUST:$RUST; do
  name="${b%%:*}"; url="${b#*:}"
  curl -sf "$url/api/v1/keys/$ID" -H "$AUTH" > "${WORK}/${name}.json"
done
python3 - "$WORK" <<'EOF'
import json, sys, re, pathlib
work = pathlib.Path(sys.argv[1])
TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
def norm(v):
    if isinstance(v, dict):  return {k: norm(x) for k, x in sorted(v.items())}
    if isinstance(v, list):  return [norm(x) for x in v]
    if isinstance(v, str) and TS.match(v):  # second precision; renderers differ in sub-seconds
        return TS.match(v).group(0) + 'Z'
    return v
docs = {p.stem: norm(json.loads(p.read_text())) for p in sorted(work.glob('*.json'))}
ref_name, ref = next(iter(docs.items()))
bad = False
for name, doc in docs.items():
    if doc != ref:
        bad = True
        for k in sorted(set(ref) | set(doc)):
            if ref.get(k) != doc.get(k):
                print(f"   DIFF {ref_name} vs {name} on '{k}':\n      {ref.get(k)!r}\n      {doc.get(k)!r}")
sys.exit(1 if bad else 0)
EOF
ok "all four backends return identical normalized JSON for the same key"

say "audit trail spans all four implementations"
AUDIT=$(curl -sf $JAVA/api/v1/keys/$ID/audit -H "$AUTH")
for b in java go node rust; do
  echo "$AUDIT" | grep -q "\"backend\":[[:space:]]*\"$b\"" || die "audit missing backend tag: $b"
done
ok "events recorded by java, go, node and rust on one key"

say "soft delete via GO"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE $GO/api/v1/keys/$ID -H "$AUTH")
[[ "$code" == "204" ]] || die "delete failed: $code"
ok "deleted (evidence row retained)"

printf '\n\033[32mRELAY PASSED — one key, four interchangeable implementations\033[0m\n'
