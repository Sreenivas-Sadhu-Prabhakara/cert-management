# Certificate Management Service — Implementation Specification

Every backend (Java/Spring Boot, Go, Node.js, Rust) implements **exactly** this
specification against **one shared PostgreSQL schema** (`db/init/01-schema.sql`).
The four services are interchangeable: any client may talk to any backend and
observe identical behavior, status codes, and JSON shapes.

Ports: Java **8081**, Go **8082**, Node **8083**, Rust **8084**.

---

## 1. Environment variables (identical for all backends)

| Variable             | Meaning                                              | Default          |
|----------------------|------------------------------------------------------|------------------|
| `PORT`               | HTTP listen port                                     | per-backend above|
| `PGHOST`             | Postgres host                                        | `localhost`      |
| `PGPORT`             | Postgres port                                        | `5434`           |
| `PGDATABASE`         | Database name                                        | `certmgr`        |
| `PGUSER`             | DB user                                              | `certmgr`        |
| `PGPASSWORD`         | DB password                                          | `certmgr`        |
| `JWT_SECRET`         | HMAC-SHA256 signing secret (≥32 bytes)               | — (required)     |
| `JWT_ISSUER`         | `iss` claim value                                    | `cert-mgmt`      |
| `JWT_TTL_SECONDS`    | Token lifetime                                       | `900`            |
| `AUTH_CLIENT_ID`     | Accepted client id for the token endpoint            | `admin`          |
| `AUTH_CLIENT_SECRET` | Accepted client secret                               | — (required)     |
| `MASTER_KEY_B64`     | base64 of exactly 32 random bytes (AES-256 key)      | — (required)     |
| `BACKEND_NAME`       | `java` \| `go` \| `node` \| `rust` (audit attribution)| per-backend      |

All backends load `../.env` style values from the process environment only —
do NOT bundle a dotenv loader requirement; the runner exports the variables
(scripts use `set -a; source .env; set +a`).

## 2. Authentication

- `POST /api/v1/auth/token` body `{"clientId": "...", "clientSecret": "..."}`
  - On match with `AUTH_CLIENT_ID`/`AUTH_CLIENT_SECRET` (constant-time compare):
    `200 {"accessToken": "<jwt>", "tokenType": "Bearer", "expiresIn": <JWT_TTL_SECONDS>}`
  - Otherwise `401` with error code `UNAUTHORIZED`.
- JWT: **HS256**, claims `iss=JWT_ISSUER`, `sub=<clientId>`, `iat`, `exp=iat+TTL`,
  `scope="keys:admin"`.
- Every other endpoint except `GET /health` requires `Authorization: Bearer <jwt>`;
  validate signature, `iss`, and `exp`. Failure → `401 UNAUTHORIZED`.

## 3. CORS (required — the Flutter web UI calls the APIs cross-origin)

All endpoints: respond to `OPTIONS` preflight with `204` and send on every response:
`Access-Control-Allow-Origin: *`,
`Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS`,
`Access-Control-Allow-Headers: Authorization, Content-Type`.

## 4. Cryptography conventions

### 4.1 Key generation
Algorithms (request enum → meaning):
`RSA_2048`, `RSA_3072`, `RSA_4096` (RSA, e=65537), `EC_P256` (P-256/secp256r1),
`EC_P384` (P-384/secp384r1).

- Private key PEM: **PKCS#8** — `-----BEGIN PRIVATE KEY-----`.
- Public key PEM: **SPKI/X.509** — `-----BEGIN PUBLIC KEY-----`.
- `fingerprint_sha256`: lowercase hex of SHA-256 over the **DER-encoded SPKI**
  (i.e. the bytes inside the public-key PEM). All four backends MUST produce the
  identical fingerprint for the same key.

### 4.2 Private key encryption at rest (must be byte-compatible across backends)
- Cipher: **AES-256-GCM**. Key = base64-decode(`MASTER_KEY_B64`) (32 bytes).
- Nonce: 12 random bytes, fresh per encryption.
- AAD: UTF-8 bytes of the key's **lowercase UUID string** (binds ciphertext to its row).
- Plaintext: the PKCS#8 private-key PEM string (UTF-8).
- Stored column value: `base64( nonce || ciphertext || tag )` — 16-byte GCM tag
  appended to the ciphertext (Java/Go/Rust APIs already do this; Node must concat
  `cipher.getAuthTag()`).
- Because AAD includes the UUID, generate the UUID **before** encrypting; insert with
  an explicit `id`.

### 4.3 CSR generation (PKCS#10)
- Signature algorithm: RSA keys → SHA256withRSA; EC_P256 → SHA256withECDSA;
  EC_P384 → SHA384withECDSA.
- Subject from request (`commonName` required; `organization`, `organizationalUnit`,
  `country`, `state`, `locality` optional). Optional `sans`: list of DNS names →
  SubjectAlternativeName extension.
- Output: PEM `-----BEGIN CERTIFICATE REQUEST-----`. CSRs are not stored; the audit
  event records the subject.

### 4.4 Certificate-chain validation (`POST /keys/{id}/certificate`)
Input: `{"certificateChainPem": "..."}` — one or more concatenated
`-----BEGIN CERTIFICATE-----` blocks, **leaf first**, then intermediates, optionally
ending in a self-signed root.

Validate in this exact order (first failure wins):
1. Key must exist and status ∈ {CREATED, READY_TO_PUBLISH} → else `409 INVALID_STATE`
   (missing key → `404 NOT_FOUND`).
2. Parse all PEM blocks as X.509; at least one → else `400 INVALID_PEM`.
3. **Public-key binding:** leaf certificate SPKI DER must equal the stored public key
   SPKI DER byte-for-byte → else `422 KEY_MISMATCH`.
4. **Chain integrity:** for each adjacent pair (cert[i], cert[i+1]):
   cert[i].issuer DN == cert[i+1].subject DN AND cert[i]'s signature verifies under
   cert[i+1]'s public key → else `422 CHAIN_BROKEN`.
5. If the last certificate is self-signed (subject == issuer), its self-signature must
   verify → else `422 CHAIN_BROKEN`. (A chain ending at an intermediate is accepted —
   roots are commonly omitted.)
6. **Validity window:** current time within `[notBefore, notAfter]` of every
   certificate → else `422 CERT_NOT_VALID`.

On success: store the chain PEM verbatim, extract from the **leaf**:
`cert_subject` (RFC 2253-style DN string), `cert_issuer`, `cert_serial` (decimal or
lowercase hex string — use the platform's canonical decimal where available),
`cert_not_before`, `cert_not_after`; set status → `READY_TO_PUBLISH`; audit
`CERTIFICATE_UPLOADED`. On any validation failure (steps 3–6) also write audit event
`CERTIFICATE_REJECTED` with `detail.reason`.

## 5. Key lifecycle (state machine)

```
            generate                 upload chain               activate
   (none) ───────────▶ CREATED ───────────────▶ READY_TO_PUBLISH ─────────▶ ACTIVE
                          │   ▲ (re-upload allowed while READY_TO_PUBLISH)    │
                          │                                                   │
                          ├──────────────── compromise ──────────────────────┤
                          ▼                                                   ▼
                      COMPROMISED  (terminal — cannot delete, cannot reactivate)
                          
   CREATED | READY_TO_PUBLISH | ACTIVE ── delete ──▶ DELETED
   (terminal; row kept, private_key_enc set to NULL = crypto-shredded)
```

Allowed operations by status:

| Operation              | CREATED | READY_TO_PUBLISH | ACTIVE | COMPROMISED | DELETED |
|------------------------|---------|------------------|--------|-------------|---------|
| GET (single/list)      | ✓       | ✓                | ✓      | ✓           | ✓       |
| CSR generation         | ✓       | ✓                | ✓      | 409         | 409     |
| Certificate upload     | ✓       | ✓                | 409    | 409         | 409     |
| Activate               | 409     | ✓                | 409    | 409         | 409     |
| Compromise             | ✓       | ✓                | ✓      | 409         | 409     |
| Delete (soft)          | ✓       | ✓                | ✓      | 409         | 409     |
| Retrieve private key   | ✓       | ✓                | ✓      | 409         | 409     |

All transitions MUST be atomic compare-and-set:
`UPDATE ssl_keys SET ... WHERE id = $1 AND status IN (...) RETURNING *` — zero rows
with an existing id ⇒ `409 INVALID_STATE`.

## 6. Endpoints (all JSON; base path `/api/v1`)

| Method & path                        | Auth | Success | Notes |
|--------------------------------------|------|---------|-------|
| `GET /health`                        | none | `200 {"status":"up","backend":"<name>"}` | also checks DB (`SELECT 1`); degraded → `503` |
| `POST /api/v1/auth/token`            | none | `200` token payload | §2 |
| `POST /api/v1/keys`                  | JWT  | `201` KeyDetail **including `privateKeyPem`** (returned here and via the private endpoint) | body `{"name": "...", "algorithm": "RSA_2048"}`; audit `KEY_GENERATED` |
| `GET /api/v1/keys`                   | JWT  | `200 {"items":[KeySummary], "total":n}` | optional `?status=ACTIVE` filter; ordered `created_at DESC`. Excludes nothing — DELETED rows appear (transparency). |
| `GET /api/v1/keys/{id}`              | JWT  | `200` KeyDetail (never includes private key) | |
| `GET /api/v1/keys/{id}/private`      | JWT  | `200 {"id":"...","privateKeyPem":"..."}` | audit `PRIVATE_KEY_ACCESSED`; 409 if COMPROMISED/DELETED |
| `POST /api/v1/keys/{id}/csr`         | JWT  | `200 {"csrPem":"..."}` | body §4.3; audit `CSR_ISSUED` |
| `POST /api/v1/keys/{id}/certificate` | JWT  | `200` KeyDetail | §4.4; audit `CERTIFICATE_UPLOADED` / `CERTIFICATE_REJECTED` |
| `POST /api/v1/keys/{id}/activate`    | JWT  | `200` KeyDetail | audit `ACTIVATED` |
| `POST /api/v1/keys/{id}/compromise`  | JWT  | `200` KeyDetail | optional body `{"reason":"..."}`; audit `COMPROMISED` |
| `DELETE /api/v1/keys/{id}`           | JWT  | `204` empty | wipes `private_key_enc`; audit `DELETED` |
| `GET /api/v1/keys/{id}/audit`        | JWT  | `200 {"items":[AuditEvent]}` | ordered `occurred_at ASC` |

Unknown id (malformed UUID too) → `404 NOT_FOUND`. Validation problems (bad enum,
missing name/commonName, malformed body) → `400 INVALID_REQUEST` (or `INVALID_PEM`).
Unexpected failure → `500 INTERNAL` (no stack traces in responses).

## 7. JSON shapes (camelCase; timestamps ISO-8601 UTC, e.g. `2026-06-12T08:30:00Z`)

```jsonc
// KeySummary (list items — no PEM material)
{ "id": "uuid", "name": "...", "algorithm": "RSA_2048", "status": "CREATED",
  "fingerprintSha256": "hex", "hasCertificate": false,
  "certNotAfter": null, "createdAt": "...", "updatedAt": "..." }

// KeyDetail (superset of KeySummary, per the OpenAPI allOf composition)
{ "id": "uuid", "name": "...", "algorithm": "...", "status": "...",
  "publicKeyPem": "...", "fingerprintSha256": "hex",
  "hasCertificate": false, "certNotAfter": null,
  "certificateChainPem": null | "...",
  "certificate": null | { "subject": "...", "issuer": "...", "serialNumber": "...",
                          "notBefore": "...", "notAfter": "..." },
  "compromisedReason": null | "...",
  "createdBy": "admin", "createdAt": "...", "updatedAt": "...",
  "privateKeyPem": "..."   // ONLY in the POST /keys (201) response
}

// AuditEvent
{ "id": 1, "keyId": "uuid", "eventType": "KEY_GENERATED", "actor": "admin",
  "backend": "go", "detail": { ... } | null, "occurredAt": "..." }

// Error (every non-2xx)
{ "error": { "code": "INVALID_STATE", "message": "human-readable explanation" } }
```

Error codes: `UNAUTHORIZED`, `NOT_FOUND`, `INVALID_REQUEST`, `INVALID_PEM`,
`KEY_MISMATCH`, `CHAIN_BROKEN`, `CERT_NOT_VALID`, `INVALID_STATE`, `INTERNAL`.

## 8. Audit events

Append-only table `key_audit_events` (DB trigger forbids UPDATE/DELETE).
`actor` = JWT `sub`. `backend` = `BACKEND_NAME`. Event types:
`KEY_GENERATED`, `CSR_ISSUED`, `CERTIFICATE_UPLOADED`, `CERTIFICATE_REJECTED`,
`ACTIVATED`, `COMPROMISED`, `DELETED`, `PRIVATE_KEY_ACCESSED`.
`detail` examples: KEY_GENERATED `{"algorithm":"EC_P256"}`; CSR_ISSUED
`{"subject":"CN=example.test","sans":["example.test"]}`; CERTIFICATE_REJECTED
`{"reason":"KEY_MISMATCH"}`; COMPROMISED `{"reason":"..."}`.
Audit writes happen in the same DB transaction as the state change.

## 9. Verification

`scripts/smoke.sh <port>` runs the full lifecycle against a backend using a
throwaway OpenSSL CA (generate → CSR → sign → upload chain → activate → private
retrieval → audit → compromise/delete + negative cases). A backend is done only
when `smoke.sh` passes cleanly.
