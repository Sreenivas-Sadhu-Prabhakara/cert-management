# Certificate Management Service — How-To & Design Rationale

This document explains **how to run and use** the service, and — more
importantly — **why it is designed the way it is** and how each decision maps
to Zero Trust principles. The same content is available inside the UI under
the Documentation page.

---

## 1. What this service is

A custody and lifecycle service for SSL/TLS key pairs. It owns the riskiest
object in any TLS deployment — the private key — from birth to destruction:

1. **Generate** an RSA (2048/3072/4096) or EC (P-256/P-384) key pair.
2. **Issue a CSR** (PKCS#10) signed by the stored private key, to be sent to
   your Certificate Authority out-of-band.
3. **Ingest the signed certificate chain** (PEM) the CA returns — but only
   after cryptographically proving it belongs to the stored key and that the
   chain itself is internally sound. Success transitions the key to
   `READY_TO_PUBLISH`.
4. **Activate** the key for use.
5. **Mark compromised** (terminal, frozen as evidence) or **delete**
   (soft — the key material is crypto-shredded, the record remains).

Every state change and every private-key access is written to an
**append-only audit table** in the same database transaction.

The service is implemented **four times — Java/Spring Boot, Go, Node.js, and
Rust — against one shared OpenAPI contract and one PostgreSQL schema**. Any
client can talk to any backend and observe identical behavior.

## 2. Quick start

```bash
# 1. Database (schema auto-applies on first start; listens on :5434)
docker compose up -d

# 2. Secrets — .env at the repo root (already generated; see .env.example)
#    JWT_SECRET, AUTH_CLIENT_ID/SECRET, MASTER_KEY_B64 (32-byte AES key)

# 3. Run any backend (each reads the same .env; all behave identically)
cd backend-java && set -a; source ../.env; set +a; PORT=8081 BACKEND_NAME=java mvn spring-boot:run
cd backend-go   && set -a; source ../.env; set +a; PORT=8082 BACKEND_NAME=go   go run .
cd backend-node && set -a; source ../.env; set +a; PORT=8083 BACKEND_NAME=node node src/server.js
cd backend-rust && set -a; source ../.env; set +a; PORT=8084 BACKEND_NAME=rust cargo run

# 4. UI (pick any backend from the connect screen)
cd ui && flutter run -d chrome

# 5. Prove a backend honors the full contract (30 lifecycle checks)
./scripts/smoke.sh 8082
```

## 3. API walkthrough (curl)

```bash
source .env
BASE=http://localhost:8082   # any backend

# Authenticate — every subsequent request carries this token
TOKEN=$(curl -s $BASE/api/v1/auth/token -H 'Content-Type: application/json' \
  -d "{\"clientId\":\"$AUTH_CLIENT_ID\",\"clientSecret\":\"$AUTH_CLIENT_SECRET\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
AUTH="Authorization: Bearer $TOKEN"

# Generate a key pair → status CREATED (the only response carrying privateKeyPem)
curl -s $BASE/api/v1/keys -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"web-frontend-2026","algorithm":"EC_P256"}'

# CSR for the CA
curl -s $BASE/api/v1/keys/$ID/csr -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"subject":{"commonName":"www.example.test","organization":"Example"},
       "sans":["www.example.test","example.test"]}'

# Upload the signed chain (leaf first) → verified → READY_TO_PUBLISH
curl -s $BASE/api/v1/keys/$ID/certificate -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"certificateChainPem\": $(python3 -c 'import json;print(json.dumps(open("chain.pem").read()))')}"

# Activate → ACTIVE
curl -s -X POST $BASE/api/v1/keys/$ID/activate -H "$AUTH"

# Lifecycle & inventory
curl -s "$BASE/api/v1/keys?status=ACTIVE" -H "$AUTH"      # list / filter
curl -s  $BASE/api/v1/keys/$ID            -H "$AUTH"      # detail (no private key)
curl -s  $BASE/api/v1/keys/$ID/private    -H "$AUTH"      # private key (audited!)
curl -s  $BASE/api/v1/keys/$ID/audit      -H "$AUTH"      # full history
curl -s -X POST $BASE/api/v1/keys/$ID/compromise -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"reason":"leaked in CI logs"}'
curl -s -X DELETE $BASE/api/v1/keys/$ID -H "$AUTH"        # soft delete
```

## 4. The key lifecycle — and why each rule exists

```
 generate            upload signed chain              activate
 ────────▶ CREATED ─────────────────────▶ READY_TO_PUBLISH ─────────▶ ACTIVE
              │                                  │                       │
              └───────────────── mark compromised ───────────────────────┘
                                       │
                                       ▼
                                  COMPROMISED   (terminal: no delete, no reuse)

 CREATED / READY_TO_PUBLISH / ACTIVE ──delete──▶ DELETED
 (terminal: row kept, private key crypto-shredded)
```

**Why a key isn't usable at birth.** A freshly generated key (`CREATED`) has
no proof that any CA vouches for it. Activation is only reachable *through*
`READY_TO_PUBLISH`, and `READY_TO_PUBLISH` is only reachable through
cryptographic verification of a signed chain. The state machine makes the
secure path the *only* path — trust is earned by verification, never assumed.

**Why certificate upload verifies three things.** When the CA returns a
signed chain, the service refuses to store it until:

1. *Public-key binding* — the leaf certificate's SubjectPublicKeyInfo is
   **byte-identical** to the stored public key. This kills an entire class of
   mix-ups and attacks where the right certificate for the wrong key (or a
   maliciously substituted certificate) gets bound to a private key it does
   not match. A served cert/key mismatch is an outage; a silently accepted
   wrong cert is worse.
2. *Chain integrity* — every certificate must be signed by its successor
   (signature verified, issuer/subject DNs linked), and a trailing self-signed
   root must verify its own signature. A chain that doesn't verify is not
   "probably fine" — it is rejected with `CHAIN_BROKEN` and the rejection
   itself is audited.
3. *Validity windows* — expired or not-yet-valid certificates are rejected
   (`CERT_NOT_VALID`) at the door rather than discovered in production.

**Why COMPROMISED is terminal and undeletable.** A compromised key's record
is *evidence*. Deleting it would let an attacker (or an embarrassed operator)
erase the trace of an incident. The state machine refuses: you can read it,
you can audit it, you cannot make it disappear.

**Why DELETE is soft.** `DELETE` sets `private_key_enc = NULL` — the
ciphertext is destroyed (crypto-shredding) so the key is unrecoverable even
with the master key — but the row, fingerprint, certificate metadata and
audit history remain. Inventory completeness is a security control: "we don't
know what keys we've had" is how expired-cert outages and orphaned-trust
incidents happen.

## 5. Why it needs to be this way — Zero Trust mapping

Zero Trust (NIST SP 800-207) abandons the idea of a trusted interior. Every
request is authenticated, every artifact verified, every action recorded, and
breach is assumed. Here is how each design decision maps:

| Design decision | Zero Trust principle it serves |
|---|---|
| Private keys are **born inside the service** and never accepted from outside; the only ingestion is *public* material (a certificate chain), and even that is cryptographically verified | *Never trust, always verify.* The provenance of every private key is known with certainty: it has never crossed a boundary unprotected, so there is nothing to take on faith. |
| **JWT on every request**, validated for signature, issuer and expiry; tokens are short-lived (15 min) | *No ambient trust.* Being on the network, or having called before, grants nothing. Identity is re-proven per request and expires quickly. |
| **AES-256-GCM encryption at rest**, with the record UUID as authenticated additional data (AAD) | *Assume breach.* A stolen database dump yields ciphertext. The AAD binds each ciphertext to its row, so an attacker with partial DB write access cannot swap one key's ciphertext into another's record without detection — decryption fails. |
| Private-key reads are a **dedicated, audited endpoint** (`/private`); list/detail responses never carry private material | *Least privilege + visibility.* The dangerous operation is separated, deliberate, and leaves a `PRIVATE_KEY_ACCESSED` event every single time. Casual or accidental exposure through a listing is structurally impossible. |
| **Append-only audit table**, enforced by a database trigger, written in the same transaction as the state change | *Assume breach → keep evidence.* Even the services themselves cannot rewrite history; a state change without its audit event cannot be committed. Forensics get a complete, ordered, tamper-resistant timeline. |
| **Atomic compare-and-set state transitions** (`UPDATE … WHERE status IN (…)`) | *Verify explicitly, even against yourself.* Two concurrent operators cannot race a key into an illegal state; the database is the single arbiter of the state machine. |
| **Soft delete with crypto-shredding** | *Inventory is a control.* The secret dies; the accountability does not. |
| **COMPROMISED is terminal** | *Incident evidence is immutable.* Containment must not enable cover-up. |
| **Four interchangeable implementations** of one contract and one schema | *Trust the contract, not the code.* No single runtime, dependency tree, or supply chain is load-bearing. Any implementation can be replaced overnight — the verified behavior (smoke-tested identically on all four) is the anchor, which is exactly how Zero Trust treats infrastructure: replaceable, continuously verified components rather than trusted pets. |
| Constant-time credential comparison; generic `401` for all auth failures; no stack traces in responses | *Don't leak oracle information* to unauthenticated callers. |

What this service deliberately does **not** do is also a Zero Trust choice:
it does not import foreign private keys ("bring your own key" would break
provenance), it does not return private keys in list responses, and it does
not let any caller — however privileged — mutate the audit trail.

## 6. Operational notes

- **Master key handling.** `MASTER_KEY_B64` is the root of confidentiality at
  rest. In production move it to a KMS/HSM and envelope-encrypt; the
  per-record AAD scheme carries over unchanged.
- **JWT secret rotation.** All four backends read the same `JWT_SECRET`;
  rotating it invalidates outstanding tokens (15-minute blast radius).
- **Which backend should I run?** Any. They pass the same 30-check lifecycle
  suite (`scripts/smoke.sh <port>`), produce identical fingerprints for the
  same key, and read/write the same rows interchangeably. Run one, or run all
  four behind a load balancer.
- **Renewal.** Re-upload is allowed while `READY_TO_PUBLISH`. Renewing an
  `ACTIVE` certificate is intentionally out of scope for v1: generate a new
  key (re-keying on renewal is best practice), walk it through the same
  verified lifecycle, then activate it and delete the old key.

## 7. Error vocabulary

Every non-2xx response is `{"error":{"code","message"}}`:

| Code | Meaning |
|---|---|
| `UNAUTHORIZED` | Missing/invalid credentials or token |
| `NOT_FOUND` | Unknown key id |
| `INVALID_REQUEST` | Malformed body, unknown algorithm, missing fields |
| `INVALID_PEM` | Certificate chain that does not parse |
| `KEY_MISMATCH` | Leaf certificate public key ≠ stored public key |
| `CHAIN_BROKEN` | Signature/DN linkage failure inside the chain |
| `CERT_NOT_VALID` | A certificate outside its validity window |
| `INVALID_STATE` | Operation illegal for the key's current status (see §4) |
| `INTERNAL` | Unexpected server error (details only in server logs) |
