-- Certificate Management Service — shared schema (all four backends use this).
-- Applied automatically by the postgres container on first start.

CREATE TABLE ssl_keys (
    id                    UUID PRIMARY KEY,
    name                  TEXT        NOT NULL,
    algorithm             TEXT        NOT NULL
        CHECK (algorithm IN ('RSA_2048','RSA_3072','RSA_4096','EC_P256','EC_P384')),
    status                TEXT        NOT NULL DEFAULT 'CREATED'
        CHECK (status IN ('CREATED','READY_TO_PUBLISH','ACTIVE','COMPROMISED','DELETED')),
    public_key_pem        TEXT        NOT NULL,
    -- AES-256-GCM(base64(nonce||ct||tag), AAD = lowercase uuid). NULL after soft
    -- delete: the row remains as evidence, the key material is crypto-shredded.
    private_key_enc       TEXT,
    fingerprint_sha256    TEXT        NOT NULL,
    certificate_chain_pem TEXT,
    cert_subject          TEXT,
    cert_issuer           TEXT,
    cert_serial           TEXT,
    cert_not_before       TIMESTAMPTZ,
    cert_not_after        TIMESTAMPTZ,
    compromised_reason    TEXT,
    created_by            TEXT        NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The same key material must not live twice, but a deleted row's fingerprint
-- may be reused by a fresh key.
CREATE UNIQUE INDEX ux_ssl_keys_fingerprint_live
    ON ssl_keys (fingerprint_sha256) WHERE status <> 'DELETED';
CREATE INDEX ix_ssl_keys_status ON ssl_keys (status);
CREATE INDEX ix_ssl_keys_created_at ON ssl_keys (created_at DESC);

CREATE TABLE key_audit_events (
    id          BIGSERIAL PRIMARY KEY,
    key_id      UUID        NOT NULL REFERENCES ssl_keys (id),
    event_type  TEXT        NOT NULL
        CHECK (event_type IN ('KEY_GENERATED','CSR_ISSUED','CERTIFICATE_UPLOADED',
                              'CERTIFICATE_REJECTED','ACTIVATED','COMPROMISED',
                              'DELETED','PRIVATE_KEY_ACCESSED')),
    actor       TEXT        NOT NULL,
    backend     TEXT        NOT NULL,
    detail      JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_key ON key_audit_events (key_id, occurred_at);

-- The audit trail is evidence. Nothing — including the services themselves —
-- may rewrite history.
CREATE FUNCTION forbid_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'key_audit_events is append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON key_audit_events
    FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
