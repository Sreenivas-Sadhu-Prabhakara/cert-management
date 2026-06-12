//! Certificate-chain validation (SPEC §4.4) — leaf first, exact failure order.

use chrono::{DateTime, Utc};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    InvalidPem,
    KeyMismatch,
    ChainBroken,
    CertNotValid,
}

impl ChainError {
    pub fn code(&self) -> &'static str {
        match self {
            ChainError::InvalidPem => "INVALID_PEM",
            ChainError::KeyMismatch => "KEY_MISMATCH",
            ChainError::ChainBroken => "CHAIN_BROKEN",
            ChainError::CertNotValid => "CERT_NOT_VALID",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            ChainError::InvalidPem => "certificate chain contains no parseable CERTIFICATE PEM blocks",
            ChainError::KeyMismatch => "leaf certificate public key does not match the stored key",
            ChainError::ChainBroken => "certificate chain is broken (issuer/signature mismatch)",
            ChainError::CertNotValid => "a certificate in the chain is outside its validity window",
        }
    }
}

pub struct LeafInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// Validate the chain in SPEC order (steps 2–6; step 1 — state — is the
/// caller's job) and extract the leaf metadata on success.
pub fn validate_chain(chain_pem: &str, expected_spki_der: &[u8]) -> Result<LeafInfo, ChainError> {
    // Step 2: parse all PEM blocks as X.509; at least one required.
    let mut pems: Vec<Pem> = Vec::new();
    for item in Pem::iter_from_buffer(chain_pem.as_bytes()) {
        let pem = item.map_err(|_| ChainError::InvalidPem)?;
        if pem.label == "CERTIFICATE" {
            pems.push(pem);
        }
    }
    if pems.is_empty() {
        return Err(ChainError::InvalidPem);
    }
    let mut certs: Vec<X509Certificate> = Vec::with_capacity(pems.len());
    for pem in &pems {
        certs.push(pem.parse_x509().map_err(|_| ChainError::InvalidPem)?);
    }

    // Step 3: leaf SPKI DER must equal the stored SPKI DER byte-for-byte.
    let leaf = &certs[0];
    if leaf.tbs_certificate.subject_pki.raw != expected_spki_der {
        return Err(ChainError::KeyMismatch);
    }

    // Step 4: adjacency — issuer DN matches and signature verifies.
    for pair in certs.windows(2) {
        let (child, parent) = (&pair[0], &pair[1]);
        if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
            return Err(ChainError::ChainBroken);
        }
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|_| ChainError::ChainBroken)?;
    }

    // Step 5: trailing self-signed certificate must verify its own signature.
    let last = certs.last().unwrap();
    if last.tbs_certificate.subject == last.tbs_certificate.issuer {
        last.verify_signature(None).map_err(|_| ChainError::ChainBroken)?;
    }

    // Step 6: every certificate currently within its validity window.
    if !certs.iter().all(|c| c.validity().is_valid()) {
        return Err(ChainError::CertNotValid);
    }

    let leaf = &certs[0];
    Ok(LeafInfo {
        subject: leaf.subject().to_string(),
        issuer: leaf.issuer().to_string(),
        serial: leaf.tbs_certificate.serial.to_string(), // canonical decimal
        not_before: to_utc(leaf.validity().not_before.timestamp()),
        not_after: to_utc(leaf.validity().not_after.timestamp()),
    })
}

fn to_utc(ts: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_default()
}
