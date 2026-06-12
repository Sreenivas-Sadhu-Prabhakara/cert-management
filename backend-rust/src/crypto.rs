//! Key generation, SPKI fingerprinting and AES-256-GCM private-key sealing
//! (SPEC §4.1, §4.2).

use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use spki::EncodePublicKey;
use uuid::Uuid;

pub struct GeneratedKey {
    pub private_pem: String,
    pub public_pem: String,
    pub fingerprint_sha256: String,
}

pub const ALGORITHMS: [&str; 5] = ["RSA_2048", "RSA_3072", "RSA_4096", "EC_P256", "EC_P384"];

/// Generate a key pair. Private key PEM is PKCS#8, public key PEM is SPKI.
/// Fingerprint is lowercase hex SHA-256 over the DER-encoded SPKI.
pub fn generate_key(algorithm: &str) -> Result<GeneratedKey, String> {
    match algorithm {
        "RSA_2048" => generate_rsa(2048),
        "RSA_3072" => generate_rsa(3072),
        "RSA_4096" => generate_rsa(4096),
        "EC_P256" => {
            let secret = p256::SecretKey::random(&mut OsRng);
            let private_pem = secret
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("pkcs8 encode: {e}"))?
                .to_string();
            finish(private_pem, &secret.public_key())
        }
        "EC_P384" => {
            let secret = p384::SecretKey::random(&mut OsRng);
            let private_pem = secret
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("pkcs8 encode: {e}"))?
                .to_string();
            finish(private_pem, &secret.public_key())
        }
        other => Err(format!("unsupported algorithm {other}")),
    }
}

fn generate_rsa(bits: usize) -> Result<GeneratedKey, String> {
    // rsa::RsaPrivateKey::new uses e = 65537.
    let key = rsa::RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| format!("rsa keygen: {e}"))?;
    let private_pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("pkcs8 encode: {e}"))?
        .to_string();
    finish(private_pem, &key.to_public_key())
}

fn finish(private_pem: String, public_key: &impl EncodePublicKey) -> Result<GeneratedKey, String> {
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("spki encode: {e}"))?;
    let spki_der = public_key
        .to_public_key_der()
        .map_err(|e| format!("spki der: {e}"))?;
    let fingerprint_sha256 = hex::encode(Sha256::digest(spki_der.as_bytes()));
    Ok(GeneratedKey { private_pem, public_pem, fingerprint_sha256 })
}

/// AES-256-GCM seal: 12-byte random nonce, AAD = lowercase UUID string,
/// stored value = base64(nonce || ciphertext || tag).
pub fn encrypt_private_key(master_key: &[u8; 32], id: &Uuid, pem: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let aad = id.to_string(); // uuid Display is lowercase
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: pem.as_bytes(), aad: aad.as_bytes() })
        .map_err(|e| format!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(B64.encode(out))
}

pub fn decrypt_private_key(master_key: &[u8; 32], id: &Uuid, stored: &str) -> Result<String, String> {
    let raw = B64.decode(stored.trim()).map_err(|e| format!("base64: {e}"))?;
    if raw.len() < 12 + 16 {
        return Err("ciphertext too short".into());
    }
    let (nonce, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let aad = id.to_string();
    let plain = cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad: aad.as_bytes() })
        .map_err(|e| format!("decrypt: {e}"))?;
    String::from_utf8(plain).map_err(|e| format!("utf8: {e}"))
}

/// Extract the DER bytes from a stored SPKI public-key PEM.
pub fn spki_der_from_pem(public_key_pem: &str) -> Result<Vec<u8>, String> {
    let (label, doc) = der::Document::from_pem(public_key_pem).map_err(|e| format!("pem: {e}"))?;
    if label != "PUBLIC KEY" {
        return Err(format!("unexpected PEM label {label}"));
    }
    Ok(doc.as_bytes().to_vec())
}
