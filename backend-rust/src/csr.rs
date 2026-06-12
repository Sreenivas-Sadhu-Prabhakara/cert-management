//! PKCS#10 CSR generation (SPEC §4.3).

use std::str::FromStr;

use pkcs8::DecodePrivateKey;
use sha2::Sha256;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::{pem::LineEnding, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;

#[derive(Debug)]
pub enum CsrError {
    BadInput(String),
    Internal(String),
}

fn ierr<E: std::fmt::Display>(context: &'static str) -> impl Fn(E) -> CsrError {
    move |e| CsrError::Internal(format!("{context}: {e}"))
}

/// Build a PEM-encoded PKCS#10 CSR for the given subject DN (RFC 4514 string)
/// and DNS SANs, signed with the stored PKCS#8 private key.
/// RSA -> SHA256withRSA, EC_P256 -> SHA256withECDSA, EC_P384 -> SHA384withECDSA.
pub fn build_csr(
    algorithm: &str,
    private_pem: &str,
    dn: &str,
    sans: &[String],
) -> Result<String, CsrError> {
    let subject =
        Name::from_str(dn).map_err(|e| CsrError::BadInput(format!("invalid subject: {e}")))?;

    let san_ext = if sans.is_empty() {
        None
    } else {
        let mut names = Vec::with_capacity(sans.len());
        for san in sans {
            let ia5 = Ia5String::new(san)
                .map_err(|_| CsrError::BadInput(format!("invalid SAN: {san}")))?;
            names.push(GeneralName::DnsName(ia5));
        }
        Some(SubjectAltName(names))
    };

    match algorithm {
        "RSA_2048" | "RSA_3072" | "RSA_4096" => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(private_pem)
                .map_err(ierr("rsa key"))?;
            let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
            let mut builder = RequestBuilder::new(subject, &signer)
                .map_err(ierr("builder"))?;
            if let Some(san) = &san_ext {
                builder.add_extension(san).map_err(ierr("san"))?;
            }
            let csr = builder
                .build::<rsa::pkcs1v15::Signature>()
                .map_err(ierr("csr sign"))?;
            csr.to_pem(LineEnding::LF).map_err(ierr("csr pem"))
        }
        "EC_P256" => {
            let key = p256::SecretKey::from_pkcs8_pem(private_pem)
                .map_err(ierr("ec key"))?;
            let signer = p256::ecdsa::SigningKey::from(key);
            let mut builder = RequestBuilder::new(subject, &signer)
                .map_err(ierr("builder"))?;
            if let Some(san) = &san_ext {
                builder.add_extension(san).map_err(ierr("san"))?;
            }
            let csr = builder
                .build::<p256::ecdsa::DerSignature>()
                .map_err(ierr("csr sign"))?;
            csr.to_pem(LineEnding::LF).map_err(ierr("csr pem"))
        }
        "EC_P384" => {
            let key = p384::SecretKey::from_pkcs8_pem(private_pem)
                .map_err(ierr("ec key"))?;
            let signer = p384::ecdsa::SigningKey::from(key);
            let mut builder = RequestBuilder::new(subject, &signer)
                .map_err(ierr("builder"))?;
            if let Some(san) = &san_ext {
                builder.add_extension(san).map_err(ierr("san"))?;
            }
            let csr = builder
                .build::<p384::ecdsa::DerSignature>()
                .map_err(ierr("csr sign"))?;
            csr.to_pem(LineEnding::LF).map_err(ierr("csr pem"))
        }
        other => Err(CsrError::Internal(format!("unsupported algorithm {other}"))),
    }
}

/// Escape one attribute value per RFC 4514.
pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let needs_escape = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=')
            || (i == 0 && (*c == ' ' || *c == '#'))
            || (i == chars.len() - 1 && *c == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(*c);
    }
    out
}
