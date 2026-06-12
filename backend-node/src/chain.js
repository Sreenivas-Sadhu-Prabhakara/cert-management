import { X509Certificate } from 'node:crypto';

/** Validation failure; `code` is one of INVALID_PEM | KEY_MISMATCH | CHAIN_BROKEN | CERT_NOT_VALID. */
export class ChainError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** Node prints DNs as newline-separated RDNs (encoded order); render RFC 2253-style. */
function dnString(nodeDn) {
  return nodeDn.split('\n').reverse().join(',');
}

function validFrom(cert) {
  return cert.validFromDate ?? new Date(cert.validFrom);
}
function validTo(cert) {
  return cert.validToDate ?? new Date(cert.validTo);
}

/**
 * Validate a leaf-first certificate chain per SPEC §4.4 (steps 2-6; first
 * failure wins). Throws ChainError; returns leaf metadata on success.
 */
export function validateChain(chainPem, storedSpkiDer) {
  // 2. parse all PEM blocks; at least one
  const blocks = chainPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  if (!blocks || blocks.length === 0) {
    throw new ChainError('INVALID_PEM', 'no CERTIFICATE PEM blocks found');
  }
  let certs;
  try {
    certs = blocks.map((b) => new X509Certificate(b));
  } catch {
    throw new ChainError('INVALID_PEM', 'certificate PEM could not be parsed as X.509');
  }

  // 3. public-key binding: leaf SPKI DER must equal stored SPKI DER byte-for-byte
  const leaf = certs[0];
  const leafSpki = leaf.publicKey.export({ type: 'spki', format: 'der' });
  if (!leafSpki.equals(storedSpkiDer)) {
    throw new ChainError(
      'KEY_MISMATCH',
      'leaf certificate public key does not match the stored public key',
    );
  }

  // 4. chain integrity: DN linkage and signature for every adjacent pair
  for (let i = 0; i + 1 < certs.length; i++) {
    const child = certs[i];
    const parent = certs[i + 1];
    let ok = false;
    try {
      ok = child.checkIssued(parent) && child.verify(parent.publicKey);
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new ChainError(
        'CHAIN_BROKEN',
        `certificate ${i} is not issued/signed by certificate ${i + 1}`,
      );
    }
  }

  // 5. trailing self-signed root must verify its own signature
  const last = certs[certs.length - 1];
  if (last.subject === last.issuer) {
    let ok = false;
    try {
      ok = last.verify(last.publicKey);
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new ChainError('CHAIN_BROKEN', 'self-signed root certificate does not verify');
    }
  }

  // 6. validity window: now within [notBefore, notAfter] of every certificate
  const now = new Date();
  for (let i = 0; i < certs.length; i++) {
    if (now < validFrom(certs[i]) || now > validTo(certs[i])) {
      throw new ChainError(
        'CERT_NOT_VALID',
        `certificate ${i} is outside its validity window`,
      );
    }
  }

  return {
    subject: dnString(leaf.subject),
    issuer: dnString(leaf.issuer),
    serial: BigInt('0x' + leaf.serialNumber).toString(10),
    notBefore: validFrom(leaf),
    notAfter: validTo(leaf),
  };
}
