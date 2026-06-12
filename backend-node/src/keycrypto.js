import crypto from 'node:crypto';
import { config } from './config.js';

export const ALGORITHMS = ['RSA_2048', 'RSA_3072', 'RSA_4096', 'EC_P256', 'EC_P384'];

const RSA_BITS = { RSA_2048: 2048, RSA_3072: 3072, RSA_4096: 4096 };
const EC_CURVE = { EC_P256: 'P-256', EC_P384: 'P-384' };

/**
 * Generate a key pair per SPEC §4.1.
 * Private PEM: PKCS#8; public PEM: SPKI; fingerprint: sha256 hex of SPKI DER.
 */
export function generateKeyPair(algorithm) {
  let keyPair;
  if (RSA_BITS[algorithm]) {
    keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: RSA_BITS[algorithm],
      publicExponent: 0x10001,
    });
  } else {
    keyPair = crypto.generateKeyPairSync('ec', { namedCurve: EC_CURVE[algorithm] });
  }
  const privatePem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });
  const spkiDer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex');
  return { privatePem, publicPem, fingerprint };
}

/** SPKI DER bytes of a stored public-key PEM (for byte-for-byte comparison). */
export function spkiDerFromPublicPem(publicPem) {
  return crypto.createPublicKey(publicPem).export({ type: 'spki', format: 'der' });
}

/**
 * AES-256-GCM per SPEC §4.2: 12-byte random nonce, AAD = UTF-8 lowercase UUID,
 * stored value = base64(nonce || ciphertext || tag).
 */
export function encryptPrivateKey(privatePem, uuidLowercase) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.masterKey, nonce);
  cipher.setAAD(Buffer.from(uuidLowercase, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(privatePem, 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString('base64');
}

export function decryptPrivateKey(storedB64, uuidLowercase) {
  const buf = Buffer.from(storedB64, 'base64');
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', config.masterKey, nonce);
  decipher.setAAD(Buffer.from(uuidLowercase, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** Constant-time string comparison via fixed-length SHA-256 digests. */
export function constantTimeEquals(a, b) {
  const ha = crypto.createHash('sha256').update(String(a ?? ''), 'utf8').digest();
  const hb = crypto.createHash('sha256').update(String(b ?? ''), 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}
