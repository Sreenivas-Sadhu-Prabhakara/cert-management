import crypto from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(crypto.webcrypto);
const { subtle } = crypto.webcrypto;

function pemToDer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function importAlgorithm(algorithm) {
  if (algorithm.startsWith('RSA_')) return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  if (algorithm === 'EC_P256') return { name: 'ECDSA', namedCurve: 'P-256' };
  return { name: 'ECDSA', namedCurve: 'P-384' };
}

function signingAlgorithm(algorithm) {
  if (algorithm.startsWith('RSA_')) return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  if (algorithm === 'EC_P256') return { name: 'ECDSA', hash: 'SHA-256' };
  return { name: 'ECDSA', hash: 'SHA-384' }; // EC_P384 -> SHA384withECDSA (SPEC §4.3)
}

/**
 * Generate a PKCS#10 CSR signed with the stored private key (SPEC §4.3).
 * Subject DN order: CN, O, OU, C, ST, L. `sans` are DNS names.
 */
export async function generateCsr({ algorithm, privatePem, publicPem, subject, sans }) {
  const alg = importAlgorithm(algorithm);
  const privateKey = await subtle.importKey('pkcs8', pemToDer(privatePem), alg, false, ['sign']);
  const publicKey = await subtle.importKey('spki', pemToDer(publicPem), alg, true, ['verify']);

  const rdns = [{ CN: [subject.commonName] }];
  if (subject.organization) rdns.push({ O: [subject.organization] });
  if (subject.organizationalUnit) rdns.push({ OU: [subject.organizationalUnit] });
  if (subject.country) rdns.push({ C: [subject.country] });
  if (subject.state) rdns.push({ ST: [subject.state] });
  if (subject.locality) rdns.push({ L: [subject.locality] });
  const name = new x509.Name(rdns);

  const extensions = [];
  if (Array.isArray(sans) && sans.length > 0) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension(
        sans.map((dns) => new x509.GeneralName('dns', dns)),
      ),
    );
  }

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name,
    keys: { privateKey, publicKey },
    signingAlgorithm: signingAlgorithm(algorithm),
    extensions,
  });

  return { csrPem: csr.toString('pem') + '\n', subjectDn: name.toString() };
}
