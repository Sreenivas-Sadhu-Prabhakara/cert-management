import crypto from 'node:crypto';
import { Router } from 'express';
import { pool, withTx, audit } from './db.js';
import { ApiError, notFound, invalidState, invalidRequest } from './errors.js';
import {
  ALGORITHMS,
  generateKeyPair,
  encryptPrivateKey,
  decryptPrivateKey,
  spkiDerFromPublicPem,
} from './keycrypto.js';
import { generateCsr } from './csr.js';
import { validateChain, ChainError } from './chain.js';

const STATUSES = ['CREATED', 'READY_TO_PUBLISH', 'ACTIVE', 'COMPROMISED', 'DELETED'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const iso = (d) => (d == null ? null : new Date(d).toISOString());

function keySummary(row) {
  return {
    id: row.id,
    name: row.name,
    algorithm: row.algorithm,
    status: row.status,
    fingerprintSha256: row.fingerprint_sha256,
    hasCertificate: row.certificate_chain_pem != null,
    certNotAfter: iso(row.cert_not_after),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function keyDetail(row) {
  return {
    id: row.id,
    name: row.name,
    algorithm: row.algorithm,
    status: row.status,
    publicKeyPem: row.public_key_pem,
    fingerprintSha256: row.fingerprint_sha256,
    hasCertificate: row.certificate_chain_pem != null,
    certNotAfter: iso(row.cert_not_after),
    certificateChainPem: row.certificate_chain_pem ?? null,
    certificate:
      row.cert_subject == null
        ? null
        : {
            subject: row.cert_subject,
            issuer: row.cert_issuer,
            serialNumber: row.cert_serial,
            notBefore: iso(row.cert_not_before),
            notAfter: iso(row.cert_not_after),
          },
    compromisedReason: row.compromised_reason ?? null,
    createdBy: row.created_by,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function auditEvent(row) {
  return {
    id: Number(row.id),
    keyId: row.key_id,
    eventType: row.event_type,
    actor: row.actor,
    backend: row.backend,
    detail: row.detail ?? null,
    occurredAt: iso(row.occurred_at),
  };
}

/** Fetch a key row or throw 404 (malformed UUIDs are 404 too, SPEC §6). */
async function getKeyOr404(id) {
  if (typeof id !== 'string' || !UUID_RE.test(id)) {
    throw notFound();
  }
  const r = await pool.query('SELECT * FROM ssl_keys WHERE id = $1', [id.toLowerCase()]);
  if (r.rows.length === 0) {
    throw notFound();
  }
  return r.rows[0];
}

/**
 * Atomic compare-and-set transition (SPEC §5): UPDATE ... WHERE id AND
 * status = ANY(allowed) RETURNING *; zero rows with an existing id => 409.
 * Writes the audit event in the same transaction.
 */
async function transition(id, allowedStatuses, setSql, params, eventType, actor, detail) {
  if (!UUID_RE.test(id)) {
    throw notFound();
  }
  return withTx(async (client) => {
    const r = await client.query(
      `UPDATE ssl_keys SET ${setSql}, updated_at = now()
       WHERE id = $1 AND status = ANY($2) RETURNING *`,
      [id.toLowerCase(), allowedStatuses, ...params],
    );
    if (r.rows.length === 0) {
      const exists = await client.query('SELECT 1 FROM ssl_keys WHERE id = $1', [id.toLowerCase()]);
      throw exists.rows.length === 0
        ? notFound()
        : invalidState(`operation not allowed in current key status`);
    }
    await audit(client, r.rows[0].id, eventType, actor, detail);
    return r.rows[0];
  });
}

export const keysRouter = Router();

// POST /api/v1/keys — generate key pair
keysRouter.post('/', async (req, res) => {
  const { name, algorithm } = req.body ?? {};
  if (typeof name !== 'string' || name.trim() === '') {
    throw invalidRequest('name is required');
  }
  if (!ALGORITHMS.includes(algorithm)) {
    throw invalidRequest(`algorithm must be one of ${ALGORITHMS.join(', ')}`);
  }
  const { privatePem, publicPem, fingerprint } = generateKeyPair(algorithm);
  const id = crypto.randomUUID(); // lowercase; generated before encrypting (AAD binding)
  const privateKeyEnc = encryptPrivateKey(privatePem, id);
  const row = await withTx(async (client) => {
    const r = await client.query(
      `INSERT INTO ssl_keys (id, name, algorithm, status, public_key_pem,
                             private_key_enc, fingerprint_sha256, created_by)
       VALUES ($1, $2, $3, 'CREATED', $4, $5, $6, $7) RETURNING *`,
      [id, name, algorithm, publicPem, privateKeyEnc, fingerprint, req.actor],
    );
    await audit(client, id, 'KEY_GENERATED', req.actor, { algorithm });
    return r.rows[0];
  });
  res.status(201).json({ ...keyDetail(row), privateKeyPem: privatePem });
});

// GET /api/v1/keys — list (newest first; DELETED rows included)
keysRouter.get('/', async (req, res) => {
  const { status } = req.query;
  if (status !== undefined && !STATUSES.includes(status)) {
    throw invalidRequest(`status must be one of ${STATUSES.join(', ')}`);
  }
  const r = status
    ? await pool.query(
        'SELECT * FROM ssl_keys WHERE status = $1 ORDER BY created_at DESC, id',
        [status],
      )
    : await pool.query('SELECT * FROM ssl_keys ORDER BY created_at DESC, id');
  res.json({ items: r.rows.map(keySummary), total: r.rows.length });
});

// GET /api/v1/keys/:id — detail (never includes private key)
keysRouter.get('/:id', async (req, res) => {
  const row = await getKeyOr404(req.params.id);
  res.json(keyDetail(row));
});

// GET /api/v1/keys/:id/private — decrypted private key (audited)
keysRouter.get('/:id/private', async (req, res) => {
  const row = await getKeyOr404(req.params.id);
  if (row.status === 'COMPROMISED' || row.status === 'DELETED') {
    throw invalidState(`private key is not retrievable for a ${row.status} key`);
  }
  const privateKeyPem = decryptPrivateKey(row.private_key_enc, row.id);
  await audit(pool, row.id, 'PRIVATE_KEY_ACCESSED', req.actor, null);
  res.json({ id: row.id, privateKeyPem });
});

// POST /api/v1/keys/:id/csr — PKCS#10 CSR
keysRouter.post('/:id/csr', async (req, res) => {
  const row = await getKeyOr404(req.params.id);
  if (!['CREATED', 'READY_TO_PUBLISH', 'ACTIVE'].includes(row.status)) {
    throw invalidState(`CSR generation is not allowed for a ${row.status} key`);
  }
  const { subject, sans } = req.body ?? {};
  if (subject == null || typeof subject !== 'object' || Array.isArray(subject)) {
    throw invalidRequest('subject is required');
  }
  if (typeof subject.commonName !== 'string' || subject.commonName.trim() === '') {
    throw invalidRequest('subject.commonName is required');
  }
  if (sans !== undefined && (!Array.isArray(sans) || sans.some((s) => typeof s !== 'string'))) {
    throw invalidRequest('sans must be an array of DNS name strings');
  }
  const privatePem = decryptPrivateKey(row.private_key_enc, row.id);
  const { csrPem, subjectDn } = await generateCsr({
    algorithm: row.algorithm,
    privatePem,
    publicPem: row.public_key_pem,
    subject,
    sans,
  });
  const detail = { subject: subjectDn };
  if (Array.isArray(sans) && sans.length > 0) detail.sans = sans;
  await audit(pool, row.id, 'CSR_ISSUED', req.actor, detail);
  res.json({ csrPem });
});

// POST /api/v1/keys/:id/certificate — upload + validate chain (SPEC §4.4)
keysRouter.post('/:id/certificate', async (req, res) => {
  const row = await getKeyOr404(req.params.id);
  if (!['CREATED', 'READY_TO_PUBLISH'].includes(row.status)) {
    throw invalidState(`certificate upload is not allowed for a ${row.status} key`);
  }
  const { certificateChainPem } = req.body ?? {};
  if (typeof certificateChainPem !== 'string' || certificateChainPem.trim() === '') {
    throw invalidRequest('certificateChainPem is required');
  }
  let leaf;
  try {
    leaf = validateChain(certificateChainPem, spkiDerFromPublicPem(row.public_key_pem));
  } catch (err) {
    if (!(err instanceof ChainError)) throw err;
    if (err.code === 'INVALID_PEM') {
      throw new ApiError(400, 'INVALID_PEM', err.message);
    }
    // steps 3-6 also write a CERTIFICATE_REJECTED audit event
    await audit(pool, row.id, 'CERTIFICATE_REJECTED', req.actor, { reason: err.code });
    throw new ApiError(422, err.code, err.message);
  }
  const updated = await transition(
    row.id,
    ['CREATED', 'READY_TO_PUBLISH'],
    `certificate_chain_pem = $3, cert_subject = $4, cert_issuer = $5, cert_serial = $6,
     cert_not_before = $7, cert_not_after = $8, status = 'READY_TO_PUBLISH'`,
    [certificateChainPem, leaf.subject, leaf.issuer, leaf.serial, leaf.notBefore, leaf.notAfter],
    'CERTIFICATE_UPLOADED',
    req.actor,
    { subject: leaf.subject, serialNumber: leaf.serial },
  );
  res.json(keyDetail(updated));
});

// POST /api/v1/keys/:id/activate — READY_TO_PUBLISH -> ACTIVE
keysRouter.post('/:id/activate', async (req, res) => {
  const updated = await transition(
    req.params.id,
    ['READY_TO_PUBLISH'],
    `status = 'ACTIVE'`,
    [],
    'ACTIVATED',
    req.actor,
    null,
  );
  res.json(keyDetail(updated));
});

// POST /api/v1/keys/:id/compromise — terminal, undeletable
keysRouter.post('/:id/compromise', async (req, res) => {
  const reason = typeof req.body?.reason === 'string' ? req.body.reason : null;
  const updated = await transition(
    req.params.id,
    ['CREATED', 'READY_TO_PUBLISH', 'ACTIVE'],
    `status = 'COMPROMISED', compromised_reason = $3`,
    [reason],
    'COMPROMISED',
    req.actor,
    reason == null ? null : { reason },
  );
  res.json(keyDetail(updated));
});

// DELETE /api/v1/keys/:id — soft delete, crypto-shred private material
keysRouter.delete('/:id', async (req, res) => {
  await transition(
    req.params.id,
    ['CREATED', 'READY_TO_PUBLISH', 'ACTIVE'],
    `status = 'DELETED', private_key_enc = NULL`,
    [],
    'DELETED',
    req.actor,
    null,
  );
  res.status(204).end();
});

// GET /api/v1/keys/:id/audit — append-only trail, oldest first
keysRouter.get('/:id/audit', async (req, res) => {
  const row = await getKeyOr404(req.params.id);
  const r = await pool.query(
    'SELECT * FROM key_audit_events WHERE key_id = $1 ORDER BY occurred_at ASC, id ASC',
    [row.id],
  );
  res.json({ items: r.rows.map(auditEvent) });
});
