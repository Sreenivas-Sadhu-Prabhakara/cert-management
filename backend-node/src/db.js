import pg from 'pg';
import { config } from './config.js';

export const pool = new pg.Pool({
  ...config.pg,
  max: 10,
});

/** Run fn inside a single transaction; ROLLBACK on error, always release. */
export async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      /* connection-level failure; release below */
    }
    throw err;
  } finally {
    client.release();
  }
}

/** Insert one audit event. `queryable` is the pool or a transaction client. */
export async function audit(queryable, keyId, eventType, actor, detail) {
  await queryable.query(
    `INSERT INTO key_audit_events (key_id, event_type, actor, backend, detail)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [keyId, eventType, actor, config.backendName, detail == null ? null : JSON.stringify(detail)],
  );
}
