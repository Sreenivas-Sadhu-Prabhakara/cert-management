import express from 'express';
import { config } from './config.js';
import { pool } from './db.js';
import { ApiError } from './errors.js';
import { issueToken, requireAuth } from './auth.js';
import { keysRouter } from './keys.js';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');

  // CORS (SPEC §3): three headers on every response; OPTIONS preflight -> 204.
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.get('/health', async (req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'up', backend: config.backendName });
    } catch {
      res.status(503).json({ status: 'down', backend: config.backendName });
    }
  });

  app.post('/api/v1/auth/token', issueToken);
  app.use('/api/v1/keys', requireAuth, keysRouter);

  // Unknown routes
  app.use((req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'no such resource' } });
  });

  // Error envelope (SPEC §7); never leak stack traces.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof ApiError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    if (err?.type === 'entity.parse.failed' || err?.type === 'entity.too.large') {
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'malformed request body' } });
    }
    if (err?.code === '22P02') {
      // invalid text representation (e.g. malformed UUID reaching the DB) -> 404
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'no such key' } });
    }
    console.error(err);
    res.status(500).json({ error: { code: 'INTERNAL', message: 'unexpected server error' } });
  });

  return app;
}
