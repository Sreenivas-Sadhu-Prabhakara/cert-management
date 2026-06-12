import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { unauthorized } from './errors.js';
import { constantTimeEquals } from './keycrypto.js';

/** POST /api/v1/auth/token handler (SPEC §2). */
export function issueToken(req, res) {
  const body = req.body ?? {};
  const idOk = constantTimeEquals(body.clientId, config.authClientId);
  const secretOk = constantTimeEquals(body.clientSecret, config.authClientSecret);
  if (!(idOk & secretOk)) {
    throw unauthorized('invalid client credentials');
  }
  const accessToken = jwt.sign({ scope: 'keys:admin' }, config.jwtSecret, {
    algorithm: 'HS256',
    issuer: config.jwtIssuer,
    subject: body.clientId,
    expiresIn: config.jwtTtlSeconds,
  });
  res.status(200).json({
    accessToken,
    tokenType: 'Bearer',
    expiresIn: config.jwtTtlSeconds,
  });
}

/** Bearer-JWT middleware: validates signature, iss and exp. */
export function requireAuth(req, res, next) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? '');
  if (!match) {
    throw unauthorized('missing bearer token');
  }
  let payload;
  try {
    payload = jwt.verify(match[1], config.jwtSecret, {
      algorithms: ['HS256'],
      issuer: config.jwtIssuer,
    });
  } catch {
    throw unauthorized('invalid or expired token');
  }
  req.actor = payload.sub ?? 'unknown';
  next();
}
