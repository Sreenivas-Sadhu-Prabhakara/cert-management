// Configuration is read from the process environment only (SPEC §1).
function required(name) {
  const v = process.env[name];
  if (v === undefined || v === '') {
    console.error(`missing required environment variable ${name}`);
    process.exit(1);
  }
  return v;
}

const masterKey = Buffer.from(required('MASTER_KEY_B64'), 'base64');
if (masterKey.length !== 32) {
  console.error('MASTER_KEY_B64 must decode to exactly 32 bytes');
  process.exit(1);
}

export const config = {
  port: parseInt(process.env.PORT ?? '8083', 10),
  pg: {
    host: process.env.PGHOST ?? 'localhost',
    port: parseInt(process.env.PGPORT ?? '5434', 10),
    database: process.env.PGDATABASE ?? 'certmgr',
    user: process.env.PGUSER ?? 'certmgr',
    password: process.env.PGPASSWORD ?? 'certmgr',
  },
  jwtSecret: required('JWT_SECRET'),
  jwtIssuer: process.env.JWT_ISSUER ?? 'cert-mgmt',
  jwtTtlSeconds: parseInt(process.env.JWT_TTL_SECONDS ?? '900', 10),
  authClientId: process.env.AUTH_CLIENT_ID ?? 'admin',
  authClientSecret: required('AUTH_CLIENT_SECRET'),
  masterKey,
  backendName: process.env.BACKEND_NAME ?? 'node',
};
