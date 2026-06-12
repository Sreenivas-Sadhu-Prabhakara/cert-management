# cert-management — Node.js backend (port 8083)

Implements `../SPEC.md` against the shared Postgres schema (`../db/init/01-schema.sql`).

```sh
npm install
set -a; source ../.env; set +a; export PORT=8083 BACKEND_NAME=node
npm start            # node src/server.js
```

Verify: `../scripts/smoke.sh 8083` (needs OpenSSL 3.x on PATH).
