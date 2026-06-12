import { config } from './config.js';
import { createApp } from './app.js';

const app = createApp();
const server = app.listen(config.port, () => {
  console.log(`cert-management backend '${config.backendName}' listening on :${config.port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
