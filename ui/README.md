# Certificate Manager — UI

Flutter front-end for the certificate-management service. It speaks the same
API to any of the four interchangeable backends:

| Backend | Base URL                |
|---------|-------------------------|
| Java    | `http://localhost:8081` |
| Go      | `http://localhost:8082` |
| Node    | `http://localhost:8083` |
| Rust    | `http://localhost:8084` |

## Prerequisites

- At least one backend running (see the repository root: database via
  `docker compose up -d`, secrets in `.env`, then start any backend).
- Flutter (stable channel) with web and/or macOS desktop support enabled.

## Run

```bash
cd ui
flutter pub get
flutter run -d chrome   # web
flutter run -d macos    # desktop
```

On the connect screen pick a backend (or enter a custom base URL) and sign in
with the `AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET` values from the repo-root
`.env`. The token is held in memory only; on expiry (15 minutes) the app
returns to the connect screen.

## Features

- Key inventory with status filter (CREATED / READY_TO_PUBLISH / ACTIVE /
  COMPROMISED / DELETED) — deleted keys stay visible by design.
- Key generation (RSA 2048/3072/4096, EC P-256/P-384) with a one-time
  private-key dialog.
- Key detail with Overview and Audit tabs:
  - metadata, public-key PEM, certificate metadata + chain PEM (copyable);
  - lifecycle actions gated strictly by the SPEC §5 state machine:
    generate CSR, upload certificate chain (verification errors surfaced as
    `KEY_MISMATCH` / `CHAIN_BROKEN` / `CERT_NOT_VALID`), activate, mark
    compromised, soft delete (crypto-shred), audited private-key retrieval;
  - append-only audit timeline (event type, actor, backend, timestamp,
    detail JSON).
- In-app documentation page (book icon in the AppBar): lifecycle, run
  instructions, API walkthrough and the Zero Trust design rationale.
- Every API failure is shown as `CODE — message`; any 401 returns to the
  connect screen.

## Verify

```bash
flutter analyze
flutter test
flutter build web --release
```
