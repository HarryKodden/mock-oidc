# mock-oidc — Mock OIDC Provider (development)

![CI](https://github.com/HarryKodden/mock-oidc/actions/workflows/release.yml/badge.svg?branch=main) ![Release](https://img.shields.io/github/v/release/HarryKodden/mock-oidc?label=release) ![GHCR](https://img.shields.io/docker/v/ghcr.io/harrykodden/mock-oidc/latest?label=ghcr%20image)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A tiny, standalone OpenID Connect (OIDC) test provider useful for local development and integration tests where you need an OIDC issuer to validate tokens or exercise OAuth/OIDC flows.

Features
- Discovery document (.well-known/openid-configuration)
- /authorize (simple login form for authorization code flow)
- /token (authorization_code and client_credentials flows)
- /userinfo (Bearer token)
- /test-token/{user} quick token generator for tests

Status
- CI builds a Docker image and pushes it to GitHub Container Registry (GHCR) on `main` (workflow: `.github/workflows/release.yml`). The workflow runs tests before building.

Quick start (local)

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

2. Start the provider (development/test use only):

```bash
python -c "from app import provider; provider.main()"
```

3. Examples

- Discovery:
  ```bash
  curl -s http://localhost:8888/.well-known/openid-configuration | jq
  ```

- Get a quick test token for `bob`:
  ```bash
  curl -s "http://localhost:8888/test-token/bob?groups=admin,dev" | jq
  ```

- Authorization code flow (manual test):
  - Open in browser: `http://localhost:8888/authorize?client_id=test-client&redirect_uri=https://example.com/cb&response_type=code&state=xyz`
  - Submit username and roles in the form; the server will redirect to your `redirect_uri` with `?code=...`

- Exchange authorization code for token:
  ```bash
  curl -s -X POST http://localhost:8888/token \
    -d grant_type=authorization_code -d code=<CODE> -d redirect_uri=https://example.com/cb
  ```

- Retrieve userinfo:
  ```bash
  curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8888/userinfo | jq
  ```

Docker / GHCR

- Image (built by CI): `ghcr.io/HarryKodden/mock-oidc:latest`

- Build & run locally:
  ```bash
  docker build -t mock-oidc:local .
  docker run -p 8888:8888 \
    -e SECRET="test-jwt-secret" \
    -e CLIENT_ID=test-client \
    -e CLIENT_SECRET=test-secret \
    mock-oidc:local
  ```

Testing

- Run the full test suite:
  ```bash
  pytest -q
  ```

Security & recommendations
- This project is intended for development and testing only. Do NOT use this in production.
- Use a secure, rotating secret or proper asymmetric keys (RS256) for signing tokens in production.
- Serve the provider over HTTPS when integrating with real clients.
- Store authorization codes and tokens in a persistent store (Redis, DB) if you need long-lived test state.
- Consider exposing JWKS with an actual keypair instead of an empty set if your clients validate signatures remotely.

**Environment variables**

The provider can be configured using environment variables. Defaults shown are the values used when the env var is not set.

| Variable | Default | Description | Valid values / notes |
|---|---|---|---|
| `SECRET` | `test-jwt-secret-key-do-not-use-in-production` | HMAC secret used to sign JWTs (env var `SECRET`). | Any string. Use a strong secret in CI or production-like tests; rotate regularly.
| `ISSUER` | `http://localhost:8888` | Issuer base URL (env var `ISSUER`). | Full URL including scheme and port. Update when running behind a proxy or different host.
| `CLIENT_ID` | `test-client` | Client identifier used for strict client authentication (env var `CLIENT_ID`). | Any string. When `STRICT_CLIENT_AUTH` is enabled this must match the client's id.
| `CLIENT_SECRET` | `test-secret` | Client secret used for strict client authentication (env var `CLIENT_SECRET`). | Any string. Keep secret in CI or secure env stores.
| `ROLES_CLAIM` | `groups` | Name of the claim that contains role/group values in issued tokens (env var `ROLES_CLAIM`). | Any string, e.g. `groups` or `roles`. The `/userinfo` response will expose this claim name.
| `STRICT_CLIENT_AUTH` | `true` | Toggle strict validation of client credentials (env var `STRICT_CLIENT_AUTH`). | Truthy: `1`, `true`, `yes` (case-insensitive). Set to `false` or unset to allow permissive mode (accepts any client creds) — convenient for local testing.
| `BASE_PATH` | `` (empty) | Optional base path when the app is mounted under a reverse-proxy (env var `BASE_PATH`). | A path segment (leading slash optional). The server normalizes the value (ensures leading slash, trims trailing slash).

Notes:
- The server also sets a cookie named `mock_oidc_userinfo` when completing `/authorize` to support SSO-style prefill of the authorize UI.
- For local Docker runs you can set these env vars with `-e NAME=value` or via a `.env` file when using `docker compose`.

Recommended for CI: set `STRICT_CLIENT_AUTH=true` to exercise client authentication paths during tests.

Contributing
- Bug reports, enhancements and PRs welcome.

---
License
- Apache License 2.0 — see `LICENSE` file.
