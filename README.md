# mock-oidc — Mock OIDC Provider (development)

![CI](https://github.com/HarryKodden/mock-oidc/actions/workflows/docker-publish.yml/badge.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A tiny, standalone OpenID Connect (OIDC) test provider useful for local development and integration tests where you need an OIDC issuer to validate tokens or exercise OAuth/OIDC flows.

Features
- Discovery document (.well-known/openid-configuration)
- /authorize (simple login form for authorization code flow)
- /token (authorization_code and client_credentials flows)
- /userinfo (Bearer token)
- /test-token/{user} quick token generator for tests

Status
- CI builds a Docker image and pushes it to GitHub Container Registry (GHCR) on `main` (workflow: `.github/workflows/docker-publish.yml`). The workflow runs tests before building.

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

Contributing
- Bug reports, enhancements and PRs welcome.

License
- Apache License 2.0 — see `LICENSE` file.
# mock-oidc
