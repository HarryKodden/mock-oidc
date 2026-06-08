# mock-oidc — Mock OIDC Provider (development)

[![CI](https://github.com/HarryKodden/mock-oidc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/HarryKodden/mock-oidc/actions/workflows/ci.yml) [![GitHub release](https://img.shields.io/github/v/release/HarryKodden/mock-oidc?label=release)](https://github.com/HarryKodden/mock-oidc/releases/latest) [![GHCR Docker image (latest)](https://img.shields.io/docker/v/ghcr.io/harrykodden/mock-oidc/latest?label=ghcr.io%2Fharrykodden%2Fmock-oidc&logo=github)](https://github.com/HarryKodden/mock-oidc/pkgs/container/mock-oidc)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A small, standalone OpenID Connect (OIDC) test provider for local development and integration tests: discovery, JWT issuance, and common OAuth/OIDC flows without an external IdP.

## Features

- **Landing & health** — `GET /` serves a small HTML page with links to discovery, authorize, JWKS, OAuth callback demo, and device-flow helpers. **`GET /callback`** receives the authorization redirect (`redirect_uri={issuer}{BASE_PATH}/callback`), shows tokens, UserInfo, and introspection/refresh helpers (see [Landing page demo](#landing-page-demo)). **`GET /health`** returns JSON (`status`, `issuer`, `version`) for Docker/Kubernetes probes.
- **Discovery** — `GET /.well-known/openid-configuration` (issuer, endpoints, grant types, **`introspection_endpoint`**, **`code_challenge_methods_supported`** for PKCE).
- **Signing** — Access and ID tokens are **RS256** JWTs. **`GET /jwks`** exposes the public key with **`x5c`** (self-signed cert by default) so clients that require RS256/x5c can validate remotely.
- **Authorization code flow** — `GET/POST /authorize` with a browser form to compose **claims** (JSON-backed rows: `sub`, `email`, `groups`, etc.). Redirects with `code`.
- **PKCE (RFC 7636)** — Optional on the authorization code flow. Pass **`code_challenge`** (and optionally **`code_challenge_method`**) on `/authorize`; if the challenge is present and the method is omitted, **`S256`** is assumed. Discovery advertises **`S256`** and **`plain`**. Exchange the code at **`POST /token`** with **`code_verifier`** (required when a challenge was used).
- **Token endpoint** — `POST /token` for:
  - `grant_type=authorization_code` (with optional PKCE as above); returns **`refresh_token`** for rotating sessions
  - `grant_type=refresh_token` — exchange a refresh token for new access + ID tokens and a **new** refresh token (rotation)
  - `grant_type=client_credentials` (no refresh token)
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` (**RFC 8628** device flow; includes refresh token)
- **Token introspection (RFC 7662)** — `POST /introspect` with `token` and client authentication (`client_id` / `client_secret` when strict auth is on). Returns **`active`** (boolean) for access tokens (JWT) and refresh tokens (opaque), plus **`token_type`**, **`client_id`**, **`sub`**, **`exp`**, etc.
- **Device authorization (RFC 8628)** — `POST /device` returns `device_code`, `user_code`, and verification URLs. User completes sign-in at **`GET/POST /device/verify`** (same claims UX as authorize). The client polls **`POST /token`** until approval or expiry.
- **UserInfo** — `GET /userinfo` with `Authorization: Bearer <access_token>`.
- **Quick test tokens** — `GET /test-token/{user}?groups=...&client_id=...` for scripted tests.
- **Tokens** — Issued JWTs include standard claims such as `iss`, `sub`, `aud` (the initiating **client_id**), `exp`, `iat`, plus your configured roles claim (default name **`groups`** via `ROLES_CLAIM`).
- **Reverse proxy** — Optional `BASE_PATH` when the app is mounted under a subpath.

## Status

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs **tests** on every **push** and **pull request**. When you **[publish a GitHub Release](https://github.com/HarryKodden/mock-oidc/releases/new)** (create a tag, e.g. `v1.2.0`), the same workflow builds and pushes the **Docker image** to [GHCR](https://github.com/HarryKodden/mock-oidc/pkgs/container/mock-oidc) with tags **`ghcr.io/harrykodden/mock-oidc:<release-tag>`** and **`:latest`**.

## Quick start (local)

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

### Landing page demo

- **`GET /`** — Includes an **Authorize** link that uses **`redirect_uri={issuer}{BASE_PATH}/callback`** (must match the value you send to `/authorize` exactly), plus a **device code** section to request `device_code` / `user_code`, open verification URLs, and poll **`POST /token`** until tokens are issued.
- **`GET /callback`** — After sign-in, the browser returns here with `?code=...&state=...`. The provider exchanges the code **in-process** (no nested HTTP call to `/token`) and renders token JSON, decoded access-token claims, **UserInfo**, and buttons that call **introspection** and **refresh** via `fetch` (demo only: client id/secret are embedded in the page HTML).
- **PKCE** — If you start `/authorize` **with** `code_challenge`, complete the flow with **`POST /token`** and **`code_verifier`**. The **`/callback`** page only supports **non-PKCE** authorization code exchanges.

3. Examples

- **Health (for orchestration):**
  ```bash
  curl -s http://localhost:8888/health | jq
  ```

- **Discovery and JWKS:**
  ```bash
  curl -s http://localhost:8888/.well-known/openid-configuration | jq
  curl -s http://localhost:8888/jwks | jq
  ```

- **Quick test token** for `bob`:
  ```bash
  curl -s "http://localhost:8888/test-token/bob?groups=admin,dev" | jq
  ```

- **Authorization code flow** (browser):
  - Open: `http://localhost:8888/authorize?client_id=test-client&redirect_uri=https://example.com/cb&response_type=code&state=xyz`
  - Edit claims in the form and submit; you are redirected to `redirect_uri?code=...&state=...`

- **Exchange code for tokens** (response includes `refresh_token` when using the authorization or device code flows):
  ```bash
  curl -s -X POST http://localhost:8888/token \
    -d grant_type=authorization_code -d code=<CODE> -d redirect_uri=https://example.com/cb
  ```

- **Refresh access token** (rotation — old refresh token is invalidated):
  ```bash
  curl -s -X POST http://localhost:8888/token \
    -d grant_type=refresh_token \
    -d refresh_token=<REFRESH_TOKEN> \
    -d client_id=test-client \
    -d client_secret=test-secret
  ```

- **Introspect a token** (RFC 7662):
  ```bash
  curl -s -X POST http://localhost:8888/introspect \
    -d token=<ACCESS_OR_REFRESH_TOKEN> \
    -d client_id=test-client \
    -d client_secret=test-secret | jq
  ```

- **Device flow** (RFC 8628) — outline:
  1. `POST /device` with `client_id` and `client_secret` (when strict client auth is on).
  2. User completes sign-in at **`/device/verify`** in a browser, **or** via `curl` as below.
  3. Poll **`POST /token`** with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`, and `client_secret` until you receive tokens, or `authorization_pending`, or `slow_down` if you poll faster than `DEVICE_POLL_INTERVAL` (default 5 seconds).

- **Device flow** — copy-paste example (`bash`, provider on `localhost:8888`, defaults `test-client` / `test-secret`, **`jq`** installed):

  ```bash
  BASE=http://localhost:8888
  GRANT=urn:ietf:params:oauth:grant-type:device_code

  # 1) Request device and user codes
  STEP=$(curl -s -X POST "$BASE/device" \
    -d client_id=test-client \
    -d client_secret=test-secret)
  echo "$STEP" | jq .
  DEVICE_CODE=$(echo "$STEP" | jq -r .device_code)
  USER_CODE=$(echo "$STEP" | jq -r .user_code)

  # 2) (Optional) Poll before the user has approved — expect authorization_pending
  curl -s -X POST "$BASE/token" \
    -d grant_type="$GRANT" \
    -d device_code="$DEVICE_CODE" \
    -d client_id=test-client \
    -d client_secret=test-secret | jq .

  # 3) Complete verification (curl): legacy username + roles, or use the browser on verification_uri / verification_uri_complete
  curl -s -X POST "$BASE/device/verify" \
    -d "user_code=$USER_CODE" \
    -d username=alice \
    -d roles=admin,dev

  # 4) If you ran step 2, wait at least DEVICE_POLL_INTERVAL seconds (default 5) before the next token request,
  #    or the server may return slow_down. Skip this sleep if you skipped step 2, or set DEVICE_POLL_INTERVAL=0 on the server.
  sleep 5

  # 5) Exchange device code for access + ID tokens
  curl -s -X POST "$BASE/token" \
    -d grant_type="$GRANT" \
    -d device_code="$DEVICE_CODE" \
    -d client_id=test-client \
    -d client_secret=test-secret | jq .
  ```

  Open `verification_uri` or `verification_uri_complete` from the step 1 JSON in a browser if you prefer the full claims form instead of step 3.

- **UserInfo:**
  ```bash
  curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8888/userinfo | jq
  ```

## Docker / GHCR

- **Package:** [`ghcr.io/harrykodden/mock-oidc`](https://github.com/HarryKodden/mock-oidc/pkgs/container/mock-oidc) — images are published when you publish a **GitHub Release** (not on every push).
- **Tags:** `latest` points at the most recent release; each release is also tagged with the **Git tag** (e.g. `v1.2.0`):

  ```bash
  docker pull ghcr.io/harrykodden/mock-oidc:latest
  docker pull ghcr.io/harrykodden/mock-oidc:v1.2.0   # example: use your release tag
  ```

- Build and run locally:
  ```bash
  docker build -t mock-oidc:local .
  docker run -p 8888:8888 \
    -e CLIENT_ID=test-client \
    -e CLIENT_SECRET=test-secret \
    mock-oidc:local
  ```

## Testing

```bash
pytest -q
```

## Security and recommendations

- Intended for **development and testing only**. Do not use as a production IdP.
- Tokens are signed with **RS256**; prefer supplying your own key and certificate in real integrations (`OIDC_RSA_PRIVATE_KEY`, `OIDC_X509_CERT`).
- Serve the provider over **HTTPS** when integrating with real clients.
- Authorization codes, device grants, and in-memory token metadata are **ephemeral**; use external storage if you need shared state across processes.

## Environment variables

Defaults apply when a variable is unset.

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER` | `http://localhost:8888` | Issuer URL (scheme, host, port). Set when behind a proxy or different host. |
| `CLIENT_ID` | `test-client` | OAuth client id; must match the client when `STRICT_CLIENT_AUTH` is enabled. |
| `CLIENT_SECRET` | `test-secret` | Client secret for strict auth and confidential flows. |
| `ROLES_CLAIM` | `groups` | Claim name used for roles/groups in tokens and `/userinfo`. |
| `DEFAULT_CLAIMS_<SCOPE>` | *(per-scope built-in)* | JSON object of default/example claims for that OAuth scope on `/authorize` and `/device/verify` when no `mock_oidc_userinfo` cookie is set. Claims from multiple requested scopes are merged (e.g. `scope=openid email` uses `DEFAULT_CLAIMS_OPENID` + `DEFAULT_CLAIMS_EMAIL`). If `scope` is omitted, only `openid` defaults apply. Use `"$uuid"` as a string value to generate a fresh UUID on each form load. Built-in defaults: `DEFAULT_CLAIMS_OPENID` → `{"sub":"$uuid"}`, `DEFAULT_CLAIMS_PROFILE` → `{"name":"Example User","preferred_username":"user"}`, `DEFAULT_CLAIMS_EMAIL` → `{"email":"user@example.com","email_verified":true}`, `DEFAULT_CLAIMS_GROUPS` → `{"groups":["developer"]}` (uses `ROLES_CLAIM` name). Custom scopes map to env names by uppercasing (e.g. scope `roles:admin` → `DEFAULT_CLAIMS_ROLES_ADMIN`). |
| `STRICT_CLIENT_AUTH` | `true` | If true, `client_id` / `client_secret` must match `CLIENT_ID` / `CLIENT_SECRET` where applicable. Use `false` for permissive local testing. |
| `BASE_PATH` | *(empty)* | **Path** prefix when the app is mounted under a URL path (e.g. `/oidc`), not the hostname. Must not duplicate a path already included in **`ISSUER`**. If you mistakenly set this to your host name (e.g. `oidc.apps.fried-air.com`), it is ignored for generated URLs and a warning is logged. |
| `OIDC_RSA_PRIVATE_KEY` | *(generate)* | Path to PEM file or PEM string of the RSA **private** key used to sign JWTs. If unset, a key is generated at startup (not stable across restarts). |
| `OIDC_X509_CERT` | *(self-signed)* | Path to PEM or PEM string of the certificate for **`x5c`** in JWKS. If unset, a self-signed cert is generated with the private key. |
| `DEVICE_POLL_INTERVAL` | `5` | Minimum seconds between token polls for the device grant; responses may include `slow_down`. Set to `0` to disable the slow-down check (e.g. tests). |
| `DEVICE_EXPIRES_SEC` | `600` | Lifetime (seconds) of a device authorization session. |
| `ACCESS_TOKEN_TTL_SEC` | `3600` | Access / ID token lifetime in seconds (`exp`, `expires_in`, and `/userinfo` validation). |
| `REFRESH_TOKEN_TTL_SEC` | `604800` (7 days) | Refresh token lifetime for authorization code and device code flows. |
| `MOCK_OIDC_VERSION` | `dev` | Shown in **`GET /health`** JSON (`version` field); set to your app or image tag in Docker/Kubernetes. |

**Notes**

- `SECRET` is reserved in code but **JWTs are not signed with it**; signing uses the RSA key above.
- Completing `/authorize` sets a cookie `mock_oidc_userinfo` to prefill the next authorize or device verification page.
- Example custom default claims per scope:
  ```bash
  DEFAULT_CLAIMS_OPENID='{"sub":"$uuid"}' \
  DEFAULT_CLAIMS_EMAIL='{"email":"alice@example.com","email_verified":true}' \
  DEFAULT_CLAIMS_GROUPS='{"groups":["admin","developer"]}' \
    python -c "from app import provider; provider.main()"
  ```

## Contributing

Bug reports, enhancements, and pull requests are welcome.

---

## License

Apache License 2.0 — see the `LICENSE` file.
