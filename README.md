# mock-oidc — Mock OIDC Provider (development)

[![CI](https://github.com/HarryKodden/mock-oidc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/HarryKodden/mock-oidc/actions/workflows/ci.yml) [![GitHub release](https://img.shields.io/github/v/release/HarryKodden/mock-oidc?label=release)](https://github.com/HarryKodden/mock-oidc/releases/latest) [![GHCR Docker image (latest)](https://img.shields.io/docker/v/ghcr.io/harrykodden/mock-oidc/latest?label=ghcr.io%2Fharrykodden%2Fmock-oidc&logo=github)](https://github.com/HarryKodden/mock-oidc/pkgs/container/mock-oidc)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A small, standalone OpenID Connect (OIDC) test provider for local development and integration tests: discovery, JWT issuance, and common OAuth/OIDC flows without an external IdP.

## Features

- **Landing & health** — `GET /` serves a small HTML page with links to discovery, authorize, JWKS, OAuth callback demo, and device-flow helpers. **`GET /callback`** receives the authorization redirect (`redirect_uri={issuer}{BASE_PATH}/callback`), shows tokens, UserInfo, and introspection/refresh helpers (see [Landing page demo](#landing-page-demo)). **`GET /health`** returns JSON (`status`, `issuer`, `version`) for Docker/Kubernetes probes.
- **Discovery** — `GET /.well-known/openid-configuration` and **`GET /.well-known/oauth-authorization-server`** (RFC 8414; same metadata for MCP/Cursor AS discovery). Includes issuer, endpoints, grant types, **`scopes_supported`** / **`claims_supported`**, **`introspection_endpoint`**, **`registration_endpoint`**, **`token_endpoint_auth_methods_supported`** (including **`none`**), and **`code_challenge_methods_supported`**.
- **Dynamic Client Registration (RFC 7591)** — `POST /register` for public clients (`token_endpoint_auth_method: "none"`). Cursor can connect with only the issuer URL (no shared `CLIENT_ID` / `CLIENT_SECRET` in `mcp.json`). Default redirect allowlist includes `http://localhost:8787/callback` and `https://www.cursor.com/agents/mcp/oauth/callback`. Public clients **must** use **PKCE S256**.
- **Signing** — Access and ID tokens are **RS256** JWTs. **`GET /jwks`** exposes the public key with **`x5c`** (self-signed cert by default) so clients that require RS256/x5c can validate remotely.
- **Authorization code flow** — `GET/POST /authorize` with a browser form to compose **claims** (JSON-backed rows: `sub`, `email`, `groups`, etc.). Redirects with `code`.
- **PKCE (RFC 7636)** — Optional for the static confidential client; **required (S256)** for DCR public clients. Pass **`code_challenge`** (and optionally **`code_challenge_method`**) on `/authorize`; if the challenge is present and the method is omitted, **`S256`** is assumed. Exchange the code at **`POST /token`** with **`code_verifier`**.
- **Token endpoint** — `POST /token` for:
  - `grant_type=authorization_code` (with optional/required PKCE as above); returns **`refresh_token`** when **`offline_access`** is in scope (or when no scope was sent, for legacy/demo compatibility)
  - `grant_type=refresh_token` — exchange a refresh token for new access + ID tokens and a **new** refresh token (rotation); public clients refresh with `client_id` only
  - `grant_type=client_credentials` (no refresh token)
  - `grant_type=urn:ietf:params:oauth:grant-type:device_code` (**RFC 8628** device flow; refresh when `offline_access` is granted)
- **Token introspection (RFC 7662)** — `POST /introspect` with `token` and client authentication (`client_id` / `client_secret` when strict auth is on; public clients use `client_id` only). Returns **`active`**, **`token_type`**, **`client_id`**, **`sub`**, **`exp`**, **`scope`**, etc.
- **Device authorization (RFC 8628)** — `POST /device` returns `device_code`, `user_code`, and verification URLs. User completes sign-in at **`GET/POST /device/verify`** (same claims UX as authorize). The client polls **`POST /token`** until approval or expiry.
- **UserInfo** — `GET /userinfo` with `Authorization: Bearer <access_token>`.
- **Quick test tokens** — `GET /test-token/{user}?groups=...&client_id=...&scope=...` for scripted tests.
- **Tokens** — Issued JWTs include `iss`, `sub`, `aud`, `exp`, `iat`, **`scope`** (space-separated granted scopes), **`client_id`**, plus your configured roles claim (default name **`groups`** via `ROLES_CLAIM`). If **`nonce`** was sent on `/authorize`, it is stored with the auth code and returned as an ID Token claim on code exchange (this mock uses the same JWT for `access_token` and `id_token`). By default **`aud`** is the initiating **client_id**; set **`ACCESS_TOKEN_AUDIENCE`** to an API/resource URL when resource servers expect a fixed audience. Add app-specific scopes via `DEFAULT_CLAIMS_<SCOPE>` (empty `{}` for claimless scopes that only appear on the token `scope` claim).
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

- **`GET /`** — Includes a **Sign in** link with checkboxes to select OAuth **scopes** (defaults to `openid`; always includes `openid`). The chosen scopes are sent as the `scope` parameter on `/authorize` (and on the demo device flow). Uses **`redirect_uri={issuer}{BASE_PATH}/callback`** (must match the value you send to `/authorize` exactly), plus a **device code** section to request `device_code` / `user_code`, open verification URLs, and poll **`POST /token`** until tokens are issued.
- **`GET /callback`** — After sign-in, the browser returns here with `?code=...&state=...`. The provider exchanges the code **in-process** (no nested HTTP call to `/token`) and renders token JSON, decoded access-token claims, **UserInfo**, and buttons that call **introspection** and **refresh** via `fetch` (demo only: client id/secret are embedded in the page HTML).
- **PKCE** — If you start `/authorize` **with** `code_challenge`, complete the flow with **`POST /token`** and **`code_verifier`**. The **`/callback`** page only supports **non-PKCE** authorization code exchanges.

3. Examples

- **Health (for orchestration):**
  ```bash
  curl -s http://localhost:8888/health | jq
  ```

- **Discovery, AS metadata, and JWKS:**
  ```bash
  curl -s http://localhost:8888/.well-known/openid-configuration | jq
  curl -s http://localhost:8888/.well-known/oauth-authorization-server | jq
  curl -s http://localhost:8888/.well-known/jwks.json | jq
  ```

- **Dynamic Client Registration** (public / PKCE client for Cursor MCP):
  ```bash
  curl -s -X POST http://localhost:8888/register \
    -H 'Content-Type: application/json' \
    -d '{
      "client_name": "cursor-mcp",
      "redirect_uris": [
        "http://localhost:8787/callback",
        "https://www.cursor.com/agents/mcp/oauth/callback"
      ],
      "token_endpoint_auth_method": "none",
      "grant_types": ["authorization_code", "refresh_token"],
      "response_types": ["code"],
      "scope": "openid offline_access profile"
    }' | jq
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
| `CLIENT_ID` | `test-client` | Static OAuth client id; must match when `STRICT_CLIENT_AUTH` is enabled. DCR clients get their own `client_id`. |
| `CLIENT_SECRET` | `test-secret` | Client secret for the static confidential client. |
| `ACCESS_TOKEN_AUDIENCE` | *(empty → client_id)* | Fixed `aud` claim for access tokens (e.g. API resource URL). When empty, `aud` is the initiating `client_id`. The JWT always also includes a `client_id` claim. |
| `DCR_ENABLED` | `true` | Advertise `registration_endpoint` and accept `POST /register`. |
| `DCR_ALLOWED_REDIRECT_URIS` | Cursor callbacks + demo `/callback` | Comma-separated redirect URI allowlist for DCR. Defaults: `http://localhost:8787/callback`, `https://www.cursor.com/agents/mcp/oauth/callback`, plus the demo callback. |
| `DCR_ALLOW_ANY_REDIRECT` | `false` | If true, accept any `redirect_uris` in registration (still validates them at `/authorize`). |
| `ROLES_CLAIM` | `groups` | Claim name used for roles/groups in tokens and `/userinfo`. |
| `DEFAULT_CLAIMS_<SCOPE>` | *(per-scope built-in)* | JSON object of default/example claims for that OAuth scope on `/authorize` and `/device/verify` when no `mock_oidc_userinfo` cookie is set. Claims from multiple requested scopes are merged. Placeholders: `"$uuid"` (fresh UUID), `"$email"` (`givenname-surname@domain`), `"$given_name"`, `"$family_name"`, `"$name"`, `"$preferred_username"` (same random person per form load). Built-in: `openid` → `{"sub":"$uuid"}`, `offline_access` → `{}` (claimless; consent for refresh tokens), `profile` → name placeholders, `email` → email placeholders, plus `ROLES_CLAIM` scope (default `groups`). Custom scopes map to env names by uppercasing and replacing non-alnum with `_` (e.g. scope `api:read` → `DEFAULT_CLAIMS_API_READ`; use `{}` for claimless scopes). |
| `DEFAULT_EMAIL_DOMAIN` | `example.com` | Domain used when expanding `"$email"` / `"$preferred_username"` placeholders. |
| `STRICT_CLIENT_AUTH` | `true` | If true, confidential clients must present a matching secret. Public DCR clients (`token_endpoint_auth_method=none`) authenticate with `client_id` only (+ PKCE). Use `false` for permissive local testing. |
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
- **Docker Compose note:** Compose treats `$…` as its own variable substitution. Escape placeholders as `$$uuid`, `$$email`, `$$name`, etc. Example:
  ```yaml
  environment:
    DEFAULT_EMAIL_DOMAIN: example.com
    DEFAULT_CLAIMS_OPENID: |
      {"sub": "$$uuid"}
    DEFAULT_CLAIMS_EMAIL: |
      {"email": "$$email", "email_verified": true}
    DEFAULT_CLAIMS_PROFILE: |
      {
        "name": "$$name",
        "given_name": "$$given_name",
        "family_name": "$$family_name",
        "preferred_username": "$$given_name-$$family_name"
      }
  ```
- Example custom default claims per scope (shell):
  ```bash
  DEFAULT_CLAIMS_OPENID='{"sub":"$uuid"}' \
  DEFAULT_CLAIMS_EMAIL='{"email":"$email","email_verified":true}' \
  DEFAULT_CLAIMS_PROFILE='{"name":"$name","given_name":"$given_name","family_name":"$family_name"}' \
  DEFAULT_EMAIL_DOMAIN=example.com \
    python -c "from app import provider; provider.main()"
  ```

## Contributing

Bug reports, enhancements, and pull requests are welcome.

---

## License

Apache License 2.0 — see the `LICENSE` file.
