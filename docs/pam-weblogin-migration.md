# Migrate from Device Code Flow to pam-weblogin

This document describes how to replace an RFC 8628 device code flow integration with the phishing-resistant pam-weblogin flow provided by this mock-oidc server.

---

## Background

The pam-weblogin flow is phishing-resistant because a 4-digit PIN is generated **server-side** and is only visible to the user in two places simultaneously:

1. Their terminal (printed as part of the challenge string)
2. The browser page after they complete authentication

A phishing page can never learn the PIN, so it cannot complete the flow on the user's behalf.

---

## Checklist

- [ ] Read the [Flow overview](#flow-overview)
- [ ] Update the `start` call ([Step 1](#step-1--start-a-session))
- [ ] Display the challenge to the user ([Step 2](#step-2--display-the-challenge))
- [ ] Read the PIN from the user ([Step 3](#step-3--read-the-pin-from-the-user))
- [ ] Replace token polling with a single check-pin call ([Step 4](#step-4--check-the-pin))
- [ ] Handle all result states ([Step 5](#step-5--handle-results))
- [ ] Remove old device code flow code ([Step 6](#step-6--remove-old-device-code-code))
- [ ] Set environment variables on the server ([Step 7](#step-7--server-environment-variables))
- [ ] Verify end-to-end in your test environment

---

## Flow overview

### Old flow (RFC 8628 device code)

```
POST /device
  → device_code + user_code + verification_uri

[User visits verification_uri, enters user_code in browser]

loop: POST /token  (grant_type=urn:ietf:params:oauth:grant-type:device_code)
  → authorization_pending  (keep polling)
  → access_token           (done)
```

### New flow (pam-weblogin)

```
POST /pam-weblogin/start
  → session_id + challenge  (challenge contains login URL + PIN)

[Print challenge verbatim in terminal]
[User opens URL in browser and signs in — PIN appears on screen]
[User reads PIN from browser, types it in terminal]

POST /pam-weblogin/check-pin  (session_id + pin)
  → SUCCESS / FAIL / TIMEOUT
```

---

## Step 1 — Start a session

Replace your call to `POST /device` with:

```http
POST /pam-weblogin/start
Authorization: Bearer <PAM_TOKEN>
Content-Type: application/json

{
  "user_id": "<username or email of the authenticating user>",
  "rhost": "<remote host / IP of the user's machine>"
}
```

**Response `201`:**

```json
{
  "session_id": "a3f8c1d2e4b5f6",
  "challenge": "Open the following URL to authenticate:\n  https://oidc.example.com/pam-weblogin/login/a3f8c1d2e4b5f6\nAfter logging in, enter the verification code shown on screen.\nYour verification code: 7342",
  "cached": false,
  "info": "Session expires in 120s"
}
```

Store `session_id` for the check-pin step.

---

## Step 2 — Display the challenge

Print the `challenge` field **verbatim** to the user's terminal. It already contains human-readable instructions, the login URL, and the PIN prompt:

```
Open the following URL to authenticate:
  https://oidc.example.com/pam-weblogin/login/a3f8c1d2e4b5f6
After logging in, enter the verification code shown on screen.
Your verification code: 7342
```

> **Do not parse or reformat the challenge.** Future versions of the server may change its wording.

---

## Step 3 — Read the PIN from the user

Prompt the user to enter the 4-digit code they see in their browser after signing in:

```
Verification code: ____
```

Read exactly 4 digits. Do not accept partial input.

---

## Step 4 — Check the PIN

Replace your polling loop on `POST /token` with a **single** call:

```http
POST /pam-weblogin/check-pin
Authorization: Bearer <PAM_TOKEN>
Content-Type: application/json

{
  "session_id": "a3f8c1d2e4b5f6",
  "pin": "7342"
}
```

---

## Step 5 — Handle results

All responses are HTTP `200` with a JSON body. Branch on the `result` field:

| `result` | `reason` | Meaning | Action |
|----------|----------|---------|--------|
| `SUCCESS` | — | Auth complete | Use `username` and `groups` from the response body |
| `FAIL` | `pending` | User has not finished browser login yet | Ask user to complete browser sign-in, then retry check-pin |
| `FAIL` | `wrong_pin` | Wrong PIN entered | Ask user to re-enter the code |
| `TIMEOUT` | — | Session expired (default 120 s) | Restart from Step 1 |

**SUCCESS response body:**

```json
{
  "result": "SUCCESS",
  "username": "alice@example.com",
  "groups": ["staff", "sudo"],
  "claims": { ... }
}
```

**Error response (not found):** HTTP `404` — the session was already consumed or never existed. Restart from Step 1.

---

## Step 6 — Remove old device code code

The following are no longer needed and can be deleted:

| What | Why |
|------|-----|
| `POST /device` call | Replaced by `POST /pam-weblogin/start` |
| Display / prompt logic for `user_code` | Replaced by printing `challenge` verbatim |
| Polling loop on `POST /token` | Replaced by `POST /pam-weblogin/check-pin` |
| `grant_type=urn:ietf:params:oauth:grant-type:device_code` handling | Not used in new flow |
| `authorization_pending` / `slow_down` error handling | Not used in new flow |

---

## Step 7 — Server environment variables

Set these on the mock-oidc server (e.g. in your `.env` or `docker-compose.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PAM_TOKEN` | value of `CLIENT_SECRET` | Bearer token your client must send on `/start` and `/check-pin` |
| `PAM_SESSION_EXPIRES_SEC` | `120` | How long a session stays open waiting for browser login |

If `PAM_TOKEN` is not set, the server falls back to `CLIENT_SECRET` automatically.

---

## curl examples

**Start a session:**
```bash
curl -s -X POST https://oidc.example.com/pam-weblogin/start \
  -H "Authorization: Bearer test-secret" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice@example.com", "rhost": "10.0.0.1"}'
```

**Check a PIN:**
```bash
curl -s -X POST https://oidc.example.com/pam-weblogin/check-pin \
  -H "Authorization: Bearer test-secret" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "a3f8c1d2e4b5f6", "pin": "7342"}'
```

---

## Contact

Questions about this mock server: open an issue at https://github.com/HarryKodden/mock-oidc
