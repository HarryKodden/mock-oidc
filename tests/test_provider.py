import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import jwt
import requests
import pytest

from http.server import HTTPServer

from app import provider


@pytest.fixture(scope="module")
def running_server():
    provider.AUTH_CODES.clear()
    provider.TOKEN_DATA.clear()
    provider.DEVICE_GRANTS.clear()
    provider.USER_CODE_INDEX.clear()
    provider.DEVICE_POLL_INTERVAL = 0  # skip slow_down between polls in tests

    server = HTTPServer(('127.0.0.1', 0), provider.OIDCHandler)
    port = server.server_address[1]

    # Ensure provider uses the test server URL
    provider.PORT = port
    provider.ISSUER = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)

    yield provider.ISSUER

    server.shutdown()
    server.server_close()
    thread.join(timeout=1)


def test_discovery_and_jwks(running_server):
    base = running_server

    # Discovery document
    r = requests.get(f"{base}/.well-known/openid-configuration")
    assert r.status_code == 200
    doc = r.json()
    assert doc.get('issuer') == provider.ISSUER
    assert 'token_endpoint' in doc
    assert doc.get('device_authorization_endpoint') == f"{provider.ISSUER}/device"
    assert 'urn:ietf:params:oauth:grant-type:device_code' in doc.get('grant_types_supported', [])

    # JWKS: RS256 key with x5c (client expects RS256/x5c)
    r = requests.get(f"{base}/jwks")
    assert r.status_code == 200
    jwks = r.json()
    keys = jwks.get('keys', [])
    assert isinstance(keys, list)
    assert len(keys) >= 1
    key = keys[0]
    assert key.get('kty') == 'RSA'
    assert key.get('alg') == 'RS256'
    assert 'n' in key and 'e' in key
    assert 'x5c' in key
    assert len(key['x5c']) >= 1


def test_authorization_code_flow_and_userinfo(running_server):
    base = running_server

    redirect_uri = 'https://example.com/callback'
    state = 'teststate123'

    # Step 1: GET authorization page
    params = {
        'client_id': provider.CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'state': state,
    }
    r = requests.get(f"{base}/authorize", params=params)
    assert r.status_code == 200
    assert '<form' in r.text

    # Step 2: POST login form to /authorize -> expect redirect with code
    data = {
        'username': 'alice',
        'roles': 'admin,dev',
        'client_id': provider.CLIENT_ID,
        'redirect_uri': redirect_uri,
        'state': state,
        'response_type': 'code',
    }
    r = requests.post(f"{base}/authorize", data=data, allow_redirects=False)
    assert r.status_code == 302
    loc = r.headers['Location']
    q = urllib.parse.urlparse(loc).query
    code = urllib.parse.parse_qs(q)['code'][0]

    # Step 3: Exchange code for token
    token_resp = requests.post(f"{base}/token", data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
    })
    assert token_resp.status_code == 200
    token_json = token_resp.json()
    assert 'access_token' in token_json

    access_token = token_json['access_token']

    # Validate JWT (RS256, public key); aud must be the initiating client_id
    decoded = jwt.decode(
        access_token, provider.RSA_PUBLIC_KEY, algorithms=['RS256'],
        audience=provider.CLIENT_ID
    )
    assert decoded.get('sub') == 'alice'
    assert decoded.get('aud') == provider.CLIENT_ID
    assert 'groups' in decoded or provider.ROLES_CLAIM in decoded

    # Step 4: Call userinfo
    ui = requests.get(f"{base}/userinfo", headers={'Authorization': f'Bearer {access_token}'})
    assert ui.status_code == 200
    ui_json = ui.json()
    assert ui_json.get('email') == 'alice'


def test_client_credentials_flow(running_server):
    base = running_server

    # Request token using client credentials and scope containing roles
    data = {
        'grant_type': 'client_credentials',
        'scope': 'roles:admin,service',
        'email': 'service@example.com',
    }
    r = requests.post(f"{base}/token", auth=(provider.CLIENT_ID, provider.CLIENT_SECRET), data=data)
    assert r.status_code == 200
    tok = r.json().get('access_token')
    assert tok

    decoded = jwt.decode(
        tok, provider.RSA_PUBLIC_KEY, algorithms=['RS256'],
        audience=provider.CLIENT_ID
    )
    assert decoded.get('aud') == provider.CLIENT_ID
    # roles claim may be in the configured ROLES_CLAIM
    roles = decoded.get(provider.ROLES_CLAIM, [])
    assert 'admin' in roles or 'service' in roles


def test_test_token_endpoint(running_server):
    base = running_server

    r = requests.get(f"{base}/test-token/bob?groups=admin,dev")
    assert r.status_code == 200
    tok = r.json().get('access_token')
    assert tok
    decoded = jwt.decode(
        tok, provider.RSA_PUBLIC_KEY, algorithms=['RS256'],
        audience=provider.CLIENT_ID
    )
    assert decoded.get('sub') == 'bob'
    assert decoded.get('aud') == provider.CLIENT_ID  # default when no client_id in query
    assert decoded.get('groups') == ['admin', 'dev']

    # Optional client_id query param sets aud
    r2 = requests.get(f"{base}/test-token/carol?groups=user&client_id=my-app")
    assert r2.status_code == 200
    decoded2 = jwt.decode(
        r2.json()['access_token'], provider.RSA_PUBLIC_KEY, algorithms=['RS256'],
        audience='my-app'
    )
    assert decoded2.get('aud') == 'my-app'
    assert decoded2.get('sub') == 'carol'


def test_device_code_flow(running_server):
    base = running_server

    r = requests.post(
        f"{base}/device",
        data={"client_id": provider.CLIENT_ID, "client_secret": provider.CLIENT_SECRET},
    )
    assert r.status_code == 200
    body = r.json()
    device_code = body["device_code"]
    user_code = body["user_code"]
    assert body.get("verification_uri") == f"{base}/device/verify"
    assert "user_code=" in body.get("verification_uri_complete", "")

    pending = requests.post(
        f"{base}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": provider.CLIENT_ID,
            "client_secret": provider.CLIENT_SECRET,
        },
    )
    assert pending.status_code == 400
    assert pending.json().get("error") == "authorization_pending"

    ok = requests.post(
        f"{base}/device/verify",
        data={"user_code": user_code, "username": "devuser", "roles": "admin,dev"},
    )
    assert ok.status_code == 200

    token_resp = requests.post(
        f"{base}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": provider.CLIENT_ID,
            "client_secret": provider.CLIENT_SECRET,
        },
    )
    assert token_resp.status_code == 200
    access = token_resp.json()["access_token"]
    decoded = jwt.decode(
        access, provider.RSA_PUBLIC_KEY, algorithms=["RS256"], audience=provider.CLIENT_ID
    )
    assert decoded.get("sub") == "devuser"
    assert decoded.get("aud") == provider.CLIENT_ID

