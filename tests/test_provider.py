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

    # JWKS
    r = requests.get(f"{base}/jwks")
    assert r.status_code == 200
    assert isinstance(r.json().get('keys'), list)


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

    # Validate JWT
    decoded = jwt.decode(access_token, provider.JWT_SECRET, algorithms=['HS256'])
    assert decoded.get('sub') == 'alice'
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

    decoded = jwt.decode(tok, provider.JWT_SECRET, algorithms=['HS256'])
    # roles claim may be in the configured ROLES_CLAIM
    roles = decoded.get(provider.ROLES_CLAIM, [])
    assert 'admin' in roles or 'service' in roles


def test_test_token_endpoint(running_server):
    base = running_server

    r = requests.get(f"{base}/test-token/bob?groups=admin,dev")
    assert r.status_code == 200
    tok = r.json().get('access_token')
    assert tok
    decoded = jwt.decode(tok, provider.JWT_SECRET, algorithms=['HS256'])
    assert decoded.get('sub') == 'bob'
    assert decoded.get('groups') == ['admin', 'dev']

