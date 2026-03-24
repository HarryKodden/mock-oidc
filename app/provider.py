#!/usr/bin/env python3
"""
Standalone OIDC Provider Server

Run this server before starting the gateway when testing with OIDC.
The gateway can then validate tokens against this server.
"""

import base64
import hashlib
import json
import re
import uuid
import jwt
import os
import sys
import secrets
import logging
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, unquote
from jinja2 import Environment, FileSystemLoader, select_autoescape

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

PORT = 8888
JWT_SECRET = os.getenv('SECRET', "test-jwt-secret-key-do-not-use-in-production")
ISSUER = os.getenv('ISSUER', f"http://localhost:{PORT}")
CLIENT_ID = os.getenv('CLIENT_ID', "test-client")
CLIENT_SECRET = os.getenv('CLIENT_SECRET', "test-secret")
ROLES_CLAIM = os.getenv('ROLES_CLAIM', 'groups')
STRICT_CLIENT_AUTH = os.getenv('STRICT_CLIENT_AUTH', 'true').lower() in ('1','true','yes')
# Optional base path (when the app is mounted at a subpath behind a reverse proxy)
BASE_PATH = os.getenv('BASE_PATH', '')
if BASE_PATH:
    # normalize: ensure leading slash, no trailing slash (unless root)
    if not BASE_PATH.startswith('/'):
        BASE_PATH = '/' + BASE_PATH
    if BASE_PATH.endswith('/') and BASE_PATH != '/':
        BASE_PATH = BASE_PATH.rstrip('/')

# RFC 8628 device flow: poll interval (seconds); set to 0 in tests to skip slow_down
DEVICE_POLL_INTERVAL = int(os.getenv('DEVICE_POLL_INTERVAL', '5'))
DEVICE_EXPIRES_SEC = int(os.getenv('DEVICE_EXPIRES_SEC', '600'))
ACCESS_TOKEN_TTL_SEC = int(os.getenv('ACCESS_TOKEN_TTL_SEC', '3600'))
REFRESH_TOKEN_TTL_SEC = int(os.getenv('REFRESH_TOKEN_TTL_SEC', str(7 * 24 * 3600)))


def _normalize_user_code(code: str) -> str:
    """Normalize user code for lookup (case-insensitive, ignore hyphen/spaces)."""
    return re.sub(r'[\s-]+', '', (code or '').upper())


def _generate_user_code() -> str:
    """Human-readable user code (RFC 8628-style unambiguous charset)."""
    alphabet = 'BCDFGHJKLMNPQRSTVWXZ2356789'
    a = ''.join(secrets.choice(alphabet) for _ in range(4))
    b = ''.join(secrets.choice(alphabet) for _ in range(4))
    return f'{a}-{b}'


def _verify_pkce(stored_challenge: str, stored_method: str, code_verifier: str) -> bool:
    """RFC 7636: check code_verifier against stored code_challenge for S256 or plain."""
    if not stored_challenge or not code_verifier:
        return False
    m = (stored_method or "S256").upper()
    if m == "S256":
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        return expected == stored_challenge
    if m == "PLAIN":
        return code_verifier == stored_challenge
    return False


def _int_to_base64url(i: int) -> str:
    """Encode a positive integer as base64url (JWK n/e)."""
    byt = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    return base64.urlsafe_b64encode(byt).decode().rstrip('=')


def _load_rsa_key_and_jwks():
    """Load or generate RSA key pair and build JWKS with x5c. Returns (private_key_pem, public_key, jwks_keys)."""
    private_key = None
    cert_pem = None

    # Optional: load private key from env (path or PEM)
    key_src = os.getenv('OIDC_RSA_PRIVATE_KEY', '').strip()
    if key_src:
        if os.path.isfile(key_src):
            with open(key_src, 'rb') as f:
                key_pem = f.read()
        else:
            key_pem = key_src.encode() if isinstance(key_src, str) else key_src
        private_key = serialization.load_pem_private_key(key_pem, password=None)

    # Optional: load cert for x5c (path or PEM)
    cert_src = os.getenv('OIDC_X509_CERT', '').strip()
    if cert_src:
        if os.path.isfile(cert_src):
            with open(cert_src, 'rb') as f:
                cert_pem = f.read()
        else:
            cert_pem = cert_src.encode() if isinstance(cert_src, str) else cert_src

    if private_key is None:
        # Generate RSA key and self-signed cert for x5c
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "mock-oidc"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    kid = "mock-oidc-rs256"

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }
    if cert_pem:
        # x5c: array of base64-encoded DER certs (use first cert from PEM)
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        der = cert_obj.public_bytes(serialization.Encoding.DER)
        jwk["x5c"] = [base64.b64encode(der).decode()]

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key_pem, public_key, [jwk]


RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, JWKS_KEYS = _load_rsa_key_and_jwks()
JWT_KEY_ID = JWKS_KEYS[0]["kid"] if JWKS_KEYS else "mock-oidc-rs256"

# Store authorization codes temporarily (in production, use Redis or similar)
AUTH_CODES = {}
# Store access token data (username, roles) for /userinfo endpoint
TOKEN_DATA = {}
# RFC 8628 device authorization: device_code -> grant record
DEVICE_GRANTS = {}
# normalized user_code -> device_code (pending grants only)
USER_CODE_INDEX = {}
# opaque refresh_token -> session (authorization_code / device_code / refresh rotation)
REFRESH_TOKENS = {}

# Jinja2 templates environment
_TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
TEMPLATES = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(['html', 'xml'])
)

class OIDCHandler(BaseHTTPRequestHandler):
    """OIDC provider HTTP handler"""

    def log_message(self, format, *args):
        """Log requests to stdout with INFO level"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.info(f"{self.command} {self.path} - {client_ip} - {format % args}")

    def log_error(self, format, *args):
        """Log errors with ERROR level"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.error(f"{self.command} {self.path} - {client_ip} - {format % args}")

    def handle(self):
        """Handle request with error catching"""
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Client disconnected - this is normal, don't log scary tracebacks
            client_ip = self.client_address[0] if self.client_address else 'unknown'
            logger.debug(f"Client {client_ip} disconnected during request")
        except Exception as e:
            client_ip = self.client_address[0] if self.client_address else 'unknown'
            logger.error(f"Unexpected error handling request from {client_ip}: {e}", exc_info=True)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.info(f"GET {parsed_path.path} from {client_ip}")

        # Support optional BASE_PATH prefix (strip it for routing)
        orig_path = parsed_path.path
        if BASE_PATH and orig_path.startswith(BASE_PATH):
            routed_path = orig_path[len(BASE_PATH):] or '/'
            # build a new parsed_path-like object for routing convenience
            parsed_path = parsed_path._replace(path=routed_path)
        else:
            routed_path = orig_path

        # Serve static files from /static/* (also handle when mounted under BASE_PATH)
        static_prefix = f"{BASE_PATH}/static" if BASE_PATH else '/static'
        if orig_path.startswith(static_prefix):
            try:
                # Static files live in project_root/static
                static_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
                # compute file path using orig_path (so prefix is stripped)
                rel = orig_path[len(static_prefix):]
                if rel.startswith('/'):
                    rel = rel[1:]
                file_path = os.path.join(static_root, 'static', rel)
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as fh:
                        self.send_response(200)
                        # Minimal content-type guessing
                        if file_path.endswith('.css'):
                            self.send_header('Content-Type', 'text/css')
                        else:
                            self.send_header('Content-Type', 'application/octet-stream')
                        self.end_headers()
                        self.wfile.write(fh.read())
                        return
            except Exception:
                pass

        # Route using the (possibly stripped) parsed_path
        if parsed_path.path == '/.well-known/openid-configuration':
            self.send_discovery_document()
        elif parsed_path.path == '/authorize':
            self.handle_authorize()
        elif parsed_path.path == '/userinfo':
            self.send_userinfo()
        elif parsed_path.path == '/jwks':
            self.send_jwks()
        elif parsed_path.path == '/device/verify':
            self.handle_device_verify_get()
        elif parsed_path.path.startswith('/test-token/'):
            # pass the full request path (including query string) so send_test_token
            # can parse query params correctly; translate path to routed form
            # rebuild a path that includes query but uses the routed path
            # orig_self_path contains original request (possibly with BASE_PATH)
            orig_self_path = self.path
            # if BASE_PATH is set, remove it from the original path before passing
            if BASE_PATH and orig_self_path.startswith(BASE_PATH):
                trimmed = orig_self_path[len(BASE_PATH):]
            else:
                trimmed = orig_self_path
            self.send_test_token(trimmed)
        else:
            logger.warning(f"404 Not Found: {parsed_path.path} from {client_ip}")
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "not_found"}).encode())

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.info(f"POST {parsed_path.path} from {client_ip}")
        # strip BASE_PATH for routing if present
        orig_path = parsed_path.path
        if BASE_PATH and orig_path.startswith(BASE_PATH):
            routed_path = orig_path[len(BASE_PATH):] or '/'
            parsed_path = parsed_path._replace(path=routed_path)

        if parsed_path.path == '/token':
            self.send_token()
        elif parsed_path.path == '/introspect':
            self.send_introspect()
        elif parsed_path.path == '/authorize':
            self.handle_authorize_post()
        elif parsed_path.path == '/device':
            self.send_device_authorization()
        elif parsed_path.path == '/device/verify':
            self.handle_device_verify_post()
        else:
            logger.warning(f"404 Not Found: {parsed_path.path} from {client_ip}")
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "not_found"}).encode())
    
    def handle_authorize(self):
        """Handle authorization request - show login form"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        client_ip = self.client_address[0] if self.client_address else 'unknown'

        client_id = params.get('client_id', [''])[0]
        redirect_uri = params.get('redirect_uri', [''])[0]
        state = params.get('state', [''])[0]
        response_type = params.get('response_type', [''])[0]
        code_challenge = params.get('code_challenge', [''])[0]
        code_challenge_method = params.get('code_challenge_method', [''])[0]
        if code_challenge and not code_challenge_method:
            code_challenge_method = "S256"

        logger.info(f"Authorization request from {client_ip} - client_id: {client_id}, response_type: {response_type}")

        if not redirect_uri:
            logger.error(f"Missing redirect_uri in authorization request from {client_ip}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
            return
        
        # Try to prefill userinfo from cookie if present; otherwise generate defaults
        saved_userinfo = None
        cookie_header = self.headers.get('Cookie', '')
        if cookie_header:
            # simple cookie parse
            for part in cookie_header.split(';'):
                kv = part.strip()
                if kv.startswith('mock_oidc_userinfo='):
                    try:
                        cookie_val = unquote(kv.split('=', 1)[1])
                        # try to parse JSON cookie into an object
                        try:
                            parsed = json.loads(cookie_val)
                            if isinstance(parsed, dict):
                                saved_userinfo = parsed
                            else:
                                saved_userinfo = None
                        except Exception:
                            saved_userinfo = None
                    except Exception:
                        saved_userinfo = None
                    break

        # If no saved userinfo, create sensible defaults with a generated sub UUID
        if not saved_userinfo:
            saved_userinfo = {
                'sub': str(uuid.uuid4()),
                'email': 'user@example.com',
                'groups': ['developer']
            }

        # Render authorize template
        try:
            template = TEMPLATES.get_template('authorize.html')
            html = template.render(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                response_type=response_type,
                code_challenge=code_challenge,
                base_path=BASE_PATH,
                saved_userinfo=saved_userinfo,
            )
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        except Exception as e:
            # Log the exception to aid debugging, then fallback to minimal inline form
            logger.exception("Failed to render 'authorize.html' template")
            html = f"<html><body><form method=\"POST\" action=\"{BASE_PATH + '/authorize' if BASE_PATH else '/authorize'}\"><input name=\"client_id\" value=\"{client_id}\"/></form></body></html>"
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
    
    def handle_authorize_post(self):
        """Handle login form submission"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'

        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        post_params = parse_qs(post_data)

        # Read free-form userinfo JSON (preferred) or fall back to legacy username/roles
        userinfo_text = post_params.get('userinfo', [''])[0]
        username = ''
        roles = []
        custom_claims = {}

        if userinfo_text:
            try:
                parsed = json.loads(userinfo_text)
                if isinstance(parsed, dict):
                    custom_claims = parsed.copy()
                    # extract username/email if present
                    username = parsed.get('email') or parsed.get('sub') or ''
                    # extract groups/roles if present
                    groups = parsed.get('groups') or parsed.get('roles')
                    if isinstance(groups, list):
                        roles = groups
                    elif isinstance(groups, str):
                        roles = [g.strip() for g in groups.split(',') if g.strip()]
                else:
                    # invalid structure
                    logger.warning(f"Invalid userinfo JSON structure from {client_ip}")
            except Exception as e:
                logger.warning(f"Failed to parse userinfo JSON from {client_ip}: {e}")

        # legacy fallback: support username + roles fields for compatibility
        if not userinfo_text:
            username = post_params.get('username', [''])[0]
            roles_input = post_params.get('roles', ['admin'])[0]
            roles = [role.strip() for role in roles_input.split(',') if role.strip()]
            if not roles:
                roles = ['user']

        logger.info(f"Login attempt from {client_ip} - username: {username}, roles: {roles}")

        # Require at least a username/sub/email
        if username:
            # Get OAuth parameters from POST body (hidden form fields)
            client_id = post_params.get('client_id', [''])[0]
            redirect_uri = post_params.get('redirect_uri', [''])[0]
            state = post_params.get('state', [''])[0]
            code_challenge = post_params.get('code_challenge', [''])[0]
            code_challenge_method = post_params.get('code_challenge_method', [''])[0]
            if code_challenge and not code_challenge_method:
                code_challenge_method = "S256"

            # Generate authorization code
            auth_code = secrets.token_urlsafe(32)

            # Store code with associated data (expires in 5 minutes)
            AUTH_CODES[auth_code] = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'username': username,
                'roles': roles,
                'custom_claims': custom_claims,
                'expires': datetime.now(timezone.utc) + timedelta(minutes=5)
            }

            logger.info(f"Login successful for {username} from {client_ip} - roles: {roles}, redirecting to: {redirect_uri}")

            # Redirect back to the application with the code
            redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"

            # Set cookie with userinfo JSON for SSO-like prefill (encode safely)
            try:
                cookie_value = quote(json.dumps(custom_claims)) if custom_claims else quote(json.dumps({"sub": username, "email": username, "groups": roles}))
                cookie_path = BASE_PATH or '/'
                self.send_response(302)
                self.send_header('Location', redirect_url)
                self.send_header('Set-Cookie', f"mock_oidc_userinfo={cookie_value}; Path={cookie_path}; HttpOnly; SameSite=Lax")
                self.end_headers()
            except Exception:
                # Fallback to redirect without cookie if something goes wrong
                self.send_response(302)
                self.send_header('Location', redirect_url)
                self.end_headers()
        else:
            logger.warning(f"Login failed from {client_ip} - username is required")
            # Render error template if available
            try:
                template = TEMPLATES.get_template('error.html')
                html = template.render(base_path=BASE_PATH)
                self.send_response(401)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
                return
            except Exception:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "username_required"}).encode())
                return

    def _send_json_error(self, status: int, body: dict):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def send_device_authorization(self):
        """RFC 8628: POST /device — issue device_code and user_code."""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        client_id = params.get('client_id', [''])[0]
        if not client_id:
            logger.error(f"Device authorization missing client_id from {client_ip}")
            self._send_json_error(400, {"error": "invalid_request", "error_description": "client_id required"})
            return

        if STRICT_CLIENT_AUTH:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                try:
                    credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                    cid, csec = credentials.split(':', 1)
                    if cid != CLIENT_ID or csec != CLIENT_SECRET:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return
                except Exception:
                    self._send_json_error(401, {"error": "invalid_client"})
                    return
            else:
                cid = params.get('client_id', [''])[0]
                csec = params.get('client_secret', [''])[0]
                if cid != CLIENT_ID or csec != CLIENT_SECRET:
                    self._send_json_error(401, {"error": "invalid_client"})
                    return

        user_code = None
        for _ in range(32):
            candidate = _generate_user_code()
            norm = _normalize_user_code(candidate)
            if norm not in USER_CODE_INDEX:
                user_code = candidate
                break
        if not user_code:
            logger.error(f"Could not allocate user_code from {client_ip}")
            self._send_json_error(500, {"error": "server_error"})
            return

        device_code = secrets.token_urlsafe(48)
        expires = datetime.now(timezone.utc) + timedelta(seconds=DEVICE_EXPIRES_SEC)
        poll_iv = DEVICE_POLL_INTERVAL if DEVICE_POLL_INTERVAL > 0 else 5

        DEVICE_GRANTS[device_code] = {
            'user_code': user_code,
            'client_id': client_id,
            'scope': params.get('scope', [''])[0],
            'expires': expires,
            'interval': DEVICE_POLL_INTERVAL,
            'last_poll_at': None,
            'status': 'pending',
            'username': None,
            'roles': [],
            'custom_claims': {},
        }
        USER_CODE_INDEX[_normalize_user_code(user_code)] = device_code

        verification_uri = f"{ISSUER}/device/verify"
        verification_uri_complete = f"{verification_uri}?user_code={quote(user_code)}"
        body = {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": DEVICE_EXPIRES_SEC,
            "interval": poll_iv,
        }
        logger.info(f"Device authorization issued to {client_ip} user_code={user_code}")
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def handle_device_verify_get(self):
        """Browser: show verification form (RFC 8628 user interaction)."""
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        params = parse_qs(parsed_path.query)
        user_code_prefill = params.get('user_code', [''])[0]

        saved_userinfo = None
        cookie_header = self.headers.get('Cookie', '')
        if cookie_header:
            for part in cookie_header.split(';'):
                kv = part.strip()
                if kv.startswith('mock_oidc_userinfo='):
                    try:
                        cookie_val = unquote(kv.split('=', 1)[1])
                        try:
                            parsed = json.loads(cookie_val)
                            if isinstance(parsed, dict):
                                saved_userinfo = parsed
                        except Exception:
                            saved_userinfo = None
                    except Exception:
                        saved_userinfo = None
                    break

        if not saved_userinfo:
            saved_userinfo = {
                'sub': str(uuid.uuid4()),
                'email': 'user@example.com',
                'groups': ['developer']
            }

        try:
            template = TEMPLATES.get_template('device.html')
            html = template.render(
                base_path=BASE_PATH,
                user_code_prefill=user_code_prefill,
                saved_userinfo=saved_userinfo,
            )
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
        except Exception as e:
            logger.exception("Failed to render device.html")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>device verify error</body></html>")

    def handle_device_verify_post(self):
        """Approve a pending device grant after user signs in."""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        post_params = parse_qs(post_data)

        raw_code = post_params.get('user_code', [''])[0]
        norm = _normalize_user_code(raw_code)
        device_code = USER_CODE_INDEX.get(norm)
        if not device_code or device_code not in DEVICE_GRANTS:
            logger.warning(f"Device verify unknown user_code from {client_ip}")
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>Invalid or expired user code.</body></html>")
            return

        grant = DEVICE_GRANTS[device_code]
        if datetime.now(timezone.utc) > grant['expires']:
            del USER_CODE_INDEX[norm]
            del DEVICE_GRANTS[device_code]
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>Invalid or expired user code.</body></html>")
            return

        if grant['status'] != 'pending':
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>This code was already used.</body></html>")
            return

        userinfo_text = post_params.get('userinfo', [''])[0]
        username = ''
        roles = []
        custom_claims = {}

        if userinfo_text:
            try:
                parsed = json.loads(userinfo_text)
                if isinstance(parsed, dict):
                    custom_claims = parsed.copy()
                    username = parsed.get('email') or parsed.get('sub') or ''
                    groups = parsed.get('groups') or parsed.get('roles')
                    if isinstance(groups, list):
                        roles = groups
                    elif isinstance(groups, str):
                        roles = [g.strip() for g in groups.split(',') if g.strip()]
            except Exception as e:
                logger.warning(f"Failed to parse userinfo JSON from {client_ip}: {e}")

        if not userinfo_text:
            username = post_params.get('username', [''])[0]
            roles_input = post_params.get('roles', ['admin'])[0]
            roles = [role.strip() for role in roles_input.split(',') if role.strip()]
            if not roles:
                roles = ['user']

        if not username:
            self.send_response(401)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body>Username / claims required.</body></html>")
            return

        grant['status'] = 'approved'
        grant['username'] = username
        grant['roles'] = roles
        grant['custom_claims'] = custom_claims
        del USER_CODE_INDEX[norm]

        try:
            cookie_value = quote(json.dumps(custom_claims)) if custom_claims else quote(json.dumps({"sub": username, "email": username, "groups": roles}))
            cookie_path = BASE_PATH or '/'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Set-Cookie', f"mock_oidc_userinfo={cookie_value}; Path={cookie_path}; HttpOnly; SameSite=Lax")
            self.end_headers()
            self.wfile.write(
                b"<html><body><p>Device authorized. You may close this window.</p></body></html>"
            )
        except Exception:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(
                b"<html><body><p>Device authorized. You may close this window.</p></body></html>"
            )
        logger.info(f"Device grant approved for user {username} from {client_ip}")
    
    def send_discovery_document(self):
        """Send OpenID Connect discovery document"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.info(f"Discovery document requested from {client_ip}")

        discovery = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/jwks",
            "device_authorization_endpoint": f"{ISSUER}/device",
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "introspection_endpoint": f"{ISSUER}/introspect",
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256", "plain"],
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(discovery, indent=2).encode())
    
    def send_token(self):
        """Send access token and ID token"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'

        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)

        grant_type = params.get('grant_type', [''])[0]
        logger.info(f"Token request from {client_ip} - grant_type: {grant_type}")

        issue_refresh = False

        if grant_type == 'authorization_code':
            # Handle authorization code flow
            code = params.get('code', [''])[0]

            if code not in AUTH_CODES:
                logger.error(f"Invalid authorization code from {client_ip}: {code[:10]}...")
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                return

            code_data = AUTH_CODES[code]

            # Check if code is expired
            if datetime.now(timezone.utc) > code_data['expires']:
                del AUTH_CODES[code]
                logger.warning(f"Expired authorization code from {client_ip}: {code[:10]}...")
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "expired_token"}).encode())
                return

            # Validate PKCE (RFC 7636) when code_challenge was used at authorize
            code_verifier = params.get('code_verifier', [''])[0]
            stored_challenge = code_data.get('code_challenge', '')
            stored_method = code_data.get('code_challenge_method', '')

            if stored_challenge:
                if not code_verifier:
                    logger.error(f"PKCE validation failed from {client_ip}: missing code_verifier")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                    return
                if not _verify_pkce(stored_challenge, stored_method, code_verifier):
                    logger.error(f"PKCE validation failed from {client_ip}: verifier does not match challenge")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                    return

            # Remove used code
            del AUTH_CODES[code]

            # Set user data for authorization code
            custom_claims = code_data.get('custom_claims', {}) or {}
            user_email = code_data.get('username', '')
            # allow custom claims to override the email/sub
            if isinstance(custom_claims, dict):
                user_email = custom_claims.get('email') or custom_claims.get('sub') or user_email
            user_roles = code_data.get('roles', [''])
            audience = code_data.get('client_id', CLIENT_ID)
            logger.info(f"Token issued for {user_email} from {client_ip} - roles: {user_roles}")
            issue_refresh = True

        elif grant_type == 'client_credentials':
            # Handle client credentials flow
            logger.info(f"Client credentials token request from {client_ip}")

            # Validate client credentials
            auth_header = self.headers.get('Authorization', '')
            # If STRICT_CLIENT_AUTH is enabled, validate client_id/client_secret strictly.
            client_id = None
            client_secret = None
            if STRICT_CLIENT_AUTH:
                if not auth_header.startswith('Basic '):
                    # Check if client_id and client_secret are in form parameters
                    client_id = params.get('client_id', [''])[0]
                    client_secret = params.get('client_secret', [''])[0]

                    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
                        logger.error(f"Invalid client credentials from {client_ip} - form params")
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
                        return
                else:
                    # Decode Basic auth
                    import base64
                    try:
                        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                        client_id, client_secret = credentials.split(':', 1)

                        if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
                            logger.error(f"Invalid client credentials from {client_ip} - basic auth")
                            self.send_response(401)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Access-Control-Allow-Origin', '*')
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
                            return
                    except Exception:
                        logger.error(f"Failed to decode basic auth from {client_ip}")
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
                        return
            else:
                # permissive mode: accept any provided client_id/secret
                if auth_header.startswith('Basic '):
                    import base64
                    try:
                        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                        client_id, client_secret = credentials.split(':', 1)
                    except Exception:
                        client_id = None
                        client_secret = None
                else:
                    client_id = params.get('client_id', [''])[0]
                    client_secret = params.get('client_secret', [''])[0]

            # Set user data for client credentials
            user_email = CLIENT_ID
            user_roles = [""]
            custom_claims = {}

            # Parse all form parameters for custom claims
            for param_name, param_values in params.items():
                param_value = param_values[0] if param_values else ""

                if param_name == 'scope' and param_value:
                    # Parse scope for roles (e.g., "roles:admin,user")
                    scope_parts = param_value.split()
                    for part in scope_parts:
                        if part.startswith('roles:'):
                            user_roles = part[6:].split(',')
                            break
                elif param_name in ['grant_type', 'client_id', 'client_secret']:
                    # Skip OAuth standard parameters
                    continue
                elif param_value:
                    # Add any other parameter as a custom claim
                    custom_claims[param_name] = param_value

            # Set email from custom claims if provided, otherwise use client_id
            if 'email' in custom_claims:
                user_email = custom_claims['email']
                del custom_claims['email']  # Remove from custom claims since it's handled separately

            audience = client_id or params.get('client_id', [''])[0] or CLIENT_ID
            logger.info(f"Client credentials token issued for {user_email} from {client_ip} - roles: {user_roles}")

        elif grant_type == 'refresh_token':
            refresh_token = params.get('refresh_token', [''])[0]
            client_id = params.get('client_id', [''])[0]
            if not refresh_token or not client_id:
                self._send_json_error(400, {"error": "invalid_request", "error_description": "refresh_token and client_id required"})
                return

            if STRICT_CLIENT_AUTH:
                auth_header = self.headers.get('Authorization', '')
                if auth_header.startswith('Basic '):
                    try:
                        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                        cid, csec = credentials.split(':', 1)
                        if cid != CLIENT_ID or csec != CLIENT_SECRET:
                            self._send_json_error(401, {"error": "invalid_client"})
                            return
                    except Exception:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return
                else:
                    cid = params.get('client_id', [''])[0]
                    csec = params.get('client_secret', [''])[0]
                    if cid != CLIENT_ID or csec != CLIENT_SECRET:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return

            rec = REFRESH_TOKENS.get(refresh_token)
            now_rt = datetime.now(timezone.utc)
            if not rec:
                logger.error(f"Unknown refresh_token from {client_ip}")
                self._send_json_error(400, {"error": "invalid_grant"})
                return
            if now_rt > rec['expires']:
                del REFRESH_TOKENS[refresh_token]
                self._send_json_error(400, {"error": "invalid_grant"})
                return
            if rec.get('client_id') != client_id:
                self._send_json_error(400, {"error": "invalid_grant"})
                return

            del REFRESH_TOKENS[refresh_token]
            user_email = rec['user_email']
            user_roles = rec['user_roles']
            custom_claims = dict(rec.get('custom_claims') or {})
            audience = rec.get('audience', CLIENT_ID)
            logger.info(f"Refresh token exchanged for {user_email} from {client_ip}")
            issue_refresh = True

        elif grant_type == 'urn:ietf:params:oauth:grant-type:device_code':
            # RFC 8628 device authorization grant
            device_code = params.get('device_code', [''])[0]
            client_id = params.get('client_id', [''])[0]
            if not device_code or not client_id:
                self._send_json_error(400, {"error": "invalid_request", "error_description": "device_code and client_id required"})
                return

            if STRICT_CLIENT_AUTH:
                auth_header = self.headers.get('Authorization', '')
                if auth_header.startswith('Basic '):
                    try:
                        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                        cid, csec = credentials.split(':', 1)
                        if cid != CLIENT_ID or csec != CLIENT_SECRET:
                            self._send_json_error(401, {"error": "invalid_client"})
                            return
                    except Exception:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return
                else:
                    cid = params.get('client_id', [''])[0]
                    csec = params.get('client_secret', [''])[0]
                    if cid != CLIENT_ID or csec != CLIENT_SECRET:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return

            grant = DEVICE_GRANTS.get(device_code)
            if not grant:
                logger.error(f"Unknown device_code from {client_ip}")
                self._send_json_error(400, {"error": "invalid_grant"})
                return

            now = datetime.now(timezone.utc)
            if now > grant['expires']:
                DEVICE_GRANTS.pop(device_code, None)
                uc = grant.get('user_code', '')
                if uc:
                    USER_CODE_INDEX.pop(_normalize_user_code(uc), None)
                self._send_json_error(400, {"error": "expired_token", "error_description": "device session expired"})
                return

            if grant.get('client_id') != client_id:
                self._send_json_error(400, {"error": "invalid_grant"})
                return

            poll_iv = grant.get('interval', DEVICE_POLL_INTERVAL)
            if poll_iv and poll_iv > 0 and grant.get('last_poll_at') is not None:
                delta = (now - grant['last_poll_at']).total_seconds()
                if delta < poll_iv:
                    self._send_json_error(400, {"error": "slow_down", "error_description": "polling too frequently"})
                    return
            grant['last_poll_at'] = now

            if grant['status'] == 'pending':
                self._send_json_error(400, {"error": "authorization_pending", "error_description": "user has not yet completed authorization"})
                return
            if grant['status'] == 'denied':
                DEVICE_GRANTS.pop(device_code, None)
                self._send_json_error(400, {"error": "access_denied"})
                return

            # approved
            custom_claims = grant.get('custom_claims', {}) or {}
            user_email = grant.get('username', '')
            if isinstance(custom_claims, dict):
                user_email = custom_claims.get('email') or custom_claims.get('sub') or user_email
            user_roles = grant.get('roles', [''])
            audience = grant.get('client_id', CLIENT_ID)
            DEVICE_GRANTS.pop(device_code, None)
            logger.info(f"Device code exchanged for token for {user_email} from {client_ip}")
            issue_refresh = True

        else:
            logger.error(f"Unsupported grant type from {client_ip}: {grant_type}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unsupported_grant_type"}).encode())
            return
        
        # Generate JWT token (id_token/access_token: aud = initiating client_id)
        now_tok = datetime.now(timezone.utc)
        ttl = timedelta(seconds=ACCESS_TOKEN_TTL_SEC)
        payload = {
            "iss": ISSUER,
            "sub": user_email,
            "aud": audience,
            "exp": int((now_tok + ttl).timestamp()),
            "iat": int(now_tok.timestamp()),
            "email": user_email,
            ROLES_CLAIM: user_roles,
        }

        # Add any custom claims
        payload.update(custom_claims)

        token = jwt.encode(
            payload, RSA_PRIVATE_KEY, algorithm="RS256",
            headers={"kid": JWT_KEY_ID}
        )

        # Store token data for /userinfo endpoint
        TOKEN_DATA[token] = {
            'username': user_email,
            'email': user_email,
            'roles': user_roles,
            'sub': user_email,
            'expires': now_tok + ttl
        }

        # Add custom claims to token data
        TOKEN_DATA[token].update(custom_claims)

        logger.info(f"Token generated for {user_email} from {client_ip} - token_id: {token[:20]}...")

        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SEC,
            "id_token": token,
        }

        if issue_refresh:
            rt = secrets.token_urlsafe(48)
            cc_store = dict(custom_claims) if isinstance(custom_claims, dict) else {}
            REFRESH_TOKENS[rt] = {
                'client_id': audience,
                'audience': audience,
                'user_email': user_email,
                'user_roles': user_roles,
                'custom_claims': cc_store,
                'expires': now_tok + timedelta(seconds=REFRESH_TOKEN_TTL_SEC),
            }
            response["refresh_token"] = rt

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def send_userinfo(self):
        """Send user info"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'

        # Check for Authorization header
        auth_header = self.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            logger.error(f"Missing or invalid Authorization header from {client_ip}")
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized"}).encode())
            return

        # Extract token
        token = auth_header[7:]  # Remove 'Bearer ' prefix

        # Decode and validate JWT token (we are the issuer; signature only, no aud check)
        try:
            payload = jwt.decode(
                token, RSA_PUBLIC_KEY, algorithms=["RS256"],
                options={"verify_aud": False}
            )
            
            # Check if token is expired
            exp = payload.get('exp', 0)
            if datetime.now(timezone.utc).timestamp() > exp:
                logger.warning(f"Expired token used from {client_ip}")
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "token_expired"}).encode())
                return

            user_email = payload.get('email', '')
            logger.info(f"Userinfo request from {client_ip} for user: {user_email}")

            userinfo = {
                "sub": payload.get('sub', ''),
                "email": payload.get('email', ''),
                ROLES_CLAIM: payload.get(ROLES_CLAIM, []),
            }

            # Add any custom claims from the token
            for key, value in payload.items():
                if key not in ['iss', 'sub', 'aud', 'exp', 'iat', 'email', ROLES_CLAIM]:
                    userinfo[key] = value

        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired JWT token used from {client_ip}")
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "token_expired"}).encode())
            return
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid JWT token used from {client_ip}: {str(e)}")
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_token"}).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(userinfo).encode())
    
    def send_jwks(self):
        """Send JSON Web Key Set"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        logger.info(f"JWKS requested from {client_ip}")

        jwks = {"keys": JWKS_KEYS}

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

    def send_introspect(self):
        """RFC 7662 OAuth 2.0 Token Introspection."""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        token = params.get('token', [''])[0]
        if not token:
            self._send_json_error(400, {"error": "invalid_request", "error_description": "token required"})
            return

        if STRICT_CLIENT_AUTH:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                try:
                    credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                    cid, csec = credentials.split(':', 1)
                    if cid != CLIENT_ID or csec != CLIENT_SECRET:
                        self._send_json_error(401, {"error": "invalid_client"})
                        return
                except Exception:
                    self._send_json_error(401, {"error": "invalid_client"})
                    return
            else:
                cid = params.get('client_id', [''])[0]
                csec = params.get('client_secret', [''])[0]
                if cid != CLIENT_ID or csec != CLIENT_SECRET:
                    self._send_json_error(401, {"error": "invalid_client"})
                    return

        now = datetime.now(timezone.utc)

        if token in REFRESH_TOKENS:
            rec = REFRESH_TOKENS[token]
            if now > rec['expires']:
                body = {"active": False}
            else:
                exp = int(rec['expires'].timestamp())
                cid = rec.get('client_id') or rec.get('audience')
                body = {
                    "active": True,
                    "token_type": "refresh_token",
                    "client_id": cid,
                    "username": rec.get('user_email'),
                    "sub": rec.get('user_email'),
                    "exp": exp,
                }
        else:
            try:
                payload = jwt.decode(
                    token, RSA_PUBLIC_KEY, algorithms=["RS256"],
                    options={"verify_aud": False}
                )
                exp = int(payload.get('exp', 0))
                if now.timestamp() > exp:
                    body = {"active": False}
                else:
                    aud = payload.get('aud')
                    if isinstance(aud, list):
                        aud = aud[0] if aud else None
                    body = {
                        "active": True,
                        "token_type": "access_token",
                        "client_id": aud,
                        "username": payload.get('email') or payload.get('sub'),
                        "sub": payload.get('sub'),
                        "exp": exp,
                        "iss": payload.get('iss'),
                    }
            except jwt.InvalidTokenError:
                body = {"active": False}

        logger.info(f"Token introspection from {client_ip} active={body.get('active')}")
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def send_test_token(self, path):
        """Generate a test token for a specific user (for testing purposes)"""
        client_ip = self.client_address[0] if self.client_address else 'unknown'
        
        # Parse full path and extract username from the path component
        parsed_path = urlparse(path)
        parts = parsed_path.path.split('/')
        if len(parts) < 3:
            logger.error(f"Invalid test token path from {client_ip}: {path}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_path"}).encode())
            return

        username = parts[2]

        # Parse query parameters to get groups
        params = parse_qs(parsed_path.query)
        groups_param = params.get('groups', ['developer-group'])[0]  # Default to developer-group
        groups = [g.strip() for g in groups_param.split(',')]  # Support comma-separated groups
        
        logger.info(f"Test token requested for user '{username}' with groups {groups} from {client_ip}")
        
        # Generate token with specified groups (aud = client_id from query or default)
        now = datetime.now(timezone.utc)
        ttl = timedelta(seconds=ACCESS_TOKEN_TTL_SEC)
        aud_client = params.get('client_id', [CLIENT_ID])[0] or CLIENT_ID
        payload = {
            "iss": ISSUER,
            "sub": username,
            "aud": aud_client,
            "email": username,
            "exp": int((now + ttl).timestamp()),
            "iat": int(now.timestamp()),
            "groups": groups  # OIDC standard claim; use SCIM group IDs
        }
        
        token = jwt.encode(
            payload, RSA_PRIVATE_KEY, algorithm="RS256",
            headers={"kid": JWT_KEY_ID}
        )
        
        # Store token data for /userinfo endpoint
        TOKEN_DATA[token] = {
            'username': username,
            'roles': ["admin", "user", "developer"],
            'expires': now + ttl
        }
        
        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SEC
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

def cleanup_expired_tokens():
    """Clean up expired authorization codes and tokens"""
    now = datetime.now(timezone.utc)
    expired_codes = []
    expired_tokens = []
    expired_devices = []
    expired_refresh = []

    for code, data in AUTH_CODES.items():
        if now > data['expires']:
            expired_codes.append(code)

    for token, data in TOKEN_DATA.items():
        if now > data['expires']:
            expired_tokens.append(token)

    for device_code, data in DEVICE_GRANTS.items():
        if now > data['expires']:
            expired_devices.append(device_code)

    for rt, data in REFRESH_TOKENS.items():
        if now > data['expires']:
            expired_refresh.append(rt)

    for code in expired_codes:
        del AUTH_CODES[code]

    for token in expired_tokens:
        del TOKEN_DATA[token]

    for device_code in expired_devices:
        grant = DEVICE_GRANTS.pop(device_code, None)
        if grant and grant.get('user_code'):
            USER_CODE_INDEX.pop(_normalize_user_code(grant['user_code']), None)

    for rt in expired_refresh:
        del REFRESH_TOKENS[rt]

    if expired_codes or expired_tokens or expired_devices or expired_refresh:
        logger.info(
            f"Cleaned up {len(expired_codes)} auth codes, {len(expired_tokens)} tokens, "
            f"{len(expired_devices)} device grants, {len(expired_refresh)} refresh tokens"
        )

def main():
    """Start the OIDC Provider server"""
    logger.info("🔧 Starting OIDC Provider Server")
    logger.info("=" * 50)
    logger.info(f"Port: {PORT}")
    logger.info(f"Issuer: {ISSUER}")
    logger.info(f"Client ID: {CLIENT_ID}")
    logger.info(f"Client Secret: {CLIENT_SECRET}")
    logger.info(f"Roles Claim: {ROLES_CLAIM}")
    logger.info(f"Strict client auth: {STRICT_CLIENT_AUTH}")
    logger.info("=" * 50)
    logger.info(f"Discovery: {ISSUER}/.well-known/openid-configuration")
    logger.info(f"Token: {ISSUER}/token")
    logger.info(f"UserInfo: {ISSUER}/userinfo")
    logger.info(f"JWKS: {ISSUER}/jwks")
    logger.info(f"Introspection: {ISSUER}/introspect")
    logger.info(f"Device authorization: {ISSUER}/device")
    logger.info(f"Device verify (browser): {ISSUER}/device/verify")
    logger.info("")
    logger.info("Configure your .env with:")
    logger.info(f"  ISSUER={ISSUER}")
    logger.info(f"  CLIENT_ID={CLIENT_ID}")
    logger.info(f"  CLIENT_SECRET={CLIENT_SECRET}")
    logger.info(f"  ROLES_CLAIM={ROLES_CLAIM} (if different)")
    logger.info("")
    logger.info("Press Ctrl+C to stop...")
    logger.info("")

    try:
        server = HTTPServer(('0.0.0.0', PORT), OIDCHandler)
        logger.info("✓ Server started successfully")

        # Clean up expired tokens every 5 minutes
        import threading
        def periodic_cleanup():
            while True:
                import time
                time.sleep(300)  # 5 minutes
                cleanup_expired_tokens()

        cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
        cleanup_thread.start()
        logger.info("✓ Token cleanup thread started")

        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down OIDC Provider server...")
        server.shutdown()
        logger.info("✓ Server stopped")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
