#!/usr/bin/env python3
"""
Standalone OIDC Provider Server

Run this server before starting the gateway when testing with OIDC.
The gateway can then validate tokens against this server.
"""

import json
import jwt
import os
import sys
import secrets
import logging
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, unquote
from jinja2 import Environment, FileSystemLoader, select_autoescape

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
# Optional base path (when the app is mounted at a subpath behind a reverse proxy)
BASE_PATH = os.getenv('BASE_PATH', '')
if BASE_PATH:
    # normalize: ensure leading slash, no trailing slash (unless root)
    if not BASE_PATH.startswith('/'):
        BASE_PATH = '/' + BASE_PATH
    if BASE_PATH.endswith('/') and BASE_PATH != '/':
        BASE_PATH = BASE_PATH.rstrip('/')

# Store authorization codes temporarily (in production, use Redis or similar)
AUTH_CODES = {}
# Store access token data (username, roles) for /userinfo endpoint
TOKEN_DATA = {}

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
        elif parsed_path.path == '/authorize':
            self.handle_authorize_post()
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

        logger.info(f"Authorization request from {client_ip} - client_id: {client_id}, response_type: {response_type}")

        if not redirect_uri:
            logger.error(f"Missing redirect_uri in authorization request from {client_ip}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
            return
        
        # Try to prefill userinfo from cookie if present
        saved_userinfo = None
        cookie_header = self.headers.get('Cookie', '')
        if cookie_header:
            # simple cookie parse
            for part in cookie_header.split(';'):
                kv = part.strip()
                if kv.startswith('mock_oidc_userinfo='):
                    try:
                        saved_userinfo = unquote(kv.split('=', 1)[1])
                    except Exception:
                        saved_userinfo = None
                    break

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

            # Generate authorization code
            auth_code = secrets.token_urlsafe(32)

            # Store code with associated data (expires in 5 minutes)
            AUTH_CODES[auth_code] = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'code_challenge': code_challenge,
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
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
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

            # Validate PKCE code_verifier
            code_verifier = params.get('code_verifier', [''])[0]
            stored_challenge = code_data.get('code_challenge', '')

            if stored_challenge and code_verifier:
                # Compute expected challenge from verifier
                import hashlib
                import base64
                expected_challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                ).decode().rstrip('=')

                if expected_challenge != stored_challenge:
                    logger.error(f"PKCE validation failed from {client_ip}: expected {expected_challenge}, got {stored_challenge}")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "invalid_grant"}).encode())
                    return
            elif stored_challenge:
                logger.error(f"PKCE validation failed from {client_ip}: missing code_verifier")
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
            logger.info(f"Token issued for {user_email} from {client_ip} - roles: {user_roles}")

        elif grant_type == 'client_credentials':
            # Handle client credentials flow
            logger.info(f"Client credentials token request from {client_ip}")

            # Validate client credentials
            auth_header = self.headers.get('Authorization', '')

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

            logger.info(f"Client credentials token issued for {user_email} from {client_ip} - roles: {user_roles}")

        else:
            logger.error(f"Unsupported grant type from {client_ip}: {grant_type}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unsupported_grant_type"}).encode())
            return
        
        # Generate JWT token
        payload = {
            "iss": ISSUER,
            "sub": user_email,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "email": user_email,
            ROLES_CLAIM: user_roles,
        }

        # Add any custom claims
        payload.update(custom_claims)

        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

        # Store token data for /userinfo endpoint
        TOKEN_DATA[token] = {
            'username': user_email,
            'email': user_email,
            'roles': user_roles,
            'sub': user_email,
            'expires': datetime.now(timezone.utc) + timedelta(hours=1)
        }

        # Add custom claims to token data
        TOKEN_DATA[token].update(custom_claims)

        logger.info(f"Token generated for {user_email} from {client_ip} - token_id: {token[:20]}...")

        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": token,
        }

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

        # Decode and validate JWT token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
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

        jwks = {
            "keys": []
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

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
        
        # Generate token with specified groups
        now = datetime.now(timezone.utc)
        payload = {
            "iss": ISSUER,
            "sub": username,
            "email": username,
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "groups": groups  # OIDC standard claim; use SCIM group IDs
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        # Store token data for /userinfo endpoint
        TOKEN_DATA[token] = {
            'username': username,
            'roles': ["admin", "user", "developer"],
            'expires': now + timedelta(hours=1)
        }
        
        response = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600
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

    for code, data in AUTH_CODES.items():
        if now > data['expires']:
            expired_codes.append(code)

    for token, data in TOKEN_DATA.items():
        if now > data['expires']:
            expired_tokens.append(token)

    for code in expired_codes:
        del AUTH_CODES[code]

    for token in expired_tokens:
        del TOKEN_DATA[token]

    if expired_codes or expired_tokens:
        logger.info(f"Cleaned up {len(expired_codes)} expired auth codes and {len(expired_tokens)} expired tokens")

def main():
    """Start the OIDC Provider server"""
    logger.info("🔧 Starting OIDC Provider Server")
    logger.info("=" * 50)
    logger.info(f"Port: {PORT}")
    logger.info(f"Issuer: {ISSUER}")
    logger.info(f"Client ID: {CLIENT_ID}")
    logger.info(f"Client Secret: {CLIENT_SECRET}")
    logger.info(f"Roles Claim: {ROLES_CLAIM}")
    logger.info("=" * 50)
    logger.info(f"Discovery: {ISSUER}/.well-known/openid-configuration")
    logger.info(f"Token: {ISSUER}/token")
    logger.info(f"UserInfo: {ISSUER}/userinfo")
    logger.info(f"JWKS: {ISSUER}/jwks")
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
