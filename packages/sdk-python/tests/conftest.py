import hashlib
import json
import secrets
import threading
import urllib.parse
from base64 import urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

CLIENT_ID = "test-client"
REDIRECT_URI = "http://localhost:3000/callback"
KID = "test-key-1"


def b64url(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


class MockOidcState:
    """Mutable state shared between a test and the mock server's handler."""

    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.issued_codes = {}  # code -> {code_challenge, sub}
        self.issued_refresh_token = None
        self.base_url = None


def _make_handler(state: MockOidcState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # silence default request logging
            pass

        def _send_json(self, status: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)

            if parsed.path == "/.well-known/openid-configuration":
                self._send_json(
                    200,
                    {
                        "issuer": state.base_url,
                        "authorization_endpoint": f"{state.base_url}/authorize",
                        "token_endpoint": f"{state.base_url}/token",
                        "userinfo_endpoint": f"{state.base_url}/userinfo",
                        "jwks_uri": f"{state.base_url}/jwks",
                    },
                )
                return

            if parsed.path == "/jwks":
                jwk = json.loads(RSAAlgorithm.to_jwk(state.public_key))
                jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
                self._send_json(200, {"keys": [jwk]})
                return

            if parsed.path == "/userinfo":
                auth = self.headers.get("Authorization")
                if auth == "Bearer access-for-test-user":
                    self._send_json(200, {"sub": "test-user", "name": "Test User", "email": "test-user@example.com"})
                else:
                    self._send_json(401, {"error": "invalid_token"})
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if urllib.parse.urlparse(self.path).path != "/token":
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = urllib.parse.parse_qs(body)
            grant_type = params.get("grant_type", [None])[0]

            if grant_type == "authorization_code":
                code = params.get("code", [""])[0]
                verifier = params.get("code_verifier", [""])[0]
                issued = state.issued_codes.get(code)
                if not issued:
                    self._send_json(400, {"error": "invalid_grant", "error_description": "unknown code"})
                    return
                computed_challenge = b64url(hashlib.sha256(verifier.encode()).digest())
                if computed_challenge != issued["code_challenge"]:
                    self._send_json(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                    return
                del state.issued_codes[code]
                state.issued_refresh_token = secrets.token_hex(16)
                id_token = jwt.encode(
                    {"sub": issued["sub"], "iss": state.base_url, "aud": CLIENT_ID},
                    state.private_key,
                    algorithm="RS256",
                    headers={"kid": KID},
                )
                self._send_json(
                    200,
                    {
                        "access_token": f"access-for-{issued['sub']}",
                        "id_token": id_token,
                        "refresh_token": state.issued_refresh_token,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "openid profile email",
                    },
                )
                return

            if grant_type == "refresh_token":
                if params.get("refresh_token", [None])[0] != state.issued_refresh_token:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                self._send_json(200, {"access_token": "refreshed-access-token", "expires_in": 3600, "token_type": "Bearer"})
                return

            self._send_json(400, {"error": "unsupported_grant_type"})

    return Handler


@pytest.fixture
def mock_server():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    state = MockOidcState(private_key)
    handler = _make_handler(state)
    server = HTTPServer(("127.0.0.1", 0), handler)
    state.base_url = f"http://127.0.0.1:{server.server_port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        thread.join(timeout=5)


def issue_code(state: MockOidcState, code_verifier: str, sub: str = "test-user") -> str:
    code = secrets.token_hex(8)
    challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
    state.issued_codes[code] = {"code_challenge": challenge, "sub": sub}
    return code
