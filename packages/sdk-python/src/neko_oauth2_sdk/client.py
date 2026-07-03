import base64
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
import requests
from jwt import PyJWKClient

from .discovery import DiscoveryDocument, fetch_discovery_document
from .pkce import generate_code_challenge, generate_code_verifier, generate_state


class NekoAuthError(Exception):
    pass


@dataclass
class AuthorizationRequest:
    url: str
    state: str
    code_verifier: str


@dataclass
class TokenSet:
    access_token: str
    token_type: str = "Bearer"
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: Optional[str] = None


def _map_token_response(body: Dict[str, Any]) -> TokenSet:
    return TokenSet(
        access_token=body["access_token"],
        token_type=body.get("token_type", "Bearer"),
        id_token=body.get("id_token"),
        refresh_token=body.get("refresh_token"),
        expires_in=body.get("expires_in"),
        scope=body.get("scope"),
    )


class NekoAuthClient:
    """A thin OIDC relying-party client for NekoOAuth2Server. Same shape as
    the TypeScript SDK (@nekosunevr/oauth2-sdk) -- see its README for the
    full integration story; this is a straight port, not a different design.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        client_secret: Optional[str] = None,
        scope: str = "openid profile email",
    ):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._discovery: Optional[DiscoveryDocument] = None
        self._jwk_client: Optional[PyJWKClient] = None

    def _ensure_discovery(self) -> DiscoveryDocument:
        if self._discovery is None:
            self._discovery = fetch_discovery_document(self.issuer)
            self._jwk_client = PyJWKClient(self._discovery.jwks_uri)
        return self._discovery

    def create_authorization_request(
        self, scope: Optional[str] = None, extra_params: Optional[Dict[str, str]] = None
    ) -> AuthorizationRequest:
        discovery = self._ensure_discovery()
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        state = generate_state()

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": scope or self.scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if extra_params:
            params.update(extra_params)

        url = f"{discovery.authorization_endpoint}?{urllib.parse.urlencode(params)}"
        return AuthorizationRequest(url=url, state=state, code_verifier=code_verifier)

    def _token_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.client_secret:
            basic = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        return headers

    def _token_request(self, data: Dict[str, str]) -> TokenSet:
        discovery = self._ensure_discovery()
        res = requests.post(discovery.token_endpoint, data=data, headers=self._token_headers(), timeout=10)
        body = res.json()
        if not res.ok:
            raise NekoAuthError(
                f"token request failed: {body.get('error', res.status_code)} {body.get('error_description', '')}".strip()
            )
        return _map_token_response(body)

    def exchange_code(self, code: str, code_verifier: str) -> TokenSet:
        return self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": code_verifier,
            }
        )

    def refresh_token(self, refresh_token: str) -> TokenSet:
        return self._token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.client_id}
        )

    def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """Verifies signature, issuer, and audience against the server's
        real JWKS -- never trust an unverified id_token."""
        discovery = self._ensure_discovery()
        assert self._jwk_client is not None
        signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)
        return jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=discovery.issuer,
        )

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        discovery = self._ensure_discovery()
        res = requests.get(
            discovery.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}, timeout=10
        )
        if not res.ok:
            raise NekoAuthError(f"userinfo request failed ({res.status_code})")
        return res.json()
