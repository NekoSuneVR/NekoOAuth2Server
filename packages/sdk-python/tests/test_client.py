import urllib.parse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from neko_oauth2_sdk import NekoAuthClient, NekoAuthError

from .conftest import CLIENT_ID, KID, REDIRECT_URI, issue_code


def test_authorization_url_has_mandatory_pkce_and_fresh_state(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    first = client.create_authorization_request()
    second = client.create_authorization_request()

    parsed = urllib.parse.urlparse(first.url)
    query = urllib.parse.parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == f"{mock_server.base_url}/authorize"
    assert query["client_id"] == [CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [first.state]

    assert first.state != second.state
    assert first.code_verifier != second.code_verifier


def test_exchanges_code_verifies_id_token_and_fetches_userinfo(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    req = client.create_authorization_request()
    code = issue_code(mock_server, req.code_verifier)

    tokens = client.exchange_code(code, req.code_verifier)
    assert tokens.access_token == "access-for-test-user"
    assert tokens.id_token

    claims = client.verify_id_token(tokens.id_token)
    assert claims["sub"] == "test-user"

    profile = client.get_user_info(tokens.access_token)
    assert profile == {"sub": "test-user", "name": "Test User", "email": "test-user@example.com"}


def test_rejects_wrong_code_verifier(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    req = client.create_authorization_request()
    code = issue_code(mock_server, req.code_verifier)

    with pytest.raises(NekoAuthError, match="invalid_grant"):
        client.exchange_code(code, "a-completely-different-verifier-value")


def test_rejects_forged_id_token_signed_by_unrelated_key(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    client.create_authorization_request()  # populates discovery/jwks

    unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {"sub": "attacker", "iss": mock_server.base_url, "aud": CLIENT_ID},
        unrelated_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(Exception):
        client.verify_id_token(forged)


def test_rejects_id_token_with_wrong_audience(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    client.create_authorization_request()

    wrong_audience = jwt.encode(
        {"sub": "test-user", "iss": mock_server.base_url, "aud": "some-other-client"},
        mock_server.private_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(Exception):
        client.verify_id_token(wrong_audience)


def test_refreshes_access_token(mock_server):
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    req = client.create_authorization_request()
    code = issue_code(mock_server, req.code_verifier)
    tokens = client.exchange_code(code, req.code_verifier)

    refreshed = client.refresh_token(tokens.refresh_token)
    assert refreshed.access_token == "refreshed-access-token"
