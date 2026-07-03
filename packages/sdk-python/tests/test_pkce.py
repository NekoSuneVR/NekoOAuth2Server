import base64
import hashlib
import re

from neko_oauth2_sdk import generate_code_challenge, generate_code_verifier, generate_state

URL_SAFE = re.compile(r"^[A-Za-z0-9\-_]+$")


def test_code_verifier_length_within_rfc7636():
    verifier = generate_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert URL_SAFE.match(verifier)


def test_code_challenge_matches_rfc7636_s256():
    verifier = "test-verifier-value"
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert generate_code_challenge(verifier) == expected


def test_verifier_is_random_each_call():
    assert generate_code_verifier() != generate_code_verifier()


def test_state_is_nonempty_and_url_safe():
    state = generate_state()
    assert len(state) > 0
    assert URL_SAFE.match(state)
