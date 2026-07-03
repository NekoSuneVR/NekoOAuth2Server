import base64
import hashlib
import os


def _urlsafe_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
    """32 random bytes, base64url-encoded -- lands in RFC 7636's 43-128 char range."""
    return _urlsafe_no_pad(os.urandom(32))


def generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _urlsafe_no_pad(digest)


def generate_state() -> str:
    return _urlsafe_no_pad(os.urandom(16))
