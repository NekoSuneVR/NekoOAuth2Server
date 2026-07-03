import hashlib
import hmac
import json

import pytest

from neko_oauth2_sdk import (
    InvalidWebhookSignature,
    parse_webhook_payload,
    verify_and_parse_webhook,
    verify_webhook_signature,
)

SECRET = "test-webhook-secret"


def sign(body: str, secret: str = SECRET) -> str:
    return f"sha256={hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()}"


def test_accepts_a_correctly_signed_body():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}, "timestamp": "2026-01-01T00:00:00.000Z"})
    assert verify_webhook_signature(body, sign(body), SECRET) is True


def test_rejects_a_tampered_body():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}})
    signature = sign(body)
    tampered = json.dumps({"event": "user.deleted", "data": {"sub": "someone-else"}})
    assert verify_webhook_signature(tampered, signature, SECRET) is False


def test_rejects_wrong_secret():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}})
    assert verify_webhook_signature(body, sign(body, "wrong-secret"), SECRET) is False


def test_rejects_missing_signature():
    assert verify_webhook_signature("{}", None, SECRET) is False
    assert verify_webhook_signature("{}", "", SECRET) is False


def test_rejects_malformed_signature():
    assert verify_webhook_signature("{}", "not-a-real-signature", SECRET) is False


def test_works_against_real_bytes():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}}).encode()
    assert verify_webhook_signature(body, sign(body.decode()), SECRET) is True


def test_parse_webhook_payload():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}, "timestamp": "2026-01-01T00:00:00.000Z"})
    event = parse_webhook_payload(body)
    assert event.event == "user.deleted"
    assert event.data == {"sub": "user-123"}


def test_verify_and_parse_webhook_returns_event_when_valid():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}, "timestamp": "2026-01-01T00:00:00.000Z"})
    event = verify_and_parse_webhook(body, sign(body), SECRET)
    assert event.data == {"sub": "user-123"}


def test_verify_and_parse_webhook_raises_when_invalid():
    body = json.dumps({"event": "user.deleted", "data": {"sub": "user-123"}})
    with pytest.raises(InvalidWebhookSignature):
        verify_and_parse_webhook(body, "sha256=deadbeef", SECRET)
