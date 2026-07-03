import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Optional, Union


@dataclass
class WebhookEvent:
    event: str
    data: Any
    timestamp: str


class InvalidWebhookSignature(Exception):
    pass


def verify_webhook_signature(raw_body: Union[bytes, str], signature_header: Optional[str], secret: str) -> bool:
    """Matches the server's own signing scheme exactly: `X-Neko-Signature:
    sha256=<hex hmac-sha256 of the raw request body>`. `raw_body` must be the
    exact bytes the server sent -- re-serializing after parsing JSON can
    differ enough (key order, whitespace) to fail verification even for
    "the same" content, so callers must capture the raw body before parsing.
    """
    if not signature_header:
        return False
    scheme, _, signature = signature_header.partition("=")
    if scheme != "sha256" or not signature:
        return False

    if isinstance(raw_body, str):
        raw_body = raw_body.encode("utf-8")

    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    try:
        expected_bytes = bytes.fromhex(expected)
        provided_bytes = bytes.fromhex(signature)
    except ValueError:
        return False
    if len(expected_bytes) != len(provided_bytes):
        return False
    return hmac.compare_digest(expected_bytes, provided_bytes)


def parse_webhook_payload(raw_body: Union[bytes, str]) -> WebhookEvent:
    data = json.loads(raw_body)
    return WebhookEvent(event=data["event"], data=data.get("data"), timestamp=data.get("timestamp", ""))


def verify_and_parse_webhook(raw_body: Union[bytes, str], signature_header: Optional[str], secret: str) -> WebhookEvent:
    if not verify_webhook_signature(raw_body, signature_header, secret):
        raise InvalidWebhookSignature("invalid webhook signature")
    return parse_webhook_payload(raw_body)
