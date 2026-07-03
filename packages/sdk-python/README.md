# nekosunevr-oauth2-sdk (Python)

Client SDK for logging into [NekoOAuth2Server](../../README.md) — the Python counterpart to `@nekosunevr/oauth2-sdk`, same shape, same feature set. See that package's README for the fuller "add login in under 10 minutes" walkthrough; this one covers what's Python-specific.

## Install

```bash
pip install nekosunevr-oauth2-sdk
# or, with the optional Flask helper:
pip install "nekosunevr-oauth2-sdk[flask]"
```

## Core usage (framework-agnostic)

```python
from neko_oauth2_sdk import NekoAuthClient

client = NekoAuthClient(
    issuer="http://localhost:4000/oidc",
    client_id="your-client-id",
    redirect_uri="http://localhost:5000/auth/callback",
)

auth_request = client.create_authorization_request()
# store auth_request.state and auth_request.code_verifier (e.g. in the user's session),
# then redirect the browser to auth_request.url

# ...once the browser comes back with ?code=...&state=...:
tokens = client.exchange_code(code, code_verifier)
claims = client.verify_id_token(tokens.id_token)  # verified against the real JWKS
profile = client.get_user_info(tokens.access_token)
```

## Flask helper

```python
from flask import Flask
from neko_oauth2_sdk import NekoAuthClient
from neko_oauth2_sdk.flask import create_neko_auth_blueprint, require_auth

app = Flask(__name__)
app.secret_key = "..."  # required -- Flask's session is where this SDK stores its state

client = NekoAuthClient(issuer=..., client_id=..., redirect_uri=...)
app.register_blueprint(create_neko_auth_blueprint(client))

@app.route("/protected")
@require_auth()
def protected():
    ...
```

## Webhooks

```python
from neko_oauth2_sdk import verify_and_parse_webhook

@app.route("/webhooks/neko", methods=["POST"])
def webhook():
    event = verify_and_parse_webhook(
        request.get_data(),  # the RAW body -- not request.json, the signature is over the raw bytes
        request.headers.get("X-Neko-Signature"),
        WEBHOOK_SECRET,
    )
    if event.event == "user.deleted":
        ...
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
```
