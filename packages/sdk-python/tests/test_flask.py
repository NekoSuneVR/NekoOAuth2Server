import urllib.parse

from flask import Flask, jsonify

from neko_oauth2_sdk import NekoAuthClient
from neko_oauth2_sdk.flask import create_neko_auth_blueprint, require_auth

from .conftest import CLIENT_ID, REDIRECT_URI, issue_code


def _make_app(mock_server):
    app = Flask(__name__)
    app.secret_key = "test-secret"
    client = NekoAuthClient(issuer=mock_server.base_url, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
    app.register_blueprint(create_neko_auth_blueprint(client))

    @app.route("/protected")
    @require_auth()
    def protected():
        from flask import session

        return jsonify({"ok": True, "user": session["neko_user"]})

    return app


def test_protected_route_redirects_to_login_when_signed_out(mock_server):
    app = _make_app(mock_server)
    client = app.test_client()

    res = client.get("/protected")
    assert res.status_code == 302
    assert res.headers["Location"] == "/auth/login?returnTo=/protected"


def test_full_login_flow_against_the_real_mock_server(mock_server):
    app = _make_app(mock_server)
    test_client = app.test_client()

    login_res = test_client.get("/auth/login")
    assert login_res.status_code == 302
    authorize_url = urllib.parse.urlparse(login_res.headers["Location"])
    assert f"{authorize_url.scheme}://{authorize_url.netloc}" == mock_server.base_url

    query = urllib.parse.parse_qs(authorize_url.query)
    state = query["state"][0]

    with test_client.session_transaction() as sess:
        code_verifier = sess["neko_pending"]["code_verifier"]

    code = issue_code(mock_server, code_verifier)

    callback_res = test_client.get(f"/auth/callback?code={code}&state={state}")
    assert callback_res.status_code == 302
    assert callback_res.headers["Location"] == "/"

    protected_res = test_client.get("/protected")
    assert protected_res.status_code == 200
    assert protected_res.get_json()["user"]["sub"] == "test-user"

    logout_res = test_client.get("/auth/logout")
    assert logout_res.status_code == 302

    after_logout_res = test_client.get("/protected")
    assert after_logout_res.status_code == 302


def test_callback_rejects_state_mismatch(mock_server):
    app = _make_app(mock_server)
    test_client = app.test_client()
    test_client.get("/auth/login")

    res = test_client.get("/auth/callback?code=whatever&state=not-the-real-state")
    assert res.status_code == 400
