"""Optional Flask integration -- only imported if you actually use it, so
`import neko_oauth2_sdk` alone never requires Flask to be installed. Mirrors
the TypeScript SDK's `@nekosunevr/oauth2-sdk/express` entry point: same
routes, same session-key names conceptually, same "bring your own session"
philosophy (this reads/writes Flask's built-in signed-cookie `session`,
already available on any Flask app with a SECRET_KEY set -- no separate
session store required).
"""

from functools import wraps
from typing import Callable, Optional

from flask import Blueprint, redirect, request, session

from .client import NekoAuthClient, TokenSet


def create_neko_auth_blueprint(
    client: NekoAuthClient,
    login_path: str = "/auth/login",
    callback_path: str = "/auth/callback",
    logout_path: str = "/auth/logout",
    default_return_to: str = "/",
    on_login_success: Optional[Callable[[dict, TokenSet], None]] = None,
) -> Blueprint:
    bp = Blueprint("neko_auth", __name__)

    @bp.route(login_path)
    def login():
        req = client.create_authorization_request()
        session["neko_pending"] = {
            "state": req.state,
            "code_verifier": req.code_verifier,
            "return_to": request.args.get("returnTo", default_return_to),
        }
        return redirect(req.url)

    @bp.route(callback_path)
    def callback():
        pending = session.pop("neko_pending", None)
        if not pending:
            return "No pending login for this session -- start at the login route again.", 400
        if request.args.get("error"):
            return f"Login failed: {request.args['error']}", 400
        if request.args.get("state") != pending["state"]:
            return "Login failed: state mismatch.", 400

        tokens = client.exchange_code(request.args["code"], pending["code_verifier"])
        profile = client.get_user_info(tokens.access_token)
        if tokens.id_token:
            claims = client.verify_id_token(tokens.id_token)
            if claims.get("sub") != profile.get("sub"):
                return "Login failed: id_token subject does not match userinfo subject.", 400

        user = {
            "sub": profile["sub"],
            "profile": profile,
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
        }
        session["neko_user"] = user

        if on_login_success:
            on_login_success(user, tokens)

        return redirect(pending.get("return_to") or default_return_to)

    @bp.route(logout_path)
    def logout():
        session.pop("neko_user", None)
        return redirect(default_return_to)

    return bp


def require_auth(login_path: str = "/auth/login"):
    """Decorator protecting a view: redirects to the login route (preserving
    the original path) if `session["neko_user"]` isn't set."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get("neko_user"):
                return redirect(f"{login_path}?returnTo={request.path}")
            return view_func(*args, **kwargs)

        return wrapped

    return decorator
