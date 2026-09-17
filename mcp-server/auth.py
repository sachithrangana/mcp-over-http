#!/usr/bin/env python3
"""Browser based OAuth2 login for the CRUD MCP server.

Runs the authorization code flow with PKCE against the Spring authorization
server: opens the user's browser, catches the redirect on a loopback port,
exchanges the code for tokens, and caches them on disk so later sessions start
already signed in.

The plugin is a public client — it ships on the user's machine, so it holds no
client secret and relies on PKCE to bind the code to this process. Spring will
not hand a refresh token to a client that cannot authenticate, so the access
token is long lived (8h) and the browser flow simply runs again when it lapses;
the refresh path below is kept for the day this client becomes confidential.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any

import httpx

BASE_URL = os.environ.get("CRUD_API_BASE_URL", "http://localhost:8080").rstrip("/")
CLIENT_ID = os.environ.get("CRUD_PLUGIN_CLIENT_ID", "crud-plugin")
SCOPE = os.environ.get("CRUD_SCOPE", "products.read products.write")
AUTHORIZE_URL = os.environ.get("CRUD_OAUTH_AUTHORIZE_URL", f"{BASE_URL}/oauth2/authorize")
TOKEN_URL = os.environ.get("CRUD_OAUTH_TOKEN_URL", f"{BASE_URL}/oauth2/token")
TIMEOUT = float(os.environ.get("CRUD_API_TIMEOUT", "10"))

# Must match the redirect URIs registered in AuthorizationServerConfig.
REDIRECT_PORTS = (8765, 8766, 8767, 8768, 8769)
REDIRECT_PATH = "/callback"

TOKEN_FILE = Path(
    os.environ.get("CRUD_TOKEN_FILE", Path.home() / ".crud-mcp" / "token.json")
).expanduser()

# How long to wait for the person to finish logging in before giving up.
LOGIN_TIMEOUT = float(os.environ.get("CRUD_LOGIN_TIMEOUT", "180"))

# Refresh this many seconds before actual expiry so a token never dies mid request.
EXPIRY_SKEW = 30


class AuthError(Exception):
    """Login or refresh failed; the message is safe to show the user."""


# --------------------------------------------------------------------------- cache


def _read_cache() -> dict[str, Any]:
    try:
        return json.loads(TOKEN_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _write_cache(data: dict[str, Any]) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the start; a token must never be world readable.
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)


def clear_tokens() -> bool:
    """Forget the cached tokens. Returns whether anything was there."""
    try:
        TOKEN_FILE.unlink()
        return True
    except FileNotFoundError:
        return False


def status() -> dict[str, Any]:
    """Describe the cached login without triggering a browser flow."""
    cache = _read_cache()
    if not cache.get("access_token"):
        return {"logged_in": False, "detail": "No cached token; run the login tool."}

    remaining = int(cache.get("expires_at", 0) - time.time())
    return {
        "logged_in": True,
        "user": cache.get("username"),
        "scopes": cache.get("scope", "").split(),
        "access_token_expires_in_seconds": max(0, remaining),
        "can_refresh": bool(cache.get("refresh_token")),
        "token_file": str(TOKEN_FILE),
    }


# ----------------------------------------------------------------------- PKCE flow


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Catches the single redirect back from the browser."""

    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != REDIRECT_PATH:
            self.send_error(404)
            return

        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        _CallbackHandler.result = params

        if "code" in params:
            title, message = "Signed in", "You can close this tab and return to Claude."
        else:
            title = "Login failed"
            message = params.get("error_description") or params.get("error", "Unknown error")

        body = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f4f5f7;
color:#1c1e21}}div{{background:#fff;border:1px solid #d9dce1;border-radius:10px;padding:32px;
max-width:380px;text-align:center}}h1{{font-size:20px;margin:0 0 8px}}p{{color:#6b7280;margin:0}}
</style></head><body><div><h1>{title}</h1><p>{message}</p></div></body></html>"""

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args: Any) -> None:
        """Silence the default stderr logging; stdio is the MCP channel."""


def _bind_loopback() -> http.server.HTTPServer:
    """Bind the first free registered port, so the redirect URI stays one the server knows."""
    for port in REDIRECT_PORTS:
        try:
            return http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        except OSError:
            continue
    raise AuthError(
        f"None of the redirect ports {list(REDIRECT_PORTS)} are free. "
        "Close whatever is using them and try again."
    )


def login(open_browser: bool = True) -> dict[str, Any]:
    """Run the full browser login and cache the resulting tokens."""
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)

    server = _bind_loopback()
    redirect_uri = f"http://127.0.0.1:{server.server_port}{REDIRECT_PATH}"
    _CallbackHandler.result = {}

    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    authorize_url = f"{AUTHORIZE_URL}?{query}"

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    if open_browser:
        webbrowser.open(authorize_url)

    thread.join(timeout=LOGIN_TIMEOUT)
    server.server_close()

    params = _CallbackHandler.result
    if not params:
        raise AuthError(
            f"Timed out after {LOGIN_TIMEOUT:.0f}s waiting for the browser login. "
            f"Open this URL manually and sign in:\n{authorize_url}"
        )

    if "error" in params:
        detail = params.get("error_description") or params["error"]
        raise AuthError(f"Authorization was refused: {detail}")

    # A mismatched state means the redirect did not come from the request we made.
    if not secrets.compare_digest(params.get("state", ""), state):
        raise AuthError("State mismatch on the OAuth redirect; login aborted.")

    _exchange({
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": redirect_uri,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    return status()


def _refresh(refresh_token: str) -> dict[str, Any]:
    return _exchange({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    })


def _exchange(data: dict[str, str]) -> dict[str, Any]:
    """POST to the token endpoint and cache whatever comes back."""
    try:
        response = httpx.post(TOKEN_URL, data=data, timeout=TIMEOUT)
    except httpx.RequestError as exc:
        raise AuthError(f"Cannot reach the authorization server at {TOKEN_URL}: {exc}") from exc

    if response.is_error:
        detail = response.text or "no body"
        try:
            payload = response.json()
            detail = payload.get("error_description") or payload.get("error") or detail
        except ValueError:
            pass
        raise AuthError(f"Token request failed (HTTP {response.status_code}): {detail}")

    payload = response.json()
    cache = {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token"),
        "scope": payload.get("scope", ""),
        "expires_at": time.time() + payload.get("expires_in", 3600),
        "username": _subject(payload["access_token"]),
    }
    _write_cache(cache)
    return cache


def _subject(access_token: str) -> str | None:
    """Read `sub` out of the JWT for display. Not a validation — the API does that."""
    try:
        claims = access_token.split(".")[1]
        padded = claims + "=" * (-len(claims) % 4)
        return json.loads(base64.urlsafe_b64decode(padded)).get("sub")
    except Exception:
        return None


def access_token(force_refresh: bool = False) -> str:
    """Return a usable access token, refreshing or prompting a login as needed."""
    cache = _read_cache()

    if not force_refresh and cache.get("access_token"):
        if time.time() < cache.get("expires_at", 0) - EXPIRY_SKEW:
            return cache["access_token"]

    if cache.get("refresh_token"):
        try:
            return _refresh(cache["refresh_token"])["access_token"]
        except AuthError:
            # Refresh token expired or already rotated away; fall through to a login.
            pass

    raise AuthError(
        "Not signed in to the product service. Run the `login` tool (or "
        "`python login.py` in the mcp-server directory) to authorize in your browser."
    )
