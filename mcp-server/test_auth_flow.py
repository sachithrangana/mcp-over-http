#!/usr/bin/env python3
"""End to end check of the browser authorization flow, without a browser.

Walks the same path a user does — /oauth2/authorize, the login form, the consent
screen, the redirect carrying the code, the PKCE token exchange — using httpx as
the browser. Requires the Spring Boot app to be running.

    python test_auth_flow.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sys
import urllib.parse

import httpx

BASE = "http://localhost:8080"
CLIENT_ID = "crud-plugin"
REDIRECT_URI = "http://127.0.0.1:8765/callback"

failures = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global failures
    if not condition:
        failures += 1
    print(f"{'ok  ' if condition else 'FAIL'}  {label}{f'  [{detail}]' if detail else ''}")


def hidden(html: str, name: str) -> str:
    """Read a hidden form field the way a browser would submit it."""
    match = re.search(rf'name="{name}"\s+value="([^"]+)"', html)
    if not match:
        raise AssertionError(f"no {name} field in form")
    return match.group(1)


def pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def authorize(client: httpx.Client, username: str, password: str, scope: str,
              grant: list[str] | None = None) -> tuple[httpx.Response, set[str], str]:
    """Drive login + consent, returning the final redirect to the callback."""
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
        "scope": scope, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    authorize_url = f"{BASE}/oauth2/authorize?{query}"

    # 1. unauthenticated -> login page
    response = client.get(authorize_url)
    check(f"[{username}] /authorize redirects to login", "/login" in str(response.url))

    # 2. sign in
    response = client.post(f"{BASE}/login", data={
        "username": username, "password": password, "_csrf": hidden(response.text, "_csrf")})

    # 3. back to authorize -> consent screen
    response = client.get(authorize_url)
    check(f"[{username}] consent screen shown", "Authorize access" in response.text)

    offered = set(re.findall(r'name="scope"\s+value="([^"]+)"', response.text))
    consent_html = response.text

    # The consent form echoes the state the authorization server issued for this
    # consent step, which is not the state the client sent to /authorize.
    approved = grant if grant is not None else sorted(offered)
    response = client.post(f"{BASE}/oauth2/authorize", follow_redirects=False, data={
        "client_id": CLIENT_ID,
        "state": hidden(consent_html, "state"),
        "_csrf": hidden(consent_html, "_csrf"),
        "scope": list(approved),
    })
    return response, offered, verifier


def exchange(response: httpx.Response, verifier: str) -> dict:
    location = response.headers["location"]
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    token_response = httpx.post(f"{BASE}/oauth2/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    token_response.raise_for_status()
    return token_response.json()


def main() -> int:
    both = "products.read products.write"

    # --- alice: full consent -------------------------------------------------
    with httpx.Client(follow_redirects=True) as client:
        redirect, _, verifier = authorize(client, "alice", "alice-secret", both)
        check("[alice] redirected to the loopback callback with a code",
              redirect.status_code == 302 and "code=" in redirect.headers.get("location", ""),
              redirect.headers.get("location", "")[:60])
        tokens = exchange(redirect, verifier)

    scope = set(claims(tokens["access_token"])["scope"])
    check("[alice] token carries both scopes", scope == {"products.read", "products.write"}, str(scope))
    check("[alice] subject is alice", claims(tokens["access_token"])["sub"] == "alice")
    # Spring only issues refresh tokens to clients that authenticate, and this one is
    # public, so the plugin re-runs the browser flow when the 8h token expires.
    check("[alice] public client gets no refresh token", "refresh_token" not in tokens,
          str(list(tokens.keys())))

    write = httpx.post(f"{BASE}/api/products",
                       headers={"Authorization": f"Bearer {tokens['access_token']}"},
                       json={"name": "From the consent screen", "price": 42.0})
    check("[alice] token can write to the API", write.status_code == 201, str(write.status_code))

    # --- alice: declines write on the consent screen -------------------------
    with httpx.Client(follow_redirects=True) as client:
        redirect, _, verifier = authorize(client, "alice", "alice-secret", both, grant=["products.read"])
        readonly = exchange(redirect, verifier)

    scope = set(claims(readonly["access_token"])["scope"])
    check("[alice] unchecking write yields a read only token", scope == {"products.read"}, str(scope))

    denied = httpx.post(f"{BASE}/api/products",
                        headers={"Authorization": f"Bearer {readonly['access_token']}"},
                        json={"name": "Should fail", "price": 1.0})
    check("[alice] read only token is refused a write", denied.status_code == 403, str(denied.status_code))

    # --- bob: read only user, and a forged consent -------------------------
    with httpx.Client(follow_redirects=True) as client:
        redirect, offered, verifier = authorize(client, "bob", "bob-secret", both,
                                                grant=["products.read"])
        check("[bob] consent screen never offers write", offered == {"products.read"}, str(offered))
        bob_tokens = exchange(redirect, verifier)
    check("[bob] token is read only", set(claims(bob_tokens["access_token"])["scope"]) == {"products.read"})

    with httpx.Client(follow_redirects=True) as client:
        # bob hand-crafts a consent POST approving write anyway.
        redirect, _, verifier = authorize(client, "bob", "bob-secret", both,
                                          grant=["products.read", "products.write"])
        forged = exchange(redirect, verifier)

    forged_scope = set(claims(forged["access_token"])["scope"])
    check("[bob] forged consent cannot grant write", "products.write" not in forged_scope,
          str(forged_scope))

    escalate = httpx.post(f"{BASE}/api/products",
                          headers={"Authorization": f"Bearer {forged['access_token']}"},
                          json={"name": "Escalation", "price": 1.0})
    check("[bob] forged token still refused a write", escalate.status_code == 403, str(escalate.status_code))

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
