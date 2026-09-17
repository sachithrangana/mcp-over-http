#!/usr/bin/env python3
"""End to end check of the remote (HTTP) MCP server.

Plays the part of Claude Code: discovers the authorization server from the
protected resource metadata, runs the login and consent flow in place of the
browser, then speaks MCP over streamable HTTP with the resulting token.

Requires both halves running — the API on :8080 and remote_server.py on :3000.

    python test_remote.py
"""

from __future__ import annotations

import base64
import json
import sys
from contextlib import asynccontextmanager

import httpx

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import test_auth_flow as flow

MCP_URL = "http://localhost:3000/mcp"
RESOURCE = "http://localhost:3000"
REMOTE_CLIENT = "crud-mcp-remote"

failures = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global failures
    if not condition:
        failures += 1
    print(f"{'ok  ' if condition else 'FAIL'}  {label}{f'  [{detail}]' if detail else ''}")


def audience_matches(aud: object, expected: str) -> bool:
    """`aud` is a string for a single audience and a list for several."""
    if aud is None:
        return False
    return expected in ([aud] if isinstance(aud, str) else list(aud))


def claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def user_token(username: str, password: str, grant: list[str] | None = None) -> str:
    """Drive login + consent for the remote client, exactly as Claude Code would."""
    original_client, original_redirect = flow.CLIENT_ID, flow.REDIRECT_URI
    flow.CLIENT_ID, flow.REDIRECT_URI = REMOTE_CLIENT, "http://localhost:8765/callback"
    try:
        with httpx.Client(follow_redirects=True) as client:
            redirect, _, verifier = flow.authorize(
                client, username, password, "products.read products.write", grant=grant)
            return flow.exchange(redirect, verifier)["access_token"]
    finally:
        flow.CLIENT_ID, flow.REDIRECT_URI = original_client, original_redirect


@asynccontextmanager
async def mcp_session(token: str):
    """Open an MCP session over streamable HTTP, carrying a bearer token."""
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http:
        async with streamable_http_client(MCP_URL, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def main() -> int:
    # --- discovery, the way Claude Code starts ------------------------------
    metadata = httpx.get(f"{RESOURCE}/.well-known/oauth-protected-resource").json()
    check("protected resource metadata names this server",
          metadata["resource"] == RESOURCE, metadata["resource"])
    check("metadata points at the authorization server",
          metadata["authorization_servers"] == ["http://localhost:8080"])

    unauth = httpx.post(MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        headers={"Accept": "application/json, text/event-stream"})
    check("unauthenticated request is refused 401", unauth.status_code == 401)
    check("401 carries resource_metadata for discovery",
          "resource_metadata" in unauth.headers.get("www-authenticate", ""))

    # --- a token for this resource, read and write --------------------------
    token = user_token("alice", "alice-secret")
    audience = claims(token).get("aud")
    check("token is bound to this server as audience", audience_matches(audience, RESOURCE),
          str(audience))

    async with mcp_session(token) as session:
            tools = (await session.list_tools()).tools
            check("tools exposed over HTTP", len(tools) == 6, f"{len(tools)}: " +
                  ", ".join(t.name for t in tools))

            created = await session.call_tool(
                "create_product", {"name": "Remote widget", "price": 9.5})
            check("create_product works as the signed in user", not created.is_error,
                  created.content[0].text[:60])
            pid = json.loads(created.content[0].text)["id"]

            got = await session.call_tool("get_product", {"id": pid})
            check("get_product returns it", not got.is_error)

            deleted = await session.call_tool("delete_product", {"id": pid})
            check("delete_product works", not deleted.is_error)

    # --- consent still decides what the remote server can do ----------------
    readonly = user_token("alice", "alice-secret", grant=["products.read"])
    async with mcp_session(readonly) as session:
            listed = await session.call_tool("list_products", {})
            check("read only token can read", not listed.is_error)
            blocked = await session.call_tool("create_product", {"name": "no", "price": 1})
            check("read only token cannot write", blocked.is_error,
                  blocked.content[0].text.strip()[-40:])

    # --- audience binding: a token for the local plugin must not work here ---
    plugin_token = None
    with httpx.Client(follow_redirects=True) as client:
        redirect, _, verifier = flow.authorize(
            client, "alice", "alice-secret", "products.read products.write")
        plugin_token = flow.exchange(redirect, verifier)["access_token"]

    check("local plugin token carries no audience for this server",
          not audience_matches(claims(plugin_token).get("aud"), RESOURCE),
          str(claims(plugin_token).get("aud")))

    wrong = httpx.post(MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                       headers={"Authorization": f"Bearer {plugin_token}",
                                "Accept": "application/json, text/event-stream"})
    check("a token minted for another resource is refused", wrong.status_code == 401,
          str(wrong.status_code))

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    import asyncio
    sys.exit(asyncio.run(main()))
