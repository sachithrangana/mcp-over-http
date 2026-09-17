#!/usr/bin/env python3
"""Local MCP server (stdio) exposing the Spring Boot product CRUD service.

A thin stdio adapter over the REST API; the Spring Boot app must be running.
Set CRUD_API_BASE_URL to point at it (default http://localhost:8080).

The API is OAuth2-protected and the tools act as a real user, not as the
application: the first call opens a browser for login and consent (authorization
code + PKCE, see auth.py), and the resulting token is cached so later sessions
start signed in. Whatever the user declined on the consent screen is simply not
in the token, so a read only login makes the write tools fail with 403.

The product tools live in tools.py and are shared with remote_server.py, which
serves the same catalogue over HTTP for a deployed install.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

import auth
import tools

mcp = MCPServer(
    name="crud-mcp-server",
    version="2.0.0",
    instructions=(
        "Read and modify the product catalogue served by the Spring Boot CRUD service. "
        "Tools act as the signed in user; if one reports that nobody is signed in, call "
        "the login tool, which opens a browser for login and consent."
    ),
)


async def access_token(force_refresh: bool = False) -> str:
    """Token for the signed in user; never starts a browser flow on its own."""
    try:
        return await asyncio.to_thread(auth.access_token, force_refresh)
    except auth.AuthError as exc:
        raise ToolError(str(exc)) from exc


tools.register_products(mcp, access_token)


# The sign in tools are stdio only: they drive a browser on this machine. A remote
# deployment has no such machine, and Claude Code owns the OAuth flow there instead.


@mcp.tool(
    title="Authorization status",
    description=(
        "Show who the plugin is signed in as, which permissions were granted on the "
        "consent screen, and when the token expires. Does not open a browser."
    ),
)
async def auth_status() -> dict[str, Any]:
    return await asyncio.to_thread(auth.status)


@mcp.tool(
    title="Sign in",
    description=(
        "Open a browser to sign in to the product service and choose which permissions "
        "to grant. Use when a tool reports that you are not signed in, or to switch user. "
        "Returns once the browser login finishes."
    ),
)
async def login() -> dict[str, Any]:
    try:
        return await asyncio.to_thread(auth.login)
    except auth.AuthError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    title="Sign out",
    description="Delete the cached tokens, so the next call requires signing in again.",
)
async def logout() -> dict[str, Any]:
    removed = await asyncio.to_thread(auth.clear_tokens)
    return {
        "signed_out": removed,
        "detail": "Cached token removed." if removed else "Was not signed in.",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
