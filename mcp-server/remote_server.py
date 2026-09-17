#!/usr/bin/env python3
"""Remote MCP server (streamable HTTP) for a deployed install.

Unlike the stdio server, this one never logs anybody in. It is an OAuth 2.1
*resource server*: Claude Code discovers the authorization server through the
protected resource metadata this server publishes, runs the browser login and
consent itself, and then presents the user's access token on every MCP request.
This server verifies that token and forwards it to the product API, so the call
still reaches the API as the real user with exactly the scopes they consented to.

    MCP request without a token
        -> 401 + WWW-Authenticate: resource_metadata=...
    GET /.well-known/oauth-protected-resource
        -> "the authorization server is <issuer>"
    Claude Code runs login + consent, gets a JWT, retries with it
        -> verified here against the issuer's JWKS, then passed to the API

Audience binding matters: a token minted for something else must not be usable
here. Spring does not implement RFC 8707 resource indicators, so the server side
stamps an `aud` claim on tokens for the remote client and this verifier refuses
anything whose audience is not this server.
"""

from __future__ import annotations

import os

import jwt
from jwt import PyJWKClient
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

import tools

# Where the authorization server lives, as seen from the public internet. This is
# the `iss` in the tokens, so it must match what Spring is configured to issue.
ISSUER_URL = os.environ.get("CRUD_ISSUER_URL", "http://localhost:8080").rstrip("/")

# This server's own canonical URI: the audience tokens must carry, and the
# resource identifier Claude Code sends as the RFC 8707 `resource` parameter.
RESOURCE_URL = os.environ.get("CRUD_MCP_PUBLIC_URL", "http://localhost:3000").rstrip("/")

JWKS_URL = os.environ.get("CRUD_JWKS_URL", f"{ISSUER_URL}/oauth2/jwks")
REQUIRED_SCOPES = os.environ.get("CRUD_REQUIRED_SCOPES", "products.read").split()

HOST = os.environ.get("CRUD_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("CRUD_MCP_PORT", "3000"))


class SpringJwtVerifier(TokenVerifier):
    """Verifies access tokens against the Spring authorization server's JWKS.

    Signature, expiry, issuer and audience are all checked. The keys are fetched
    from the JWKS endpoint and cached by PyJWKClient, which refetches when it sees
    an unknown key id — which is what happens after the Spring app restarts, since
    it generates a fresh signing key at startup.
    """

    def __init__(self) -> None:
        self._jwks = PyJWKClient(JWKS_URL, cache_keys=True)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=ISSUER_URL,
                audience=RESOURCE_URL,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except Exception:
            # Any failure is just an invalid token; the middleware turns this into a 401.
            return None

        scope = claims.get("scope", [])
        scopes = scope.split() if isinstance(scope, str) else list(scope)

        return AccessToken(
            token=token,
            client_id=claims.get("azp") or claims.get("client_id") or "unknown",
            scopes=scopes,
            expires_at=claims.get("exp"),
            resource=RESOURCE_URL,
            subject=claims.get("sub"),
            claims=claims,
        )


mcp = MCPServer(
    name="crud-mcp-server",
    version="2.0.0",
    instructions=(
        "Read and modify the product catalogue served by the Spring Boot CRUD service. "
        "Tools act as the signed in user, with the permissions granted on the consent "
        "screen; a write attempt without products.write fails with 403."
    ),
    token_verifier=SpringJwtVerifier(),
    auth=AuthSettings(
        issuer_url=ISSUER_URL,
        resource_server_url=RESOURCE_URL,
        required_scopes=REQUIRED_SCOPES,
        # The verifier above checks `aud` itself, which is what binds a token to
        # this server; Spring does not emit RFC 8707 resource indicators.
        validate_token_resource=False,
    ),
)


async def caller_token(force_refresh: bool = False) -> str:
    """The token Claude Code presented on this request, passed straight through.

    There is nothing to refresh here — this server holds no credentials of its
    own, and renewing the user's token is the client's job — so a forced refresh
    can only mean the API rejected a token this server already verified.
    """
    token = get_access_token()
    if token is None:
        raise ToolError("No access token on this request; authenticate with /mcp first.")
    if force_refresh:
        raise ToolError(
            "The product API rejected your access token. Re-authenticate this server "
            "with /mcp (or `claude mcp login`) to get a fresh one."
        )
    return token.token


tools.register_products(mcp, caller_token)


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host=HOST, port=PORT)
