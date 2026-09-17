# Deploying

Two containers. The Spring app is both the product API **and** the OAuth
authorization server, so the MCP server cannot be deployed on its own — it has no
one to verify tokens against.

```
                 browser: login + consent
                        │
   Claude Code ─────────┼─────────> api  :8090   REST API + OAuth2 AS
        │ MCP over HTTP │                 ▲
        │  Bearer <JWT> │                 │ Bearer <JWT>, as the user
        └───────────> mcp  :3000 ─────────┘
                    resource server
```

Claude Code holds the user's token and presents it on every MCP call. The MCP
server verifies it against the authorization server's JWKS and passes it through
to the API, so the API still sees the real user and the scopes they consented to.
The MCP server holds no credentials of its own.

## Run it

```bash
cp .env.example .env     # then edit the two public URLs
docker compose up --build
```

That is the whole deployment. The same two images run on any host that runs
containers — a VPS, Render, Railway, Fly, ECS, Cloud Run.

## The URLs matter

`PUBLIC_API_URL` and `PUBLIC_MCP_URL` are not cosmetic. They end up inside tokens
and discovery documents, and a mismatch fails in confusing ways:

| Setting | Becomes | Breaks if wrong |
|---------|---------|-----------------|
| `PUBLIC_API_URL` | the `iss` claim and the issuer in `/.well-known/oauth-authorization-server` | Claude Code rejects the token: issuer mismatch |
| `PUBLIC_MCP_URL` | the `aud` claim and `resource` in the protected resource metadata | the MCP server rejects its own users' tokens |

Set them to the URLs **a browser and Claude Code actually reach**, not container
names. Inside the compose network the MCP server still calls the API at
`http://api:8080` for API traffic and JWKS; only the identity URLs are public.

## Connecting Claude Code

Claude Code prefers dynamic client registration, but Spring's registration
endpoint requires an initial access token that Claude Code cannot supply, so the
client is **pre-registered** as `crud-mcp-remote` and named explicitly:

```bash
claude mcp add --transport http crud-remote https://mcp.example.com/mcp \
  --client-id crud-mcp-remote \
  --callback-port 8765
```

Then authenticate:

```bash
claude mcp login crud-remote     # or /mcp inside a session
```

The browser opens the same login and consent screens as the local plugin. Ticking
only `products.read` gives a session that can read but not write.

`--callback-port` must be one of the ports registered as a redirect URI:
**8765-8769** (`CLAUDE_CALLBACK_PORTS` in `AuthorizationServerConfig`). Add more
there if you need a different one.

The client is public, so there is no client secret to pass.

## Before exposing it publicly

This runs as a demo out of the box. Three things to change for real use:

1. **Serve both over HTTPS.** Tokens travel in `Authorization` headers; plain HTTP
   puts them on the wire. Put a TLS terminating proxy in front and set the public
   URLs to `https://`.
2. **Persist the signing key.** `AuthorizationServerConfig#jwkSource` generates an
   RSA key at startup, so every restart invalidates every token. Load one from a
   keystore or secret manager instead.
3. **Replace the seeded users and the H2 database.** `alice` and `bob` are created
   on boot with known passwords, and the database is in memory — all product data
   is lost on restart. Point `spring.datasource.*` at a real database and manage
   users properly.

`crud-client` / `crud-secret` also still exists for machine-to-machine access. Give
it a real secret or drop it from `AuthorizationServerConfig#serviceClient`.

## Verifying a deployment

With both halves running:

```bash
cd mcp-server
python test_remote.py    # discovery, 401 challenge, tools, consent, audience binding
```

It plays the part of Claude Code end to end: reads the protected resource
metadata, checks the 401 carries `resource_metadata`, runs login and consent,
speaks MCP over HTTP, and confirms a token minted for anything else is refused.
Point it at another host by editing `MCP_URL` and `RESOURCE` at the top.
