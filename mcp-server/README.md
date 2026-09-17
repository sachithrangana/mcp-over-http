# CRUD MCP Server (Python)

An MCP server that exposes the Spring Boot product service as tools, so an MCP client (Claude Code,
Claude Desktop, any other) can read and modify the catalogue.

It comes in two transports that share one set of tools (`tools.py`):

| | `server.py` (stdio) | `remote_server.py` (HTTP) |
|---|---|---|
| Runs | on your machine, spawned by the client | deployed, see [`../DEPLOY.md`](../DEPLOY.md) |
| Signs the user in | itself, browser + loopback (`auth.py`) | never — Claude Code does, this only verifies |
| Holds credentials | a cached token on disk | none at all |
| Extra tools | `login`, `logout`, `auth_status` | – |

Both call the REST API as the signed-in user, so the Spring app in `../springboot` must be running.

## Setup

```bash
uv venv --python 3.12
uv pip install "mcp[cli]" httpx
```

## Tools

| Tool | Arguments | Calls |
|------|-----------|-------|
| `list_products`  | –                                     | `GET /api/products` |
| `get_product`    | `id`                                  | `GET /api/products/{id}` |
| `create_product` | `name`, `price`, `description?`       | `POST /api/products` |
| `update_product` | `id`, `name`, `price`, `description?` | `PUT /api/products/{id}` |
| `delete_product` | `id`                                  | `DELETE /api/products/{id}` |
| `health_check`   | –                                     | `GET /actuator/health` |
| `auth_status`    | –                                     | – (reads the cached login) |
| `login`          | –                                     | browser login + consent |
| `logout`         | –                                     | – (deletes the cached token) |

Arguments are validated against the same rules the API enforces (non-blank name, non-negative
price), so bad input is rejected before a request is made. API errors (404, 403, 400), a failed
token request, and an unreachable service all surface as MCP tool errors with a readable message.

## Signing in

The tools act as a **real user**, not as the application. On the first call that needs the API the
server reports that nobody is signed in; running the `login` tool (or `python login.py`) opens a
browser through the standard authorization code flow with PKCE:

```
Claude Code ──spawns──> server.py            login tool
                                                 │
                        opens browser ───────────┤
                                                 ▼
                          ┌──────────────────────────────────┐
                          │  /login      sign in as a user   │
                          │  /oauth2/consent   tick scopes   │
                          └──────────────────┬───────────────┘
                                             ▼
                    redirect to http://127.0.0.1:8765/callback?code=…
                                             │
                          exchange code + verifier for a JWT
                                             ▼
                              ~/.crud-mcp/token.json (0600)
```

The plugin is a **public client**: it runs on your machine, so it holds no client secret and PKCE is
what binds the authorization code to the process that started the flow. The loopback listener takes
the first free port from 8765-8769; those exact URIs are registered on the server, because Spring
matches redirect URIs exactly rather than allowing any loopback port.

**Consent is asked every time.** Spring would normally remember what you approved and reuse it
silently, which would mean ticking `products.write` once and carrying write access forever after.
`PerLoginConsentService` deliberately stores nothing, so each login is a fresh decision.

**Unticking a permission really removes it.** The consent screen only offers scopes your account is
allowed to hold — `bob` is never shown a write checkbox — and the issued token is capped a second
time at the server (`UserScopeJwtCustomizer`), so a hand-crafted consent POST cannot widen access.
Sign in read-only and `create_product` fails with 403.

There is **no refresh token**: Spring only issues one to a client that authenticates, and a public
client cannot. The access token lasts 8 hours instead, after which `login` runs the flow again.

| Variable | Default | Meaning |
|----------|---------|---------|
| `CRUD_API_BASE_URL`        | `http://localhost:8080`        | Base URL of the service |
| `CRUD_PLUGIN_CLIENT_ID`    | `crud-plugin`                  | Public OAuth client id |
| `CRUD_OAUTH_AUTHORIZE_URL` | `<base>/oauth2/authorize`      | Authorization endpoint |
| `CRUD_OAUTH_TOKEN_URL`     | `<base>/oauth2/token`          | Token endpoint |
| `CRUD_SCOPE`               | `products.read products.write` | Scopes to ask for |
| `CRUD_TOKEN_FILE`          | `~/.crud-mcp/token.json`       | Where the token is cached |
| `CRUD_LOGIN_TIMEOUT`       | `180`                          | Seconds to wait for the browser |
| `CRUD_API_TIMEOUT`         | `10`                           | HTTP timeout, seconds |

`CRUD_SCOPE` only sets what is *asked for* — the consent screen still decides what is granted.

Demo users: `alice` / `alice-secret` (read and write), `bob` / `bob-secret` (read only).

### From the terminal

```bash
python login.py            # sign in
python login.py --status   # who am I, which scopes, when does it expire
python login.py --logout   # forget the cached token
```

Signing in up front avoids a tool call sitting and waiting on the browser mid-conversation.

The machine-to-machine `crud-client` (client_credentials and the password grant) is untouched and
still works for scripts; it is simply no longer what the plugin uses.

## Test

With the Spring Boot app running:

```bash
.venv/bin/python test_client.py      # MCP tools, needs a signed in user
.venv/bin/python test_auth_flow.py   # the browser flow, no browser needed
```

`test_client.py` starts the server over stdio as a real MCP client, lists the tools, and runs a full
create / read / update / delete lifecycle plus the error paths.

`test_auth_flow.py` walks the authorization flow with httpx standing in for the browser — login
form, consent screen, redirect, PKCE exchange — and checks the parts that matter: unticking a scope
yields a narrower token, `bob` is never offered write, and a forged consent POST approving
`products.write` still comes back read-only and is refused 403 by the API.

## Remote mode

`remote_server.py` is an OAuth 2.1 **resource server**. It publishes
`/.well-known/oauth-protected-resource` (RFC 9728), answers an unauthenticated call with a 401
carrying `resource_metadata`, and Claude Code takes it from there: it discovers the authorization
server, runs the browser login and consent, and sends the user's token on every MCP request. This
server verifies that token against the JWKS and forwards it to the API — it never logs anyone in and
stores no credentials.

Tokens are audience bound. Spring ignores the RFC 8707 `resource` parameter, so
`ResourceAudienceJwtCustomizer` stamps `aud` on tokens for the remote client and the verifier
refuses anything else — a token minted for the local plugin returns 401 here.

```bash
pip install "mcp>=2.2.0" "httpx>=0.28" "pyjwt[crypto]>=2.9" "uvicorn>=0.30"
CRUD_API_BASE_URL=http://localhost:8080 \
CRUD_ISSUER_URL=http://localhost:8080 \
CRUD_MCP_PUBLIC_URL=http://localhost:3000 python remote_server.py
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `CRUD_ISSUER_URL`      | `http://localhost:8080` | Authorization server, as clients reach it (`iss`) |
| `CRUD_MCP_PUBLIC_URL`  | `http://localhost:3000` | This server's canonical URI (`aud`, `resource`) |
| `CRUD_JWKS_URL`        | `<issuer>/oauth2/jwks`  | Signing keys; may use an internal address |
| `CRUD_REQUIRED_SCOPES` | `products.read`         | Advertised as `scopes_supported` |
| `CRUD_MCP_HOST` / `CRUD_MCP_PORT` | `0.0.0.0` / `3000` | Bind address |

Deploying it is `docker compose up` from the repository root — see [`../DEPLOY.md`](../DEPLOY.md).

## Use as a Claude Code plugin

This directory is also a Claude Code plugin (`.claude-plugin/plugin.json` + `.mcp.json`), with the
repository root acting as a local marketplace. Everything is local — no network, no registry, no
GitHub remote — so the plugin installs and syncs entirely offline.

```bash
claude plugin marketplace add /Users/admin/Desktop/mcp-with-api
claude plugin install crud-products@crud-local
```

Restart Claude Code (or `/reload-plugins`) and the six tools are available in every session, named
`crud-products:<tool>`.

The plugin launches the server with `uv run`, which resolves `mcp` and `httpx` on the fly — the local
`.venv` is only needed for running `test_client.py`, and is deliberately not relied on by the plugin
(the venv's `python` symlink does not survive the install copy).

`${CLAUDE_PLUGIN_ROOT}` in `.mcp.json` resolves to *this* directory, not the snapshot under
`~/.claude/plugins/cache/`, so edits to `server.py` take effect on the next Claude Code restart with
no reinstall. Manifest changes (`plugin.json`, `.mcp.json`) are read from the cached snapshot and do
need the version bump + update below.

Connection settings live in the `env` block of `.mcp.json`; edit them there to point at a different
host, client, or scope.

### If the marketplace directory moves

The marketplace records an absolute path, so moving or renaming the repository breaks it — installs
then fail with a missing-source error. Re-point it:

```bash
claude plugin marketplace remove crud-local
claude plugin marketplace add /new/path/to/mcp-with-api
claude plugin install crud-products@crud-local
```

### Updating

Bump `version` in `.claude-plugin/plugin.json`, then:

```bash
claude plugin marketplace update crud-local
claude plugin update crud-products@crud-local
```

An unchanged version is treated as already up to date, so the bump is what makes the update land.

### Checking

```bash
claude plugin validate . --strict      # manifest check
claude plugin details crud-products@crud-local   # component inventory
```
