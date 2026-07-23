# tap-mcp

Remote MCP server for TAP. A hosted MCP client (Claude, ChatGPT, …) can be
configured with only a URL, discover TAP's OAuth server, open browser
authorization, complete PKCE, and then use the user's TAP credentials.

Production authorization delegates to the existing TAP dashboard session and
passkey flow. The dashboard returns a short-lived signed assertion; the user's
full TAP session token never enters `tap-mcp` or a browser redirect.

## Tools

- **`tap_discover`** — lists the credentials this connection can use and how to
  call each: service name, target shape (full URL vs relative path, with an
  example), whether writes need approval, and any auto-approved URL patterns.
  A condensed, MCP-oriented view of the proxy's `/agent/services` (the raw
  payload is written for curl agents and makes MCP clients hallucinate HTTP
  plumbing).
- **`tap_call`** — calls a third-party API through TAP by credential *name*. TAP
  injects the real secret, enforces policy, and pauses writes for the user's
  one-tap approval before forwarding. The agent never sees the secret. Results
  come back as `{upstream_status, content_type, body}` with JSON bodies parsed;
  TAP's own policy rejections are returned separately as `tap_error` with a
  corrective `hint` (and `credential_link_url` when the fix is creating the
  credential in the dashboard).

Both tools authenticate to the proxy with the connection's OAuth access token
(no TAP API key is held by the client). On authorization the proxy provisions a
dedicated agent scoped to all of the user's team credentials (Nanak's "full
account scope = an API key with all credentials") and threads its id through the
token; `TAP_PROXY_URL` is the proxy the tools call. Unset ⇒ discovery-only.

## Run the interoperability demo

```sh
TAP_MCP_PUBLIC_URL=http://127.0.0.1:3200 \
TAP_MCP_LOCAL_KEY=replace-with-at-least-32-random-bytes \
DANGEROUS_TAP_MCP_DEMO_AUTH=1 \
cargo run -p tap-mcp
```

`DANGEROUS_TAP_MCP_DEMO_AUTH` serves a passwordless consent screen and disables
the allowed-hosts guard, so it is **only accepted with a loopback
`TAP_MCP_PUBLIC_URL`** (`127.0.0.1`/`localhost`/`::1`) — the server refuses to
start in demo mode on any public host. It also skips the durable token state, so
refresh tokens are not revocable in demo mode; never use it in production.

For a hosted-client test, run the real (non-demo) mode below behind an HTTPS
tunnel instead. Enter `<origin>/mcp` in the MCP client and leave OAuth
Client ID/Secret empty.

## Run with TAP dashboard authorization

`tap-mcp` and `tap-proxy` hold **different** keys — see
[Two keys, two trust domains](#two-keys-two-trust-domains) below.
(`mcp.tap.human.tech` below is a placeholder — the public MCP domain is not
decided yet; substitute whatever origin fronts port 3200.)

```sh
TAP_MCP_PUBLIC_URL=https://mcp.tap.human.tech \
TAP_DASHBOARD_URL=https://tap.human.tech/dashboard \
TAP_MCP_LOCAL_KEY=replace-with-at-least-32-random-bytes \
TAP_PROXY_URL=https://tap.human.tech \
TAP_MCP_SERVICE_KEY=replace-with-a-shared-random-secret \
cargo run -p tap-mcp
```

### `tap-mcp` has no database access — by design

`tap-mcp` is an internet-facing OAuth server. `tap-proxy` runs inside an attested
Azure confidential container group, and the KEK that decrypts credential blobs is
released only to that measured workload. Giving `tap-mcp` a
`POSTGRES_DATABASE_URL` would put a live credential for that same database
outside the enclave boundary, so it holds none: **there is no
`POSTGRES_DATABASE_URL` on this service.**

Its durable OAuth token state — revocable refresh-token families and single-use
authorization codes — is reached over three narrow, authenticated endpoints on
the proxy (`tap-proxy/src/mcp_internal.rs`):

| endpoint | when |
| --- | --- |
| `POST /internal/mcp/token/issue` | the `authorization_code` grant is exchanged |
| `POST /internal/mcp/token/refresh` | a refresh token is rotated |

Both sit on the low-frequency OAuth connect/refresh path, never on the
per-request hot path, so the extra hop is not a latency concern. The atomic
semantics are preserved exactly: rotation is still a single
`UPDATE … RETURNING` and code consumption a single `INSERT … ON CONFLICT DO
NOTHING` — they now happen *inside* issue and refresh rather than as separate
round trips. A rejection comes back as `{"issued": false, "reason": …}` with a
200, so replay detection stays distinguishable from a network fault. A transport
failure **fails closed**: the exchange is refused, and there is no local
fallback because this service holds no key any proxy would accept.

### Two keys, two trust domains

`tap-mcp` **does not have `TAP_MCP_SIGNING_KEY`**, and must never be given it.

HMAC is symmetric, so holding the key that signs access tokens *is* the
authority to mint one. The access-token payload carries `team_id` and
`agent_id`, so a `tap-mcp` holding that key — an internet-facing OAuth server
running outside the attested enclave — could forge a bearer for **any** team and
agent and act as it on `/forward`, bypassing the passkey consent flow entirely.
Domain separation does not help here: it constrains a *value*, never a *key
holder*.

So the keys are split by who has to be trusted:

| key | held by | covers |
| --- | --- | --- |
| `TAP_MCP_SIGNING_KEY` | **`tap-proxy` only** | authorization assertions, access tokens, refresh tokens |
| `TAP_MCP_LOCAL_KEY` | `tap-mcp` (and `tap-proxy`, verify-only) | `tap-mcp`'s own artifacts: the signed authorization request, the DCR client id, the authorization code |

The two **must be different values**. `TAP_MCP_LOCAL_KEY` must be at least 32
bytes.

`tap-proxy` also holds `TAP_MCP_LOCAL_KEY`, but only to *verify* the signed
authorization request and DCR client id when it renders the connect screen
("Claude (claude.ai) is asking"). That grants no authority over tokens, and it
is not a trust downgrade: `tap-mcp` owns Dynamic Client Registration, so it is
already authoritative for client identity.

Consequences for this service, all deliberate:

- It **cannot mint** an access or refresh token. Both grants call the proxy,
  which mints and returns them; `tap-mcp` relays them to the client verbatim.
- It **cannot verify** the authorization assertion it receives on
  `/authorize/callback`. It decodes it unverified only to read the OAuth request
  inside, then relays it into the authorization code; the proxy verifies it for
  real at `/internal/mcp/token/issue` and derives `subject`/`team_id` from its
  own signature, then re-derives `agent_id`. A forged assertion therefore yields
  an authorization code that can never be exchanged.
- It **cannot verify** the access token presented to `/mcp`. That gate is now a
  cheap unverified shape/expiry/audience screen for a well-formed
  `WWW-Authenticate` challenge — it never was the security boundary. Real
  authorization happens on every tool call, when `tap-proxy` verifies the bearer,
  checks the refresh-token family for revocation and resolves the agent.

Demo mode (`DANGEROUS_TAP_MCP_DEMO_AUTH`, loopback only) has no proxy, so it
mints locally with `TAP_MCP_LOCAL_KEY`. Those tokens authenticate nothing beyond
that process — no `tap-proxy` will accept them, which is exactly the property
the split guarantees.

Outside demo mode both of the following are **required**:

- `TAP_PROXY_URL` — base URL of `tap-proxy`.
- `TAP_MCP_SERVICE_KEY` — shared secret sent as `X-TAP-Service-Key` and compared
  in constant time by the proxy. **It must be set to the same value on both
  `tap-proxy` and `tap-mcp`.** If it is unset or empty on the proxy the
  `/internal/mcp/*` endpoints are disabled entirely (404) — they are never open.
  This is deliberately *separate* from both keys above: it is an identity for
  calling those endpoints, nothing more. Presenting it proves only that the
  caller is `tap-mcp` — never who the end user is, which is why the proxy still
  re-verifies the assertion.

The browser flow is:

1. `tap-mcp` validates and signs Claude's OAuth request;
2. the browser is redirected to `TAP_DASHBOARD_URL`;
3. an existing TAP session goes directly to passkey verification;
4. otherwise the user completes TAP login and its passkey step;
5. `tap-proxy` signs a two-minute authorization assertion;
6. `tap-mcp` returns the PKCE-bound authorization code to Claude.

## Implemented surface

- `POST /mcp` — authenticated MCP Streamable HTTP endpoint
- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-protected-resource/mcp`
- `GET /.well-known/oauth-authorization-server`
- `POST /register` — DCR for public PKCE clients
- `GET /authorize` — redirect to TAP dashboard authorization
- `GET /authorize/callback` — consume TAP's passkey-backed assertion
- `POST /authorize` — demo-only consent callback
- `POST /token` — authorization-code exchange with PKCE S256, plus
  `refresh_token` grant (access tokens last 1 hour; the client renews silently
  for up to 30 days, then the user logs in + passkeys again). Authorization codes
  are single-use and refresh tokens belong to a durable, revocable family
  (rotation is an atomic DB check-and-swap; a replayed code or superseded refresh
  token is rejected). `/register`, `/authorize`, `/token` are per-IP throttled.
- `GET /health`

Refresh tokens are rotated on every use but are stateless like everything else
here, so rotation carries the original 30-day family expiry rather than
extending it, and an old refresh token cannot be individually revoked — the
kill switch is deleting the provisioned `mcp-*` agent in the dashboard: the
proxy re-resolves that agent on every tool call, so credential access dies
immediately for every token that names it. Before general availability,
authorization-code redemption and refresh-token rotation must be persisted
atomically in TAP's database (single-use codes, true rotation).
