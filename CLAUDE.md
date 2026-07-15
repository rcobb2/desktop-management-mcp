# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build          # compile TypeScript to dist/
npm run clean          # remove dist/
npm run start:jamf     # run standalone JAMF MCP HTTP server (port 3001)
npm run start:intune   # run standalone Intune MCP HTTP server (port 3002)
npm test               # compile (tsconfig.test.json) + run integration tests against live JAMF, plus the auth unit tests
npm run test:write     # same, but enables destructive write tests (BlankPush, UpdateInventory, etc.)
npm run test:unit      # auth/roles unit tests only — no live JAMF credentials or network required
```

Start scripts use Bitwarden Secrets Manager — set `BWS_ACCESS_TOKEN` in your shell, then run `./start-jamf.sh` or `./start-intune.sh`. The `bws run --` wrapper injects credentials as env vars.

Tests require credentials as env vars (set by BWS or manually) plus `TEST_COMPUTER_NAME`, `TEST_COMPUTER_SERIAL`, and `TEST_USER_EMAIL` for test fixtures.

## Architecture

Two standalone Streamable HTTP servers built on Express + `@modelcontextprotocol/sdk`. Each is single-file and self-contained — helpers like `toText`/`notFound`/`errorResult`/`resolveDevice` are duplicated per server rather than shared, so a fix in one server file does not propagate to the other:

- **`src/mcp/jamf-server.ts`** — JAMF MCP server on port 3001. `createJamfMcpServer(roles)` builds a fresh `McpServer` + `JamfClient` per HTTP request (stateless mode, required for load-balanced/APIM deployment), registering only the tools the caller's resolved roles permit; every POST to `/mcp` gets its own `StreamableHTTPServerTransport` with `sessionIdGenerator: undefined`, torn down on `res.on("close")`. Exposes read tools plus write tools (`jamf_send_mdm_command`, `jamf_update_computer`, `jamf_assign_computers_to_prestage`, `jamf_flush_mdm_commands`).
- **`src/mcp/intune-server.ts`** — Intune MCP server on port 3002. Same per-request stateless transport pattern.

Both expose `GET /health` for load balancer checks and return 405 on `GET`/`DELETE /mcp` (stateless servers don't support session resumption). MCP endpoints: `http://localhost:3001/mcp` (JAMF) / `http://localhost:3002/mcp` (Intune)

Both require `Authorization: Bearer <token>` on `/mcp` (not on `/health`), enforced by the shared `src/utils/auth.ts` `requireMcpAuth(options)` middleware — one of three intentionally-shared modules (alongside `src/utils/entra-jwt.ts` and `src/utils/roles.ts`), since duplicating auth/role logic risks the two servers' copies drifting out of sync. `requireMcpAuth` accepts EITHER of two independent auth modes on the same request:
1. A static bearer token from `JAMF_MCP_AUTH_TOKEN`/`INTUNE_MCP_AUTH_TOKEN` (comma-separated to allow rotation) — unchanged from before Entra auth existed, and still the only mechanism for non-interactive automation (scripts, n8n). Grants that server's full role set (see below), matching this token's original behavior exactly.
2. When `ENTRA_OAUTH_ENABLED=true`, an Entra-issued JWT verified against Entra's JWKS (`src/utils/entra-jwt.ts`, using `jose`) — tool visibility is then driven by the token's `roles` claim.

Fails closed exactly as before: if neither mode is configured for a server, every `/mcp` request gets `503`.

### Authentication and roles

Role names are Entra App Roles defined on one shared "Desktop Management MCP" resource app registration: `Jamf.Read`, `Jamf.Write`, `Intune.Read` (`src/utils/roles.ts`). Each server only inspects its own role names via `hasRole()`/`resolveRolesFromAuthInfo()` and ignores the rest — there's no isolation lost by sharing one resource app, since role *assignment* (who gets which role) is still granted per-role, per-user/group in Entra independently.

Both `createJamfMcpServer(roles)` / `createIntuneMcpServer(roles)` take the caller's resolved role array and wrap each `server.registerTool(...)` call in `if (hasRole(roles, ...))` — a tool a caller's role doesn't grant is never registered on that request's `McpServer`, so it's simply not callable (not just hidden). The four destructive/mutating JAMF tools (`jamf_send_mdm_command`, `jamf_update_computer`, `jamf_assign_computers_to_prestage`, `jamf_flush_mdm_commands`) additionally call `assertRole(roles, JAMF_WRITE)` inside their own handler as a defense-in-depth check against a future refactor accidentally omitting the registration-time gate. All other tools rely solely on the registration-time gate.

**Entra ID does not support OAuth Dynamic Client Registration (RFC 7591)**, which real MCP clients lean on for zero-config setup — this project deliberately does NOT implement a custom OAuth broker/proxy to paper over that gap (see the plan history for the phased rationale); it's a resource-server-only integration. Practical per-client setup, confirmed by live testing (not just read from docs):
- **OpenCode** — works today: register a small native/public Entra client app (PKCE, no secret) and configure it as `oauth.clientId` in `opencode.json`, with an explicit `oauth.scope` (Entra's `/authorize` requires a non-empty `scope`; OpenCode doesn't infer one). `opencode mcp auth <name>` drives a normal browser PKCE flow.
- **Codex CLI** — no static-`clientId` OAuth support upstream yet; keep using `bearer_token_env_var` pointing at the existing static token. Not tied to per-user Entra identity in this phase.
- **Claude Code** — its *native* HTTP-transport OAuth (`claude mcp add --transport http ... --client-id ... --callback-port ...`) sends no `scope` parameter at all and fails against Entra with `AADSTS900144: The request body must contain the following parameter: 'scope'` — confirmed live, not an assumption; there's no CLI flag to inject one. Use the `mcp-remote` npm package instead, as a stdio↔http bridge, with **both** `--static-oauth-client-info '{"client_id":"<public-client-id>"}'` and `--static-oauth-client-metadata '{"scope":"openid profile offline_access <resource-scope>"}'` (the metadata flag is required — client-info alone doesn't carry scope). Add it via `claude mcp add-json <name> '{"type":"stdio","command":"mcp-remote","args":["<mcp-url>","<fixed-port>","--static-oauth-client-info","...","--static-oauth-client-metadata","..."]}'`. Pin an explicit port (mcp-remote otherwise derives one from a hash of the server URL) and register its exact callback redirect URI (`http://localhost:<port>/oauth/callback` — note `localhost`, not `127.0.0.1`, and note the path differs from OpenCode's own `/mcp/oauth/callback`) on the Entra public client. Revisit if/when Claude Code's native flow gains scope support upstream.

**Multiple identifier URIs are required on the resource app**, one reason this took real testing to get right: any MCP-spec client that sends the RFC 8707 `resource` parameter (OpenCode and `mcp-remote` both do, using the literal MCP server URL taken from this project's own RFC 9728 protected-resource metadata) needs that exact URL registered as an `identifierUris` entry on the Entra app — Entra rejects the request with `AADSTS9010010` if `resource` and `scope` resolve to different app identities. Since jamf-mcp and intune-mcp are different URLs sharing one resource app, both `https://jamf-mcp.colgate.edu/mcp` and `https://intune-mcp.colgate.edu/mcp` are registered as additional identifier URIs alongside the abstract `api://colgate.edu/desktop-mgmt-mcp` one.

### API Clients

- `src/jamf/jamf-api.ts` — `JamfClient`: authenticates via OAuth2 client-credentials (`POST /api/v1/oauth/token`), caches the bearer token and re-authenticates lazily via `ensureAuthenticated()` once it's within 60s of `expires_in`. Uses JAMF Pro REST API v1/v3 for most endpoints (e.g. computer lookups go through `computers-inventory` to resolve an ID, then `computers-inventory-detail/:id` for the full record); falls back to the Classic API (XML-based, e.g. policies, configuration profiles) where v1/v3 doesn't cover a resource.
- `src/intune/graph-api.ts` — `IntuneClient`: uses `@azure/identity` `ClientSecretCredential` + `@microsoft/microsoft-graph-client`'s `TokenCredentialAuthenticationProvider` (token acquisition/caching handled by the SDK, not manually). Mixes Graph API versions per-endpoint — e.g. Autopilot lookups try a `v1.0` server-side `$filter` first and fall back to fetching a `beta` batch and filtering client-side if the filter 500s.

Both clients log via `src/utils/logger.ts`, a plain `console.*`-based structured logger (`createLogger(service)` + `logApiCall`/`logAuth` helpers) — the doc comment calling it "for Azure Functions" is a holdover from where this code was extracted from; there's no Azure Functions runtime here. `LOG_LEVEL=debug` enables debug-level output.

### Device/name resolution

Read tools that take a human name generally resolve it server-side rather than requiring an ID:
- Intune: `resolveDevice()` (in `intune-server.ts`) accepts `deviceName`, `deviceId`, or `serialNumber` and normalizes to `{ deviceId, azureADDeviceId }`. `resolveAppByName()` and `resolvePolicyByName()` resolve human-readable names to GUIDs by fetching the full list and matching case-insensitively (exact match preferred, first partial match as fallback).
- JAMF: several `JamfClient` methods (e.g. `getComputerByName`, `updateComputerRecord`, `sendComputerMdmCommand`) accept a name/serial and internally look up the JAMF numeric ID before calling the detail/write endpoint.

### Tool registration pattern

Tools are registered via `server.registerTool(name, schema, handler)` with Zod schemas and `annotations` (`readOnlyHint`, `openWorldHint`, `destructiveHint`) describing side effects. Handlers return `{ content: [{ type: "text", text }] }`, or `{ isError: true, content: [...] }` on failure/not-found. Nearly every read tool takes an optional `response_format: "markdown" | "json"` (default `"markdown"`) — the shared `toText(data, format, markdownFn)` helper either dumps raw JSON or renders a hand-built markdown summary, so adding a field to markdown output means also checking whether it should surface in the raw JSON path (it already does, since JSON mode returns the full API response object, not the trimmed markdown view).

## Environment Variables

**JAMF** (injected by BWS from `bws-secrets.map`):
- `JAMF_URL` — e.g. `https://yourorg.jamfcloud.com`
- `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`
- `JAMF_MCP_AUTH_TOKEN` — bearer token(s) MCP clients must present (comma-separated to allow rotation)
- `JAMF_MCP_PUBLIC_URL` — this server's externally-visible origin, e.g. `https://jamf-mcp.colgate.edu` (required only when `ENTRA_OAUTH_ENABLED=true`)

**Intune** (injected by BWS from `bws-secrets.map`):
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` — Graph app-only client credentials for device data, unrelated to the Entra auth vars below
- `INTUNE_MCP_AUTH_TOKEN` — bearer token(s) MCP clients must present (comma-separated to allow rotation)
- `INTUNE_MCP_PUBLIC_URL` — this server's externally-visible origin, e.g. `https://intune-mcp.colgate.edu` (required only when `ENTRA_OAUTH_ENABLED=true`)

**Entra ID auth** (shared by both servers, each can enable independently; injected by BWS from `bws-secrets.map`):
- `ENTRA_OAUTH_ENABLED` — `"true"` to accept Entra-issued bearer tokens on `/mcp` in addition to the static token
- `ENTRA_TENANT_ID` — Entra tenant GUID (deliberately separate from `AZURE_TENANT_ID` above — different app registration, different purpose)
- `ENTRA_RESOURCE_APP_ID_URI` — Application ID URI of the "Desktop Management MCP" resource app, e.g. `api://colgate.edu/desktop-mgmt-mcp` (Entra tenants that require a verified domain in the URI, as Colgate's does, will reject a bare `api://desktop-mgmt-mcp` — confirmed live)
- `ENTRA_RESOURCE_APP_ID` — GUID app ID of the same resource app; accepted as an alternate `aud` value. MCP-spec clients that send the RFC 8707 `resource` parameter (e.g. OpenCode) get tokens audienced to this GUID rather than the URI above, even with `requestedAccessTokenVersion: 2` set on the app — confirmed against a real issued token, not assumed from docs.

## Tests

`test/jamf-api.test.ts` uses Node.js built-in `node:test` — no extra test framework. Tests are live integration tests against a real JAMF Pro API. Write operations are gated behind `JAMF_TEST_WRITE=1`. Tests that may fail due to API client permissions use `permissionAwareTest()` which treats 401/403/404 as a skip rather than a failure.

`test/auth.test.ts` covers `requireMcpAuth`'s dual-mode fallback/fail-closed behavior and the `roles.ts` helpers with fakes — no live credentials or network access needed, hence the separate `npm run test:unit` script.

## Deployment

Both servers run in production as Podman quadlet containers on `podman02` (built from the repo-root `Dockerfile`, one image, two containers — the Intune container overrides the image's default `CMD` via the quadlet's `Exec=`), fronted by Caddy which terminates TLS and reverse-proxies to the container's plain-HTTP port. The servers themselves never see TLS directly. Client-facing URLs are `https://jamf-mcp.colgate.edu/mcp` and `https://intune-mcp.colgate.edu/mcp` — internal DNS only, no public exposure, and several JAMF tools are destructive, so `/mcp` also requires a bearer token (see Environment Variables) on top of the network restriction — defense in depth, not a substitute for it. Deploy/redeploy playbooks live in `IAC/ansible-servers/linux/apps/desktop-management-mcp.yml` (full deploy) and `desktop-management-mcp-update.yml` (code-only redeploy); see `IAC/CLAUDE.md` for the broader Terraform → Ansible dispatch pipeline.

Both quadlets are rendered from **one shared env file** (`/etc/desktop-management-mcp/desktop-management-mcp.env`, one Ansible template, one set of vars) — so despite `ENTRA_OAUTH_ENABLED` reading as a per-server toggle in code, there is currently no way to enable Entra auth for jamf-mcp without also enabling it for intune-mcp, or vice versa. This is a known gap versus the original rollout plan (which assumed independent enablement), left as-is because it's low-risk while role assignment is still solo-testing scale — no one has an `Intune.*` role yet. Splitting into two env files (or two env-var names) would be needed to truly decouple this before a wider pilot.
