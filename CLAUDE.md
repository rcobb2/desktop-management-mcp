# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build          # compile TypeScript to dist/
npm run clean          # remove dist/
npm run start:jamf     # run standalone JAMF MCP HTTP server (port 3001)
npm run start:intune   # run standalone Intune MCP HTTP server (port 3002)
npm test               # compile (tsconfig.test.json) + run integration tests against live JAMF
npm run test:write     # same, but enables destructive write tests (BlankPush, UpdateInventory, etc.)
```

Start scripts use Bitwarden Secrets Manager — set `BWS_ACCESS_TOKEN` in your shell, then run `./start-jamf.sh` or `./start-intune.sh`. The `bws run --` wrapper injects credentials as env vars.

Tests require credentials as env vars (set by BWS or manually) plus `TEST_COMPUTER_NAME`, `TEST_COMPUTER_SERIAL`, and `TEST_USER_EMAIL` for test fixtures.

## Architecture

Two standalone Streamable HTTP servers built on Express + `@modelcontextprotocol/sdk`. Each is single-file and self-contained — helpers like `toText`/`notFound`/`errorResult`/`resolveDevice` are duplicated per server rather than shared, so a fix in one server file does not propagate to the other:

- **`src/mcp/jamf-server.ts`** — JAMF MCP server on port 3001. `createJamfMcpServer()` builds a fresh `McpServer` + `JamfClient` per HTTP request (stateless mode, required for load-balanced/APIM deployment); every POST to `/mcp` gets its own `StreamableHTTPServerTransport` with `sessionIdGenerator: undefined`, torn down on `res.on("close")`. Exposes read tools plus write tools (`jamf_send_mdm_command`, `jamf_update_computer`, `jamf_flush_mdm_commands`).
- **`src/mcp/intune-server.ts`** — Intune MCP server on port 3002. Same per-request stateless transport pattern.

Both expose `GET /health` for load balancer checks and return 405 on `GET`/`DELETE /mcp` (stateless servers don't support session resumption). MCP endpoints: `http://localhost:3001/mcp` (JAMF) / `http://localhost:3002/mcp` (Intune)

Both require `Authorization: Bearer <token>` on `/mcp` (not on `/health`), enforced by the shared `src/utils/auth.ts` `requireBearerAuth(envVarName)` middleware — the one piece of cross-server shared code, since duplicating an auth check risks the two copies drifting out of sync. Fails closed: if the server's token env var isn't set, every `/mcp` request gets `503` rather than being let through. Accepts a comma-separated list of valid tokens per server, so a token can be rotated by adding the new one, redeploying, then removing the old one.

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

**Intune** (injected by BWS from `bws-secrets.map`):
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- `INTUNE_MCP_AUTH_TOKEN` — bearer token(s) MCP clients must present (comma-separated to allow rotation)

## Tests

`test/jamf-api.test.ts` uses Node.js built-in `node:test` — no extra test framework. Tests are live integration tests against a real JAMF Pro API. Write operations are gated behind `JAMF_TEST_WRITE=1`. Tests that may fail due to API client permissions use `permissionAwareTest()` which treats 401/403/404 as a skip rather than a failure.

## Deployment

Both servers run in production as Podman quadlet containers on `podman02` (built from the repo-root `Dockerfile`, one image, two containers — the Intune container overrides the image's default `CMD` via the quadlet's `Exec=`), fronted by Caddy which terminates TLS and reverse-proxies to the container's plain-HTTP port. The servers themselves never see TLS directly. Client-facing URLs are `https://jamf-mcp.colgate.edu/mcp` and `https://intune-mcp.colgate.edu/mcp` — internal DNS only, no public exposure, and several JAMF tools are destructive, so `/mcp` also requires a bearer token (see Environment Variables) on top of the network restriction — defense in depth, not a substitute for it. Deploy/redeploy playbooks live in `IAC/ansible-servers/linux/apps/desktop-management-mcp.yml` (full deploy) and `desktop-management-mcp-update.yml` (code-only redeploy); see `IAC/CLAUDE.md` for the broader Terraform → Ansible dispatch pipeline.
