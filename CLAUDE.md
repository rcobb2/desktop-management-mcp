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

Two standalone Streamable HTTP servers built on Express + `@modelcontextprotocol/sdk`:

- **`src/mcp/jamf-server.ts`** — JAMF MCP server on port 3001. Each POST to `/mcp` creates a new stateless `StreamableHTTPServerTransport`. Exposes read tools plus write tools (`jamf_send_mdm_command`, `jamf_update_computer`, `jamf_flush_mdm_commands`).
- **`src/mcp/intune-server.ts`** — Intune MCP server on port 3002. Same transport pattern.

MCP endpoints: `http://localhost:3001/mcp` (JAMF) / `http://localhost:3002/mcp` (Intune)

### API Clients

- `src/jamf/jamf-api.ts` — `JamfClient`: authenticates via OAuth client credentials. Uses JAMF Pro REST API v1/v2 for most endpoints; falls back to Classic API (XML) for policies and configuration profiles.
- `src/intune/graph-api.ts` — `IntuneClient`: uses `@azure/identity` `ClientSecretCredential` + `@microsoft/microsoft-graph-client` to query Microsoft Graph / Intune endpoints.

### Device resolution (Intune)

`resolveDevice()` accepts `deviceName`, `deviceId`, or `serialNumber` and normalizes to `{ deviceId, azureADDeviceId }`. `resolveAppByName()` and `resolvePolicyByName()` resolve human-readable names to GUIDs by fetching the full list and matching case-insensitively (exact match preferred, first partial match as fallback).

### Tool registration pattern

Tools are registered via `server.registerTool(name, schema, handler)`. Each handler returns `{ content: [{ type: "text", text: ... }] }`. The `src/utils/logger.ts` utility formats output as markdown with a JSON detail block.

## Environment Variables

**JAMF** (injected by BWS from `bws-secrets.map`):
- `JAMF_URL` — e.g. `https://yourorg.jamfcloud.com`
- `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`

**Intune** (injected by BWS from `bws-secrets.map`):
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

## Tests

`test/jamf-api.test.ts` uses Node.js built-in `node:test` — no extra test framework. Tests are live integration tests against a real JAMF Pro API. Write operations are gated behind `JAMF_TEST_WRITE=1`. Tests that may fail due to API client permissions use `permissionAwareTest()` which treats 401/403/404 as a skip rather than a failure.
