# Desktop Management MCP Server

Standalone [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers for JAMF Pro and Microsoft Intune. AI assistants (Claude Code, Gemini CLI, OpenCode, etc.) connect over HTTP and call device-management tools.

## Architecture

```
MCP Client  ──HTTP──▶  jamf-server (port 3001)  ──▶  JAMF Pro REST API
MCP Client  ──HTTP──▶  intune-server (port 3002) ──▶  Microsoft Graph API
```

Each server is a stateless Express app using `@modelcontextprotocol/sdk`. Every POST to `/mcp` creates a fresh `StreamableHTTPServerTransport`. Secrets are injected at runtime by [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) — no credentials are stored in the repo.

## Prerequisites

- Node.js 24+
- [BWS CLI](https://github.com/bitwarden/sdk-sm) (`bws` in PATH)
- A Bitwarden Secrets Manager project with the secrets listed in `bws-secrets.map`
- JAMF Pro API client credentials (OAuth2)
- Azure AD app registration with Microsoft Graph permissions (for Intune)
- (Optional) A Microsoft Entra ID resource app registration with App Roles, if you want per-user OAuth instead of the shared static token — see [Authentication](#authentication)

## Quick Start

```bash
# Install dependencies and build
npm install && npm run build

# Set your BWS machine account access token
export BWS_ACCESS_TOKEN="<your-token>"

# Start whichever server(s) you need
./start-jamf.sh    # JAMF MCP on http://localhost:3001/mcp
./start-intune.sh  # Intune MCP on http://localhost:3002/mcp
```

See `bws-secrets.map` for the secret names to create in your BWS project.

## Authentication

`/mcp` on both servers requires `Authorization: Bearer <token>` (not required on `/health`). Requests without a valid token get `401`; if a server has no auth mechanism configured at all, every `/mcp` request fails closed with `503` rather than being let through unauthenticated. Two independent modes are accepted on the same endpoint:

1. **Static bearer token** — `JAMF_MCP_AUTH_TOKEN` / `INTUNE_MCP_AUTH_TOKEN` (comma-separated to allow rotating without downtime). This is the only mechanism available to non-interactive automation (scripts, n8n), and grants that server's full tool set — every tool below, including the destructive ones. Treat this token as equivalent to full admin access to the corresponding backend.
2. **Entra ID OAuth** (`ENTRA_OAUTH_ENABLED=true`) — a JWT issued by Microsoft Entra ID, verified against Entra's JWKS. Tool visibility is driven by the token's `roles` claim (`Jamf.Read`, `Jamf.Write`, `Intune.Read` — see `src/utils/roles.ts`): a tool a caller's role doesn't grant is never registered on that request's server instance, so it's not just hidden, it's uncallable. This lets real staff authenticate as themselves instead of sharing one all-or-nothing token.

**`jamf_send_mdm_command` is flagged `destructiveHint: true`** and supports `EraseDevice` (irreversible) among other commands; it and the other nine write/mutating JAMF tools (computer/prestage/inventory-preload updates, MDM flush, plus the script/package/smart-group/policy create-and-update tools) are gated behind the `Jamf.Write` role under Entra auth (or the static token, which grants both read and write). Anyone holding a valid `JAMF_MCP_AUTH_TOKEN` can call all of them — the token itself is the access boundary for the automation path.

In production (podman02), network exposure is layered on top of this: internal-DNS-only hostnames, plus a Caddy IP allowlist. `/mcp`'s bearer-token requirement is the one layer that's actual authentication rather than network-level exposure control, and the one that still holds if the other two are ever misconfigured — see `CLAUDE.md` for the full deployment/defense-in-depth writeup.

### Setting up Entra ID OAuth (optional)

1. Register one Entra app to act as the OAuth resource server, e.g. "Desktop Management MCP". Give it an Application ID URI using a verified-domain form (a bare custom string like `api://desktop-mgmt-mcp` is rejected by tenants that require a verified domain — Colgate's does; use `api://<verified-domain>/desktop-mgmt-mcp` instead), a delegated `access_as_user` scope, and App Roles matching `src/utils/roles.ts` (`Jamf.Read`, `Jamf.Write`, `Intune.Read`). Turn on "User assignment required" and assign roles to users or groups via Enterprise Applications.
2. **Also register each server's own literal MCP URL** (e.g. `https://jamf-mcp.colgate.edu/mcp`) as an *additional* `identifierUris` entry on that same app. MCP-spec clients (OpenCode, `mcp-remote`) send an RFC 8707 `resource` parameter set to that literal URL; if it doesn't resolve to the same app as the requested `scope`, Entra rejects the request with `AADSTS9010010`. One resource app can have multiple identifier URIs, so this doesn't require separate apps per server.
3. Register one small public/native client app (PKCE, no secret) for interactive clients, pre-authorized for the resource app's `access_as_user` scope so users skip the consent screen.
4. Decode a real issued token before assuming the audience format: Entra sometimes audiences tokens to the resource app's **GUID app ID** rather than its Application ID URI, specifically when a client sends the `resource` parameter — confirmed live, not something the `requestedAccessTokenVersion: 2` setting prevents. `createEntraVerifier` accepts both forms via the optional `ENTRA_RESOURCE_APP_ID` env var.

See `CLAUDE.md`'s Authentication and roles section for the code-level details, and the per-client config below for what actually works today.

## Environment Variables

Injected by `bws run` from your BWS project (see `bws-secrets.map`):

**JAMF Pro:**
- `JAMF_URL` — e.g. `https://yourorg.jamfcloud.com`
- `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`
- `JAMF_MCP_AUTH_TOKEN` — bearer token(s) MCP clients must present (comma-separated to allow rotation)
- `JAMF_MCP_PUBLIC_URL` — this server's externally-visible origin, e.g. `https://jamf-mcp.colgate.edu` (required only when `ENTRA_OAUTH_ENABLED=true`, used to build RFC 9728 resource metadata)
- `JAMF_PACKAGE_UPLOAD_DIR` — directory `jamf_upload_package` may read files from on this server's own filesystem. Required for that tool; it refuses every call if unset.

**Microsoft Intune:**
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` — Graph app-only client credentials for device data; unrelated to the Entra auth vars below
- `INTUNE_MCP_AUTH_TOKEN` — bearer token(s) MCP clients must present (comma-separated to allow rotation)
- `INTUNE_MCP_PUBLIC_URL` — this server's externally-visible origin, e.g. `https://intune-mcp.colgate.edu` (required only when `ENTRA_OAUTH_ENABLED=true`)

**Entra ID auth** (optional; shared by both servers — see `CLAUDE.md` for the caveat that a single shared deployment env file means both servers currently enable/disable together despite the per-service naming):
- `ENTRA_OAUTH_ENABLED` — `"true"` to accept Entra-issued bearer tokens on `/mcp` in addition to the static token
- `ENTRA_TENANT_ID` — Entra tenant GUID (deliberately separate from `AZURE_TENANT_ID` above — different app registration, different purpose, don't reuse one BWS secret for both)
- `ENTRA_RESOURCE_APP_ID_URI` — Application ID URI of the resource app, e.g. `api://colgate.edu/desktop-mgmt-mcp`
- `ENTRA_RESOURCE_APP_ID` — GUID app ID of the same resource app; accepted as an alternate valid `aud` value (see Authentication above)

### Azure AD Graph Permissions

The Intune app registration needs these **Application** permissions (with admin consent):
- `Device.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `Group.Read.All`
- `User.Read.All`

## Client Configuration

Point clients at `http://localhost:<port>/mcp` for a locally-running server, or at the `https://` hostname below when talking to the podman02 deployment (Caddy terminates TLS and reverse-proxies to the container over plain HTTP — the servers themselves never speak TLS directly).

| Environment | JAMF URL | Intune URL |
|---|---|---|
| Local (`./start-jamf.sh` / `./start-intune.sh`) | `http://localhost:3001/mcp` | `http://localhost:3002/mcp` |
| podman02 (internal DNS only) | `https://jamf-mcp.colgate.edu/mcp` | `https://intune-mcp.colgate.edu/mcp` |

The podman02 hostnames resolve only inside Colgate's network (internal DNS locale) — see `IAC/ansible-servers/linux/apps/desktop-management-mcp.yml`. **Both deployments require a bearer token on `/mcp`** (see [Authentication](#authentication) above); several JAMF tools are destructive, so treat the token — not just the URL — as sensitive.

### Claude Code — static token (works today)

```json
{
  "mcpServers": {
    "jamf": {
      "type": "http",
      "url": "https://jamf-mcp.colgate.edu/mcp",
      "headers": { "Authorization": "Bearer <JAMF_MCP_AUTH_TOKEN value>" }
    },
    "intune": {
      "type": "http",
      "url": "https://intune-mcp.colgate.edu/mcp",
      "headers": { "Authorization": "Bearer <INTUNE_MCP_AUTH_TOKEN value>" }
    }
  }
}
```

Or via the CLI: `claude mcp add --transport http jamf https://jamf-mcp.colgate.edu/mcp --header "Authorization: Bearer <token>"`.

### Claude Code — Entra ID OAuth (per-user identity)

Claude Code's *native* HTTP-transport OAuth (`claude mcp add --transport http ... --client-id ...`) does not send a `scope` parameter and fails against Entra with `AADSTS900144` — confirmed live, not a hypothetical. Use the `mcp-remote` bridge instead, which supports an explicit scope:

```bash
npm install -g mcp-remote   # or use npx, at the cost of a re-fetch each launch
```

```json
{
  "type": "stdio",
  "command": "mcp-remote",
  "args": [
    "https://jamf-mcp.colgate.edu/mcp",
    "3334",
    "--static-oauth-client-info",
    "{\"client_id\":\"<public-client-id>\"}",
    "--static-oauth-client-metadata",
    "{\"scope\":\"openid profile offline_access <resource-app-id-uri>/access_as_user\"}"
  ]
}
```

Add with `claude mcp add-json jamf-remote -s user '<json above>'`, then trigger the OAuth flow with `claude mcp get jamf-remote` (or just start using its tools — first use triggers auth). Pin an explicit port per server (mcp-remote otherwise derives one from a hash of the server URL, which works but is less predictable) and register the exact resulting redirect URI — `http://localhost:<port>/oauth/callback`, note `localhost` not `127.0.0.1`, and a different path than OpenCode uses below — on the Entra public client.

### Gemini CLI (`~/.gemini/settings.json`)

```json
{
  "mcpServers": {
    "jamf": { "httpUrl": "https://jamf-mcp.colgate.edu/mcp", "headers": { "Authorization": "Bearer <JAMF_MCP_AUTH_TOKEN value>" } },
    "intune": { "httpUrl": "https://intune-mcp.colgate.edu/mcp", "headers": { "Authorization": "Bearer <INTUNE_MCP_AUTH_TOKEN value>" } }
  }
}
```

### OpenCode (`~/.config/opencode/opencode.json`)

Static token:

```json
{
  "mcp": {
    "jamf": {
      "type": "remote",
      "url": "https://jamf-mcp.colgate.edu/mcp",
      "enabled": true,
      "headers": { "Authorization": "Bearer <JAMF_MCP_AUTH_TOKEN value>" }
    }
  }
}
```

Entra ID OAuth (confirmed working live end-to-end — `opencode mcp auth jamf` drives a normal browser PKCE flow):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "jamf": {
      "type": "remote",
      "url": "https://jamf-mcp.colgate.edu/mcp",
      "enabled": true,
      "oauth": {
        "clientId": "<public-client-id>",
        "scope": "openid profile offline_access <resource-app-id-uri>/access_as_user"
      }
    }
  }
}
```

OpenCode's OAuth callback listens on a fixed `http://127.0.0.1:19876/mcp/oauth/callback` (not currently configurable) — register that exact redirect URI on the Entra public client. If OpenCode runs on a different machine than your browser (e.g. a remote dev VM), the redirect won't reach the listener; tunnel the port with `ssh -L 19876:localhost:19876 <host>` before running `opencode mcp auth`.

Swap in the `http://localhost:<port>/mcp` URLs from the table above for local development.

## MCP Tools Reference

### JAMF Pro Tools

`jamf_send_mdm_command` is the one tool flagged `destructiveHint: true` (supports `EraseDevice`, irreversible on Apple Silicon without the erasure passcode). It and the other write tools below require the `Jamf.Write` role under Entra auth. `jamf_create_script`/`jamf_upload_package`/`jamf_create_smart_group` are upserts by name (re-running updates the existing object in place); `jamf_create_policy` always creates a new policy; `jamf_update_policy` handles enable/disable + scope widening for an existing one. See `CLAUDE.md` for the Classic-API-requires-XML detail and the known Delete-permission gap (Scripts/Policies/Smart Groups can be created/updated but not deleted by this API client — package deletion does work).

| Tool | Description | Parameters |
|------|-------------|------------|
| `jamf_get_computer` | Computer details by name | `computerName` |
| `jamf_list_computers` | Search/list computers, optionally by asset tag | `assetTag?`, `page?`, `pageSize?` |
| `jamf_get_computer_by_serial` | Computer details by serial number | `serial` |
| `jamf_get_computers_by_user` | Macs by username / name / email | `userIdentifier` |
| `jamf_get_mobile_device` | Mobile device details by name | `deviceName` |
| `jamf_list_mobile_devices` | Fleet-wide mobile device list/breakdown (type, managed, supervised, model) | `type?`, `managed?`, `supervised?` |
| `jamf_list_smart_groups` | List smart groups | `type` (`"computer"` or `"mobile_device"`) |
| `jamf_get_smart_group_members` | Members of a smart group | `groupId` |
| `jamf_list_static_groups` | Static computer groups | — |
| `jamf_list_sites` | All JAMF sites | — |
| `jamf_list_scripts` | Scripts (with optional filter/pagination) | `name?`, `page?`, `pageSize?` |
| `jamf_list_packages` | Packages (with optional filter/pagination) | `name?`, `page?`, `pageSize?` |
| `jamf_list_inventory_preload` | Inventory preload records | `page?`, `pageSize?` |
| `jamf_upsert_inventory_preload_record` | Create/update a preload record by serial (pre-enrollment asset tag/building/room/user) | `serialNumber`, `assetTag?`, `building?`, `room?`, `username?`, `fullName?`, `emailAddress?`, `deviceType?` |
| `jamf_list_prestage_configs` | Computer prestage enrollment configs | — |
| `jamf_assign_computers_to_prestage` | Scope serials into a prestage's enrollment | `prestage`, `serialNumbers` |
| `jamf_list_policies` | Policies list | `name?`, `page?`, `pageSize?` |
| `jamf_get_policy` | Policy details | `policyId` |
| `jamf_list_configuration_profiles` | Configuration profiles | `name?` |
| `jamf_list_patch_policies` | Patch policies | `page?`, `pageSize?` |
| `jamf_list_categories` | Categories | `page?`, `pageSize?` |
| `jamf_list_departments` | Departments | — |
| `jamf_get_filevault_status` | FileVault encryption status | `computerNameOrSerial` |
| `jamf_send_mdm_command` | Send an MDM command (`EraseDevice`, `RestartDevice`, `UnlockUserAccount`, etc.) | `computerNameOrSerial`, `command`, `unlockUsername?`, `erasurePasscode?` |
| `jamf_update_computer` | Update computer inventory fields | `computerNameOrSerial`, `username?`, `realName?`, `emailAddress?`, `department?`, `building?`, `room?`, `assetTag?` |
| `jamf_flush_mdm_commands` | Flush pending/failed MDM commands | `computerNameOrSerial`, `status?` |
| `jamf_create_script` | Create/update a script (upsert by name) | `name`, `scriptContents`, `categoryName?`, `info?`, `notes?`, `priority?`, `osRequirements?`, `parameter4?`...`parameter11?` |
| `jamf_upload_package` | Upload a .pkg/.dmg and create/update its package object (upsert by name) | `localFilePath` (server-side path, inside `JAMF_PACKAGE_UPLOAD_DIR`), `packageName`, `categoryName?`, `priority?`, plus install-behavior flags |
| `jamf_create_smart_group` | Create/update an Application Title+Version detection smart group (upsert by name) | `name`, `applicationTitle`, `applicationVersion`, `siteId?` |
| `jamf_create_policy` | Create a policy scoped to smart/static groups; script-only policies supported | `name`, `enabled?`, trigger/frequency fields, `categoryName?`, `targetGroupNames?`, `exclusionGroupNames?`, `scripts?`, `packages?`, `selfService?`, `maintenanceRecon?` |
| `jamf_update_policy` | Enable/disable + widen/narrow an existing policy's scope | `policy`, `enabled?`, `addTargetGroupNames?`, `removeTargetGroupNames?`, `addExclusionGroupNames?`, `removeExclusionGroupNames?` |

### Microsoft Intune Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `intune_get_autopilot_status` | Autopilot profile & status | `serialNumber?`, `deviceName?` |
| `intune_get_device_by_name` | Managed device by name | `deviceName` |
| `intune_get_device_by_serial` | Managed device by serial number | `serialNumber` |
| `intune_get_devices_by_user` | All devices for a user | `userIdentifier` |
| `intune_list_devices` | Fleet-wide device list/breakdown (OS, compliance, management agent) — `intuneManagedOnly` excludes Defender-sensor-only/ConfigMgr-only devices | `operatingSystem?`, `complianceState?`, `managementState?`, `managementAgent?`, `intuneManagedOnly?` |
| `intune_get_device_groups` | Device group memberships | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_get_device_apps` | Detected & assigned apps | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_list_configuration_policies` | Configuration policies (classic + settings catalog) | `policyName?`, `platform?` |
| `intune_troubleshoot_device_policies` | Device-level policy deployment diagnostics | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_get_policy_assignments` | Assignment targets for a policy, by ID or name | `policyId?`, `policyName?`, `source?` |
| `intune_troubleshoot_policy` | Correlates policy assignment + device state | `deviceName?`, `deviceId?`, `serialNumber?`, `policyId?`, `policyName?`, `source?` |
| `intune_list_app_deployments` | Intune app deployments | `appName?`, `publisher?`, `platform?` |
| `intune_get_app_assignments` | Assignment targets for an app, by ID or name | `appId?`, `appName?` |
| `intune_troubleshoot_app` | Correlates app assignment + device app status | `deviceName?`, `deviceId?`, `serialNumber?`, `appId?`, `appName?` |

## Running Tests

```bash
export BWS_ACCESS_TOKEN="<your-token>"
bws run --access-token "$BWS_ACCESS_TOKEN" -- \
  TEST_COMPUTER_NAME="<name>" \
  TEST_COMPUTER_SERIAL="<serial>" \
  TEST_USER_EMAIL="<email>" \
  npm test
```

Add `JAMF_TEST_WRITE=1` to enable destructive write tests (MDM commands, inventory updates) against live JAMF Pro. The script/smart-group/policy upsert tests additionally need a pre-existing, manually-created fixture object named via `TEST_SCRIPT_NAME`/`TEST_SMART_GROUP_NAME`/`TEST_POLICY_NAME` (each optional — the test skips if unset or if no object with that name exists yet, since this API client can create/update but not delete those object types). The package upsert test is fully self-cleaning via `TEST_PACKAGE_PATH` (also optional) pointing at a small `.pkg`/`.dmg` inside `JAMF_PACKAGE_UPLOAD_DIR`.

`npm run test:unit` runs just the auth/roles unit tests (`test/auth.test.ts`) — no live credentials or network access needed, since they exercise `requireMcpAuth`'s fallback/fail-closed logic and the `roles.ts` helpers against fakes.

## Project Structure

```
├── src/
│   ├── mcp/
│   │   ├── jamf-server.ts      # JAMF standalone MCP server (port 3001)
│   │   └── intune-server.ts    # Intune standalone MCP server (port 3002)
│   ├── jamf/
│   │   └── jamf-api.ts         # JAMF Pro REST + Classic API client
│   ├── intune/
│   │   └── graph-api.ts        # Microsoft Graph / Intune client
│   └── utils/
│       ├── auth.ts             # requireMcpAuth: static-token / Entra JWT dual-mode middleware
│       ├── entra-jwt.ts        # Entra JWT verification (jose) + RFC 9728 resource metadata
│       ├── roles.ts            # Entra App Role constants and role-checking helpers
│       └── logger.ts           # Output formatting helpers
├── test/
│   ├── jamf-api.test.ts        # Live integration tests against real JAMF Pro
│   └── auth.test.ts            # Auth/roles unit tests — no live credentials needed
├── start-jamf.sh               # BWS-wrapped launcher for JAMF server
├── start-intune.sh             # BWS-wrapped launcher for Intune server
└── bws-secrets.map             # Required BWS secret names and descriptions
```

## Additional Resources

- [MCP Specification](https://modelcontextprotocol.io/)
- [JAMF Pro API Docs](https://developer.jamf.com/jamf-pro/reference/classic-api)
- [Microsoft Graph API Docs](https://learn.microsoft.com/en-us/graph/overview)
- [Bitwarden Secrets Manager](https://bitwarden.com/help/secrets-manager-overview/)
- [MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) (RFC 8707 resource indicators, RFC 9728 protected resource metadata)
