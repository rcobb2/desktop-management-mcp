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

## Environment Variables

Injected by `bws run` from your BWS project (see `bws-secrets.map`):

**JAMF Pro:**
- `JAMF_URL` — e.g. `https://yourorg.jamfcloud.com`
- `JAMF_CLIENT_ID`, `JAMF_CLIENT_SECRET`

**Microsoft Intune:**
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

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

The podman02 hostnames resolve only inside Colgate's network (internal DNS locale) — see `IAC/ansible-servers/linux/apps/desktop-management-mcp.yml`. Neither deployment has authentication on the `/mcp` endpoint, and several JAMF tools are destructive (`EraseDevice`, `RestartDevice`, `UnlockUserAccount`, etc.) — treat the URL itself as sensitive.

### Claude Code (`~/.claude/claude_desktop_config.json` or MCP settings)

```json
{
  "mcpServers": {
    "jamf": {
      "type": "http",
      "url": "https://jamf-mcp.colgate.edu/mcp"
    },
    "intune": {
      "type": "http",
      "url": "https://intune-mcp.colgate.edu/mcp"
    }
  }
}
```

### Gemini CLI (`~/.gemini/settings.json`)

```json
{
  "mcpServers": {
    "jamf": { "httpUrl": "https://jamf-mcp.colgate.edu/mcp" },
    "intune": { "httpUrl": "https://intune-mcp.colgate.edu/mcp" }
  }
}
```

### OpenCode (`~/.config/opencode/opencode.json`)

```json
{
  "mcp": {
    "jamf":   { "type": "remote", "url": "https://jamf-mcp.colgate.edu/mcp", "enabled": true },
    "intune": { "type": "remote", "url": "https://intune-mcp.colgate.edu/mcp", "enabled": true }
  }
}
```

Swap in the `http://localhost:<port>/mcp` URLs from the table above for local development.

## MCP Tools Reference

### JAMF Pro Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `jamf_get_computer` | Computer details by name | `computerName` |
| `jamf_get_computer_by_serial` | Computer details by serial number | `serialNumber` |
| `jamf_get_computers_by_user` | Macs by username / name / email | `userIdentifier` |
| `jamf_get_mobile_device` | Mobile device details by name | `deviceName` |
| `jamf_list_smart_groups` | List smart groups | `type` (`"computer"` or `"mobile_device"`) |
| `jamf_get_smart_group_members` | Members of a smart group | `groupId` |
| `jamf_list_sites` | All JAMF sites | — |
| `jamf_list_scripts` | Scripts (with optional filter/pagination) | `name?`, `page?`, `pageSize?` |
| `jamf_list_packages` | Packages (with optional filter/pagination) | `name?`, `page?`, `pageSize?` |
| `jamf_list_inventory_preload` | Inventory preload records | `page?`, `pageSize?` |
| `jamf_list_prestage_configs` | Computer prestage assignments | — |
| `jamf_list_static_groups` | Static computer groups | — |
| `jamf_list_policies` | Policies list | — |
| `jamf_get_policy` | Policy details | `policyId` |
| `jamf_list_configuration_profiles` | Configuration profiles | — |
| `jamf_list_patch_policies` | Patch policies | — |
| `jamf_list_categories` | Categories | — |
| `jamf_list_departments` | Departments | — |
| `jamf_get_filevault_status` | FileVault encryption status | `computerName` |
| `jamf_send_mdm_command` | Send MDM command to a device | `deviceId`, `command` |
| `jamf_update_computer` | Update computer inventory fields | `computerId`, `fields` |
| `jamf_flush_mdm_commands` | Flush pending MDM commands | `deviceId` |

### Microsoft Intune Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `intune_get_autopilot_status` | Autopilot profile & status | `serialNumber?`, `deviceName?` |
| `intune_get_device_by_name` | Managed device by name | `deviceName` |
| `intune_get_device_by_serial` | Managed device by serial number | `serialNumber` |
| `intune_get_devices_by_user` | All devices for a user | `userIdentifier` |
| `intune_get_device_groups` | Device group memberships | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_get_device_apps` | Detected & assigned apps | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_list_configuration_policies` | Configuration policies (classic + settings catalog) | `policyName?`, `platform?` |
| `intune_troubleshoot_device_policies` | Device-level policy deployment diagnostics | `deviceName?`, `deviceId?`, `serialNumber?` |
| `intune_get_policy_assignments` | Assignment targets for a policy | `policyId`, `source?` |
| `intune_troubleshoot_policy` | Correlates policy assignment + device state | `policyId`, `deviceName?`, `deviceId?`, `serialNumber?`, `source?` |
| `intune_list_app_deployments` | Intune app deployments | `appName?`, `publisher?`, `platform?` |
| `intune_get_app_assignments` | Assignment targets for an app | `appId` |
| `intune_troubleshoot_app` | Correlates app assignment + device app status | `appId`, `deviceName?`, `deviceId?`, `serialNumber?` |

## Running Tests

Tests are live integration tests against a real JAMF Pro instance:

```bash
export BWS_ACCESS_TOKEN="<your-token>"
bws run --access-token "$BWS_ACCESS_TOKEN" -- \
  TEST_COMPUTER_NAME="<name>" \
  TEST_COMPUTER_SERIAL="<serial>" \
  TEST_USER_EMAIL="<email>" \
  npm test
```

Add `JAMF_TEST_WRITE=1` to enable destructive write tests (MDM commands, inventory updates).

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
│       └── logger.ts           # Output formatting helpers
├── start-jamf.sh               # BWS-wrapped launcher for JAMF server
├── start-intune.sh             # BWS-wrapped launcher for Intune server
└── bws-secrets.map             # Required BWS secret names and descriptions
```

## Additional Resources

- [MCP Specification](https://modelcontextprotocol.io/)
- [JAMF Pro API Docs](https://developer.jamf.com/jamf-pro/reference/classic-api)
- [Microsoft Graph API Docs](https://learn.microsoft.com/en-us/graph/overview)
- [Bitwarden Secrets Manager](https://bitwarden.com/help/secrets-manager-overview/)
