# Client Setup — Claude Code TUI and Claude Desktop

How to point Claude Code (terminal/TUI) and the Claude desktop app at the **podman02** deployment of
the JAMF and Intune MCP servers. For the local-dev (`./start-jamf.sh`) case, substitute the localhost
URLs from the table below; everything else is the same.

| Server | podman02 URL | Local dev URL |
|---|---|---|
| JAMF | `https://jamf-mcp.colgate.edu/mcp` | `http://localhost:3001/mcp` |
| Intune | `https://intune-mcp.colgate.edu/mcp` | `http://localhost:3002/mcp` |

## Before you start

1. **Be on Colgate's network.** Both hostnames resolve on internal DNS only, and Caddy (which
   terminates TLS and reverse-proxies to the containers) enforces an IP allowlist on top of that.
   Off-network, you get DNS failure or `403` — not an auth error.
2. **Node.js 24+** and `mcp-remote`:
   ```bash
   npm install -g mcp-remote     # or use npx, at the cost of a re-fetch each launch
   ```
3. **Have an Entra app role assigned.** Tool visibility comes from your token's `roles` claim:
   `Jamf.Read`, `Jamf.Write`, `Intune.Read`, `Intune.Write`. A role you don't hold means those tools
   are *never registered* on your request — they don't show up and aren't callable. Request the roles
   you need on the "Desktop Management MCP" app registration before setting up a client.

**Static bearer tokens do not work against podman02.** `JAMF_MCP_AUTH_TOKEN`/`INTUNE_MCP_AUTH_TOKEN`
were retired in production on 2026-07-15 — the ansible playbook renders both env vars empty, so prod
rejects them. Entra OAuth is the only auth mode in prod. (The static-token config in `README.md`
applies to locally-started servers only.)

### Shared Entra values

| | |
|---|---|
| Tenant ID | `5b75a9d0-188c-4a00-af54-5800ada1149f` |
| Public client ID | `6ec0e521-9e10-44cb-b767-7806f365c8df` |
| Scope | `openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user` |

### Which flow do you need?

| Situation | Use |
|---|---|
| Laptop/desktop with a local browser | **Browser PKCE** via `mcp-remote` (below) |
| Headless box / remote dev VM over SSH | **Device code flow** via the wrapper scripts (below) |

Entra does **not** support OAuth Dynamic Client Registration (RFC 7591), so `mcp-remote` always needs
`--static-oauth-client-info`; this project deliberately doesn't run an OAuth broker to paper over that.

---

## Claude Code TUI

### Option A — browser PKCE (machine with a browser)

Add both servers at user scope:

```bash
claude mcp add-json jamf-remote -s user '{
  "type": "stdio",
  "command": "mcp-remote",
  "args": [
    "https://jamf-mcp.colgate.edu/mcp",
    "3334",
    "--static-oauth-client-info", "{\"client_id\":\"6ec0e521-9e10-44cb-b767-7806f365c8df\"}",
    "--static-oauth-client-metadata", "{\"scope\":\"openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user\"}"
  ]
}'

claude mcp add-json intune-remote -s user '{
  "type": "stdio",
  "command": "mcp-remote",
  "args": [
    "https://intune-mcp.colgate.edu/mcp",
    "3335",
    "--static-oauth-client-info", "{\"client_id\":\"6ec0e521-9e10-44cb-b767-7806f365c8df\"}",
    "--static-oauth-client-metadata", "{\"scope\":\"openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user\"}"
  ]
}'
```

Then trigger the browser flow with `claude mcp get jamf-remote` (or just call one of its tools — first
use authenticates). Sign in, and `mcp-remote` caches tokens under `~/.mcp-auth/` and refreshes them
transparently from then on.

Notes:
- The `3334`/`3335` positional args pin `mcp-remote`'s callback port per server. Without them it derives
  a port from a hash of the server URL — works, but unpredictable, and you can't pre-register the
  redirect URI.
- Register **`http://localhost:3334/oauth/callback`** and **`http://localhost:3335/oauth/callback`** on
  the public client app as *Mobile and desktop applications* redirect URIs. It must be `localhost`, not
  `127.0.0.1`, and the path is `/oauth/callback` (OpenCode uses a different one — don't reuse it).
- Claude Code's *native* HTTP-transport OAuth (`claude mcp add --transport http … --client-id …`) does
  not send a `scope` parameter and fails against Entra with `AADSTS900144`. Use `mcp-remote`.

### Option B — device code flow (headless box, no local browser)

`mcp-remote` only implements authorization-code + PKCE with a localhost listener, which can't complete
over a bare SSH session. `src/cli/entra-device-auth.ts` drives RFC 8628 device code against the same
public client instead, then hands the result to `mcp-remote`.

```bash
cd /path/to/desktop-management-mcp
npm install && npm run build      # the wrappers invoke dist/, so this is required

# One interactive login per profile — prints a URL + code to enter on any device
node dist/src/cli/entra-device-auth.js login --profile jamf
node dist/src/cli/entra-device-auth.js login --profile intune

# Check what you got (expiry, refresh token, roles, upn)
node dist/src/cli/entra-device-auth.js status --profile jamf
```

Tokens cache in `~/.mcp-auth/entra-device/<profile>.json` (mode 0600).

This repo already ships the client config — `.mcp.json` wires `jamf-remote`/`intune-remote` to
`scripts/mcp-wrappers/{jamf,intune}-mcp-device.sh`, so a Claude Code session started in this repo picks
them up with no further config. To use them from another directory, copy the same block into
`~/.claude.json` (or `claude mcp add-json … -s user`) with an absolute path to the wrapper. The wrappers
locate the repo via `DESKTOP_MCP_DIR`, which defaults to a sibling directory literally named
`desktop-management-mcp` — set that env var explicitly if your checkout is named or placed differently.

**Long sessions:** the shipped wrappers pass the token via `mcp-remote --header`, which `mcp-remote`
reads once at startup and never re-reads. They therefore wrap it in `timeout` bounded to just under the
token's remaining lifetime, so the connection drops cleanly at expiry (reconnect with `/mcp`) instead of
every tool call hanging silently. For a connection that refreshes itself indefinitely, use the
seed-based variant instead — `scripts/mcp-wrapper-device-auth.sh.example`, which writes the token into
`mcp-remote`'s *own* cache so its native refresh-on-401 takes over. Copy it, fix `DESKTOP_MCP_DIR`,
`chmod +x`, point `command` at your copy, and pair it with a keepalive so an idle box's refresh token
stays exercised:

```bash
node dist/src/cli/entra-device-auth.js keepalive \
  --profile jamf --server-url https://jamf-mcp.colgate.edu/mcp --interval-seconds 1800
```

(Run one per profile, e.g. as a `systemd --user` service.)

---

## Claude desktop app

Use the same `mcp-remote` stdio bridge, declared in the desktop app's config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "jamf": {
      "command": "/usr/local/bin/mcp-remote",
      "args": [
        "https://jamf-mcp.colgate.edu/mcp",
        "3334",
        "--static-oauth-client-info", "{\"client_id\":\"6ec0e521-9e10-44cb-b767-7806f365c8df\"}",
        "--static-oauth-client-metadata", "{\"scope\":\"openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user\"}"
      ]
    },
    "intune": {
      "command": "/usr/local/bin/mcp-remote",
      "args": [
        "https://intune-mcp.colgate.edu/mcp",
        "3335",
        "--static-oauth-client-info", "{\"client_id\":\"6ec0e521-9e10-44cb-b767-7806f365c8df\"}",
        "--static-oauth-client-metadata", "{\"scope\":\"openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user\"}"
      ]
    }
  }
}
```

Then fully quit and reopen the app (it only reads this file at launch), and click the servers' entry
under the tools/connectors menu to complete the browser sign-in.

Notes:
- The desktop app launches child processes with a minimal `PATH`, so give `command` an **absolute path**
  (`which mcp-remote`; on Windows, the `mcp-remote.cmd` shim). `npx` works too, if given absolutely.
- The same redirect-URI registration as Option A applies (`http://localhost:3334|3335/oauth/callback`).
- **Settings → Connectors → "Add custom connector" won't work here.** That path expects the server's
  authorization server to support Dynamic Client Registration, which Entra doesn't, and it gives you no
  way to supply a static client ID/scope or an `Authorization` header. The stdio bridge above is the
  supported route.
- The **Claude Code desktop app** reads the same MCP config as the CLI, so Option A/B above cover it —
  no separate setup.

---

## Verify

```bash
curl -s https://jamf-mcp.colgate.edu/health      # {"status":"ok","server":"jamf-mcp-server",...}
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://jamf-mcp.colgate.edu/mcp   # 401 — expected, /health is the unauthenticated one
```

In the client, `/mcp` (TUI) or the connectors menu (desktop) should show both servers connected. Ask for
something cheap, e.g. `jamf_list_sites` or `intune_list_devices`, to confirm your roles took effect.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| DNS failure or `403` before any auth prompt | Off-network. Internal DNS + Caddy IP allowlist — get on Colgate's network/VPN. |
| `401` on every call | No/expired token. Re-run the browser flow, or `entra-device-auth login --profile …`. |
| `503` on every call | The server has no auth mode configured (fails closed) — a deployment-side problem, not yours. |
| Server connects, but expected tools are missing | Missing app role. Check `entra-device-auth status --profile …` → `roles`, then get the role assigned and **re-authenticate** — a new roles claim only lands in a freshly issued token. |
| `AADSTS900144` (missing `scope`) | You used Claude Code's native HTTP-transport OAuth. Switch to `mcp-remote`. |
| `AADSTS9010010` | The literal MCP URL isn't an `identifierUris` entry on the resource app. Clients send it as an RFC 8707 `resource` parameter, and it must resolve to the same app as the requested scope. |
| Browser flow opens but never completes | Redirect URI not registered, or `mcp-remote` is running on a different machine than the browser. Register the exact URI, or `ssh -L 3334:localhost:3334 <host>`. |
| Tool calls hang silently after ~an hour | `--header`-style wrapper past token expiry. Reconnect with `/mcp`, or move to the seed + keepalive setup. |
| Bursts of concurrent calls all stall | Each `/mcp` process caps concurrency at `MCP_MAX_CONCURRENT_REQUESTS` (default 8) and FIFO-queues the rest; heavy parallel fan-out also risks upstream JAMF/Graph throttling. Serialize large batches. |
| `No mcp-remote-* directory found under ~/.mcp-auth` | `seed-mcp-remote` ran before `mcp-remote` ever did. Launch `mcp-remote` once (even a failed auth creates the dir), then reseed. |

## Entra registration checklist

Needed once, on the shared registrations, for the above to work:

- **Resource app** ("Desktop Management MCP"): Application ID URI
  `api://colgate.edu/desktop-mgmt-mcp`, a delegated `access_as_user` scope, app roles `Jamf.Read`,
  `Jamf.Write`, `Intune.Read`, `Intune.Write`, plus each server's literal MCP URL
  (`https://jamf-mcp.colgate.edu/mcp`, `https://intune-mcp.colgate.edu/mcp`) as additional
  `identifierUris` entries.
- **Public client** (`6ec0e521-…`): PKCE, no secret, pre-authorized for `access_as_user`, redirect URIs
  `http://localhost:3334/oauth/callback` and `http://localhost:3335/oauth/callback`. Already eligible
  for the device code flow (`isFallbackPublicClient: true`) — no change needed for Option B.
- Per-user role assignment happens in Enterprise Applications (or `POST
  /users/{id}/appRoleAssignments`), per role, per user/group.
