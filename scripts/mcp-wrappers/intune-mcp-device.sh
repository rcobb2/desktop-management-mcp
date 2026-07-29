#!/usr/bin/env bash
# Project-level MCP client wrapper for headless boxes where mcp-remote's normal
# localhost-callback OAuth flow can't complete (no local browser, and setting
# up SSH port forwarding for every session is a hassle).
#
# Fetches a fresh Entra access token via the device code flow (see
# desktop-management-mcp/src/cli/entra-device-auth.ts — run its `login`
# subcommand once, interactively, before wiring this up) and hands it to
# mcp-remote via --header, which bypasses mcp-remote's own OAuth entirely (its
# documented "Custom Headers" bypass-auth mechanism).
#
# Depends on the desktop-management-mcp repo being checked out as a sibling of
# this repo (both directly under the same parent, e.g. ~/cobbr/) — that's
# where entra-device-auth.ts actually lives. DESKTOP_MCP_DIR auto-discovers
# that sibling relative to this script's own location, so no machine-specific
# absolute path is hardcoded here; override it if your layout differs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_MCP_DIR="${DESKTOP_MCP_DIR:-$(cd "${SCRIPT_DIR}/../../../desktop-management-mcp" && pwd)}"
PROFILE="${1:-intune}"          # matches the --profile used with `entra-device-auth login`
MCP_URL="${2:-https://intune-mcp.colgate.edu/mcp}"
CALLBACK_PORT="${3:-3335}"      # unused by mcp-remote once --header bypasses OAuth, but it still binds this port

TOKEN=$(node "${DESKTOP_MCP_DIR}/dist/src/cli/entra-device-auth.js" token --profile "${PROFILE}")

# mcp-remote (0.1.38) parses --header once at startup and never re-reads it —
# there's no way to hand it a refreshed token later, so this connection's
# lifetime is capped at the access token's remaining lifetime regardless of
# how long the Claude Code session stays open. Left alone, every tool call
# after expiry just hangs silently (the harness's own ~30min idle timeout is
# the only thing that eventually surfaces it). Instead, bound mcp-remote's
# runtime to just under the token's actual remaining lifetime (entra-device-
# auth.js's own refresh logic already ran above, so this is the true
# remaining window) so the connection closes cleanly and immediately at that
# point — Claude Code sees an unambiguous disconnect right away and you can
# `/mcp` reconnect on the spot, instead of discovering a silent hang later.
EXPIRES_IN=$(node "${DESKTOP_MCP_DIR}/dist/src/cli/entra-device-auth.js" status --profile "${PROFILE}" \
  | grep -oE '\([0-9]+s from now\)' | grep -oE '[0-9]+')
LIFETIME_SEC=$(( EXPIRES_IN > 90 ? EXPIRES_IN - 90 : 30 ))

exec timeout --signal=TERM "${LIFETIME_SEC}s" mcp-remote "${MCP_URL}" "${CALLBACK_PORT}" --header "Authorization:Bearer ${TOKEN}"
