#!/usr/bin/env bash
# Requires BWS_ACCESS_TOKEN to be set in the environment.
# Secrets are injected by Bitwarden Secrets Manager — see bws-secrets.map.
: "${BWS_ACCESS_TOKEN:?BWS_ACCESS_TOKEN environment variable is required}"
export PORT="${PORT:-3002}"
exec bws run --access-token "$BWS_ACCESS_TOKEN" -- \
  node "$(dirname "$0")/dist/src/mcp/intune-server.js"
