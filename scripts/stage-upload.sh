#!/usr/bin/env bash
# Stage a large installer on a Desktop Management MCP server so a tool can use it.
#
# MCP tool calls are capped at ~100KB by the servers' JSON body limit, so installers
# can't ride inside them. This PUTs the raw file to the server's /uploads endpoint
# (streamed to disk server-side) and prints the JSON response; pass its `path` as
# `localFilePath` (jamf_upload_package) or `intunewinFilePath` (intune_create_win32_app).
#
# Usage: scripts/stage-upload.sh <jamf|intune> <file>
# Env:   MCP_BASE_URL          override https://<jamf|intune>-mcp.colgate.edu
#        ENTRA_DEVICE_AUTH_JS  override the entra-device-auth.js used to fetch a token
set -euo pipefail

SERVER="${1:-}"
FILE="${2:-}"
if [[ ( "${SERVER}" != "jamf" && "${SERVER}" != "intune" ) || -z "${FILE}" ]]; then
  echo "Usage: $0 <jamf|intune> <file>" >&2
  exit 2
fi
[[ -f "${FILE}" ]] || { echo "File not found: ${FILE}" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Token helper precedence: explicit env var, then this repo's own built CLI, then the
# DesktopManagement wrapper copy the other tooling uses.
if [[ -n "${ENTRA_DEVICE_AUTH_JS:-}" ]]; then
  AUTH_JS="${ENTRA_DEVICE_AUTH_JS}"
elif [[ -f "${SCRIPT_DIR}/../dist/src/cli/entra-device-auth.js" ]]; then
  AUTH_JS="${SCRIPT_DIR}/../dist/src/cli/entra-device-auth.js"
else
  AUTH_JS="${HOME}/DesktopManagement/scripts/mcp-wrappers/entra-device-auth.js"
fi

BASE_URL="${MCP_BASE_URL:-https://${SERVER}-mcp.colgate.edu}"
NAME="$(basename "${FILE}")"
# Percent-encode the name (spaces etc.) for the URL path.
ENCODED_NAME="$(printf '%s' "${NAME}" | node -e 'process.stdout.write(encodeURIComponent(require("fs").readFileSync(0, "utf8")))')"

TOKEN="$(node "${AUTH_JS}" token --profile "${SERVER}")"

if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "${FILE}" | cut -d' ' -f1)"
else
  SHA="$(shasum -a 256 "${FILE}" | cut -d' ' -f1)"
fi

# The token goes in a header file on stdin (-H @-) so it never appears in `ps` output or this script's stdout.
printf 'Authorization: Bearer %s\n' "${TOKEN}" | curl --fail-with-body -sS -T "${FILE}" \
  -H @- \
  -H "X-Content-SHA256: ${SHA}" \
  "${BASE_URL}/uploads/${ENCODED_NAME}"
echo
