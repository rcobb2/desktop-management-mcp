/**
 * Entra ID OAuth 2.0 Device Authorization Grant (RFC 8628) helper for headless
 * MCP client setups.
 *
 * `mcp-remote` (the stdio<->HTTP bridge wired into jamf-remote/intune-remote in
 * Claude Code's MCP config) only implements Authorization Code + PKCE with a
 * localhost callback listener — confirmed by inspecting its published 0.1.38
 * package (`dist/*.js` has zero references to device_code). That flow requires
 * the browser completing login to reach a port on the SAME machine running the
 * MCP client, which breaks down on a headless box reached over SSH without
 * port forwarding.
 *
 * The device code grant sidesteps that entirely: no redirect, no local
 * listener. This script drives that flow directly against the same public
 * client app registration mcp-remote already uses ("Desktop Management MCP -
 * OpenCode Client", isFallbackPublicClient: true — confirmed via `az ad app
 * show`, so it's already eligible for device code without any Entra-side
 * changes), and caches the resulting token.
 *
 * Two ways to hand that token to mcp-remote:
 *
 * 1. `token` — prints a bare access token for `mcp-remote --header
 *    "Authorization:Bearer $TOKEN"` (its documented bypass-auth mechanism).
 *    Simple, but the header is read once at process startup and never
 *    refreshed — a long-running mcp-remote process (and the long MCP client
 *    session riding on its stdio pipe) goes stale once that token expires
 *    (~60-90min) and every subsequent request 401s until the client restarts.
 *
 * 2. `seed-mcp-remote` (preferred) — writes this token/refresh_token pair
 *    directly into mcp-remote's OWN on-disk token cache
 *    (`~/.mcp-auth/mcp-remote-<version>/<hash>_tokens.json`), in the exact
 *    shape its `OAuthTokensSchema` expects. Confirmed by reading mcp-remote
 *    0.1.38's source directly: its Streamable HTTP transport re-reads that
 *    file fresh on every single outgoing request (not just once at startup),
 *    and on a 401 it automatically refreshes via the cached refresh_token and
 *    *transparently retries the same request* — no restart, no proxy needed.
 *    Once seeded, invoke mcp-remote the same way the browser-capable
 *    (non-headless) setup already does — `--static-oauth-client-info`/
 *    `--static-oauth-client-metadata`, no `--header` — and it self-refreshes
 *    indefinitely via that same built-in mechanism. `keepalive` wraps this in
 *    a loop that reseeds proactively before real expiry, both to avoid the
 *    one-request refresh latency hit and to keep the refresh_token exercised
 *    so it doesn't go stale from long inactivity on a quiet box.
 *
 * Usage:
 *   node dist/src/cli/entra-device-auth.js login          --profile intune
 *   node dist/src/cli/entra-device-auth.js token           --profile intune   # prints access token to stdout
 *   node dist/src/cli/entra-device-auth.js status          --profile intune
 *   node dist/src/cli/entra-device-auth.js seed-mcp-remote --profile intune --server-url https://intune-mcp.colgate.edu/mcp
 *   node dist/src/cli/entra-device-auth.js keepalive       --profile intune --server-url https://intune-mcp.colgate.edu/mcp [--interval-seconds 1800]
 *
 * Env overrides (all optional, defaults match this project's existing Entra app):
 *   ENTRA_TENANT_ID       Entra tenant GUID (default: colgate.edu's tenant)
 *   DEVICE_AUTH_CLIENT_ID Public client app ID (default: the OpenCode client mcp-remote already uses)
 *   DEVICE_AUTH_SCOPE     Space-separated scopes (default: matches mcp-remote's --static-oauth-client-metadata)
 */

import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_TENANT_ID = "5b75a9d0-188c-4a00-af54-5800ada1149f";
const DEFAULT_CLIENT_ID = "6ec0e521-9e10-44cb-b767-7806f365c8df";
const DEFAULT_SCOPE = "openid profile offline_access api://colgate.edu/desktop-mgmt-mcp/access_as_user";

const CACHE_DIR = join(homedir(), ".mcp-auth", "entra-device");

interface TokenCache {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    scope: string;
    expires_at: number; // absolute epoch seconds, computed at save time
}

interface DeviceCodeResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    expires_in: number;
    interval: number;
    message?: string;
}

interface TokenResponse {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    scope: string;
    expires_in: number;
    error?: string;
    error_description?: string;
}

function config() {
    return {
        tenantId: process.env.ENTRA_TENANT_ID ?? DEFAULT_TENANT_ID,
        clientId: process.env.DEVICE_AUTH_CLIENT_ID ?? DEFAULT_CLIENT_ID,
        scope: process.env.DEVICE_AUTH_SCOPE ?? DEFAULT_SCOPE,
    };
}

function cachePath(profile: string): string {
    return join(CACHE_DIR, `${profile}.json`);
}

function loadCache(profile: string): TokenCache | undefined {
    try {
        return JSON.parse(readFileSync(cachePath(profile), "utf8"));
    } catch {
        return undefined;
    }
}

function saveCache(profile: string, cache: TokenCache): void {
    mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(cachePath(profile), JSON.stringify(cache, null, 2), { mode: 0o600 });
}

function decodeJwtPayload(token: string): Record<string, unknown> {
    const payload = token.split(".")[1];
    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, "base64url").toString("utf8"));
}

async function requestDeviceCode(): Promise<DeviceCodeResponse> {
    const { tenantId, clientId, scope } = config();
    const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/devicecode`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: clientId, scope }),
    });
    if (!res.ok) {
        throw new Error(`Device code request failed (${res.status}): ${await res.text()}`);
    }
    return res.json() as Promise<DeviceCodeResponse>;
}

async function pollForToken(deviceCode: DeviceCodeResponse): Promise<TokenResponse> {
    const { tenantId, clientId } = config();
    const deadline = Date.now() + deviceCode.expires_in * 1000;
    let intervalMs = deviceCode.interval * 1000;

    while (Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, intervalMs));

        const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id: clientId,
                device_code: deviceCode.device_code,
            }),
        });
        const body = (await res.json()) as TokenResponse;

        if (res.ok) return body;

        switch (body.error) {
            case "authorization_pending":
                continue;
            case "slow_down":
                intervalMs += 5000;
                continue;
            case "authorization_declined":
                throw new Error("Sign-in was declined.");
            case "expired_token":
                throw new Error("Device code expired before sign-in completed — run `login` again.");
            default:
                throw new Error(`Token request failed: ${body.error} — ${body.error_description ?? ""}`);
        }
    }
    throw new Error("Device code expired before sign-in completed — run `login` again.");
}

async function refreshToken(refresh_token: string): Promise<TokenResponse> {
    const { tenantId, clientId, scope } = config();
    const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token, scope }),
    });
    const body = (await res.json()) as TokenResponse;
    if (!res.ok) {
        throw new Error(`Refresh failed: ${body.error} — ${body.error_description ?? ""}`);
    }
    return body;
}

function toCache(token: TokenResponse): TokenCache {
    return {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        id_token: token.id_token,
        scope: token.scope,
        expires_at: Math.floor(Date.now() / 1000) + token.expires_in,
    };
}

async function cmdLogin(profile: string): Promise<void> {
    const deviceCode = await requestDeviceCode();
    console.error(
        deviceCode.message ??
            `To sign in, open ${deviceCode.verification_uri} on any device and enter code: ${deviceCode.user_code}`
    );
    const token = await pollForToken(deviceCode);
    saveCache(profile, toCache(token));
    console.error(`Signed in — cached to ${cachePath(profile)}`);
}

/** Returns a valid access token, refreshing via the cached refresh_token if it's within 60s of expiry. */
async function cmdToken(profile: string): Promise<string> {
    const cached = loadCache(profile);
    if (!cached) {
        throw new Error(`No cached token for profile "${profile}" — run: entra-device-auth login --profile ${profile}`);
    }

    const nearExpiry = cached.expires_at - Math.floor(Date.now() / 1000) < 60;
    if (!nearExpiry) return cached.access_token;

    if (!cached.refresh_token) {
        throw new Error(`Cached token for "${profile}" expired and has no refresh_token — run login again.`);
    }
    const refreshed = toCache(await refreshToken(cached.refresh_token));
    saveCache(profile, refreshed);
    return refreshed.access_token;
}

/**
 * Locate mcp-remote's own token cache directory. Its name is
 * `mcp-remote-<version>` where <version> is a constant baked into mcp-remote's
 * own bundle at build time — confirmed live this does NOT always match the
 * npm package.json version (0.1.38 installed here, but the bundle's own
 * version constant — and therefore this directory name — is "0.1.37"), so
 * this must be discovered at runtime rather than assumed from the installed
 * package version. mcp-remote creates this directory itself on first run, so
 * it's expected to already exist.
 */
function resolveMcpRemoteConfigDir(): string {
    const baseDir = join(homedir(), ".mcp-auth");
    let entries: string[];
    try {
        entries = readdirSync(baseDir);
    } catch {
        throw new Error(`${baseDir} doesn't exist yet — run mcp-remote at least once first (even a failed auth attempt creates it).`);
    }

    const matches = entries.filter((e) => e.startsWith("mcp-remote-"));
    if (matches.length === 0) {
        throw new Error(`No mcp-remote-* directory found under ${baseDir} — run mcp-remote at least once first.`);
    }
    if (matches.length === 1) {
        return join(baseDir, matches[0]);
    }

    // Multiple versions present (e.g. after an mcp-remote upgrade) — use the
    // most recently modified one and warn, rather than guessing wrong silently.
    const sorted = matches
        .map((name) => ({ name, mtime: statSync(join(baseDir, name)).mtimeMs }))
        .sort((a, b) => b.mtime - a.mtime);
    console.error(`Warning: multiple mcp-remote config dirs found (${matches.join(", ")}) — using the most recently modified: ${sorted[0].name}`);
    return join(baseDir, sorted[0].name);
}

/** Matches mcp-remote's own getServerUrlHash() for the plain (no --header, no --resource) invocation this project uses. */
function mcpRemoteServerUrlHash(serverUrl: string): string {
    return createHash("md5").update(serverUrl).digest("hex");
}

/**
 * Seed mcp-remote's own on-disk token cache from this profile's cached
 * device-code token, so mcp-remote's native OAuth machinery (transparent
 * refresh-on-401 — see the file header comment) takes over from here with no
 * further involvement from this script needed for a given request to succeed.
 * Refreshes this profile's own cache first if it's near expiry, same as `token`.
 */
async function seedMcpRemote(profile: string, serverUrl: string): Promise<void> {
    await cmdToken(profile); // ensures the cached token below is fresh (refreshes in place if needed)
    const cached = loadCache(profile);
    if (!cached) {
        throw new Error(`No cached token for profile "${profile}" — run: entra-device-auth login --profile ${profile}`);
    }

    const configDir = resolveMcpRemoteConfigDir();
    const hash = mcpRemoteServerUrlHash(serverUrl);

    const tokensPath = join(configDir, `${hash}_tokens.json`);
    const tokensJson = {
        access_token: cached.access_token,
        token_type: "Bearer",
        expires_in: Math.max(0, cached.expires_at - Math.floor(Date.now() / 1000)),
        scope: cached.scope,
        refresh_token: cached.refresh_token,
    };
    writeFileSync(tokensPath, JSON.stringify(tokensJson, null, 2), { mode: 0o600 });

    // Only needed if the MCP client's mcp-remote invocation ISN'T already passing
    // --static-oauth-client-info (which takes priority over this file regardless) —
    // written defensively so seeding alone is sufficient even without that flag.
    const { clientId, scope } = config();
    const clientInfoPath = join(configDir, `${hash}_client_info.json`);
    const clientInfoJson = {
        client_id: clientId,
        redirect_uris: ["http://localhost:0/oauth/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope,
    };
    writeFileSync(clientInfoPath, JSON.stringify(clientInfoJson, null, 2), { mode: 0o600 });
}

async function cmdSeedMcpRemote(profile: string, serverUrl: string): Promise<void> {
    await seedMcpRemote(profile, serverUrl);
    console.error(`Seeded mcp-remote's token cache for ${serverUrl} (profile "${profile}").`);
}

/**
 * Loops forever, reseeding mcp-remote's cache every intervalSeconds. Proactive
 * rather than relying purely on mcp-remote's own reactive refresh-on-401 so:
 * (1) no request ever eats a refresh round-trip at the exact expiry boundary,
 * and (2) a genuinely idle box's refresh_token still gets exercised regularly
 * so it can't go stale from disuse even with zero real MCP traffic. Errors are
 * logged and swallowed so a transient network blip doesn't kill the loop.
 */
async function cmdKeepalive(profile: string, serverUrl: string, intervalSeconds: number): Promise<void> {
    console.error(`Starting keepalive for profile "${profile}" -> ${serverUrl} (every ${intervalSeconds}s). Ctrl-C to stop.`);
    // eslint-disable-next-line no-constant-condition
    while (true) {
        try {
            await seedMcpRemote(profile, serverUrl);
            console.error(`[${new Date().toISOString()}] reseeded`);
        } catch (err) {
            console.error(`[${new Date().toISOString()}] reseed failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        await new Promise((resolve) => setTimeout(resolve, intervalSeconds * 1000));
    }
}

function cmdStatus(profile: string): void {
    const cached = loadCache(profile);
    if (!cached) {
        console.log(`${profile}: no cached token`);
        return;
    }
    const claims = decodeJwtPayload(cached.access_token);
    const expiresInSec = cached.expires_at - Math.floor(Date.now() / 1000);
    console.log(`profile: ${profile}`);
    console.log(`expires: ${new Date(cached.expires_at * 1000).toISOString()} (${expiresInSec}s from now)`);
    console.log(`has refresh_token: ${Boolean(cached.refresh_token)}`);
    console.log(`roles: ${JSON.stringify(claims.roles ?? [])}`);
    console.log(`upn: ${claims.upn ?? claims.preferred_username ?? "(none)"}`);
}

function flagValue(args: string[], flag: string): string | undefined {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
}

async function main(): Promise<void> {
    const [command, ...rest] = process.argv.slice(2);
    const profile = flagValue(rest, "--profile");

    if (!command || !profile) {
        console.error("Usage: entra-device-auth <login|token|status|seed-mcp-remote|keepalive> --profile <name> [--server-url <url>] [--interval-seconds <n>]");
        process.exitCode = 1;
        return;
    }

    switch (command) {
        case "login":
            await cmdLogin(profile);
            break;
        case "token":
            console.log(await cmdToken(profile));
            break;
        case "status":
            cmdStatus(profile);
            break;
        case "seed-mcp-remote": {
            const serverUrl = flagValue(rest, "--server-url");
            if (!serverUrl) {
                console.error("seed-mcp-remote requires --server-url <url>");
                process.exitCode = 1;
                return;
            }
            await cmdSeedMcpRemote(profile, serverUrl);
            break;
        }
        case "keepalive": {
            const serverUrl = flagValue(rest, "--server-url");
            if (!serverUrl) {
                console.error("keepalive requires --server-url <url>");
                process.exitCode = 1;
                return;
            }
            const intervalArg = flagValue(rest, "--interval-seconds");
            const intervalSeconds = intervalArg ? parseInt(intervalArg, 10) : 1800;
            if (!Number.isFinite(intervalSeconds) || intervalSeconds < 60) {
                console.error("--interval-seconds must be a number >= 60");
                process.exitCode = 1;
                return;
            }
            await cmdKeepalive(profile, serverUrl, intervalSeconds);
            break;
        }
        default:
            console.error(`Unknown command: ${command}`);
            process.exitCode = 1;
    }
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
});
