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
 * changes), caches the resulting token, and prints a bare access token that
 * can be fed to `mcp-remote --header "Authorization:Bearer $TOKEN"` (its
 * documented bypass-auth mechanism) from a wrapper script — see
 * scripts/mcp-wrapper-device-auth.sh.example.
 *
 * Usage:
 *   node dist/src/cli/entra-device-auth.js login  --profile intune
 *   node dist/src/cli/entra-device-auth.js token  --profile intune   # prints access token to stdout
 *   node dist/src/cli/entra-device-auth.js status --profile intune
 *
 * Env overrides (all optional, defaults match this project's existing Entra app):
 *   ENTRA_TENANT_ID       Entra tenant GUID (default: colgate.edu's tenant)
 *   DEVICE_AUTH_CLIENT_ID Public client app ID (default: the OpenCode client mcp-remote already uses)
 *   DEVICE_AUTH_SCOPE     Space-separated scopes (default: matches mcp-remote's --static-oauth-client-metadata)
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

async function main(): Promise<void> {
    const [command, ...rest] = process.argv.slice(2);
    const profileIdx = rest.indexOf("--profile");
    const profile = profileIdx >= 0 ? rest[profileIdx + 1] : undefined;

    if (!command || !profile) {
        console.error("Usage: entra-device-auth <login|token|status> --profile <name>");
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
        default:
            console.error(`Unknown command: ${command}`);
            process.exitCode = 1;
    }
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
});
