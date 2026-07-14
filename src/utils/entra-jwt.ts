/**
 * Microsoft Entra ID access token verification.
 *
 * Resource-server-only: this module verifies JWTs that some other OAuth
 * client obtained directly from Entra (see CLAUDE.md for why this project
 * doesn't act as its own authorization server). No `/authorize`/`/token`
 * endpoints live here — just signature/issuer/audience verification and
 * claim extraction.
 *
 * `jose` is ESM-only; this project compiles to CommonJS, so it must be
 * loaded via dynamic `import()` rather than a static import (a static
 * import fails to compile under this project's `module: node16` setting —
 * see TS1479). The dynamic import is cached after first use.
 */
import type { JWTPayload } from "jose" with { "resolution-mode": "import" };

export interface EntraAuthInfo {
    token: string;
    clientId: string;
    scopes: string[];
    expiresAt?: number;
    extra: {
        roles: string[];
        oid?: string;
        upn?: string;
        tid?: string;
    };
}

type JoseModule = typeof import("jose", { with: { "resolution-mode": "import" } });

let josePromise: Promise<JoseModule> | null = null;
function loadJose(): Promise<JoseModule> {
    if (!josePromise) {
        josePromise = import("jose");
    }
    return josePromise;
}

interface EntraDiscoveryDoc {
    issuer: string;
    jwks_uri: string;
}

const discoveryCache = new Map<string, Promise<{ issuer: string; jwks: ReturnType<JoseModule["createRemoteJWKSet"]> }>>();

async function getIssuerAndJwks(tenantId: string) {
    let cached = discoveryCache.get(tenantId);
    if (!cached) {
        cached = (async () => {
            const jose = await loadJose();
            const discoveryUrl = `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
            const res = await fetch(discoveryUrl);
            if (!res.ok) {
                throw new Error(`Failed to fetch Entra OIDC discovery document (${res.status}): ${discoveryUrl}`);
            }
            const discovery = (await res.json()) as EntraDiscoveryDoc;
            return {
                issuer: discovery.issuer,
                jwks: jose.createRemoteJWKSet(new URL(discovery.jwks_uri), {
                    cooldownDuration: 30_000,
                    cacheMaxAge: 600_000,
                }),
            };
        })();
        discoveryCache.set(tenantId, cached);
    }
    return cached;
}

function stringClaim(payload: JWTPayload, key: string): string | undefined {
    const value = payload[key];
    return typeof value === "string" ? value : undefined;
}

/**
 * Builds a verifier bound to one Entra tenant + resource app audience.
 * Throws on any signature/issuer/audience/tenant mismatch.
 */
export function createEntraVerifier(opts: { tenantId: string; audience: string }) {
    return async function verifyEntraAccessToken(token: string): Promise<EntraAuthInfo> {
        const jose = await loadJose();
        const { issuer, jwks } = await getIssuerAndJwks(opts.tenantId);

        const { payload } = await jose.jwtVerify(token, jwks, {
            issuer,
            audience: opts.audience,
        });

        const tid = stringClaim(payload, "tid");
        if (tid !== opts.tenantId) {
            throw new Error("Token tenant (tid) does not match configured Entra tenant");
        }

        const rolesClaim = payload.roles;
        const roles = Array.isArray(rolesClaim) ? rolesClaim.filter((r): r is string => typeof r === "string") : [];

        const scpClaim = stringClaim(payload, "scp");

        return {
            token,
            clientId: stringClaim(payload, "azp") ?? stringClaim(payload, "appid") ?? "unknown",
            scopes: scpClaim ? scpClaim.split(" ") : [],
            expiresAt: payload.exp,
            extra: {
                roles,
                oid: stringClaim(payload, "oid"),
                upn: stringClaim(payload, "upn") ?? stringClaim(payload, "preferred_username"),
                tid,
            },
        };
    };
}

/**
 * Authorization-server metadata for Entra's v2.0 endpoint, in the shape the
 * MCP SDK's `mcpAuthMetadataRouter` expects for RFC 9728 protected-resource
 * discovery. Built from Entra's well-known, stable v2.0 endpoint URLs rather
 * than fetched at startup, to avoid a network dependency on process boot.
 */
export function buildEntraOAuthMetadata(tenantId: string) {
    const base = `https://login.microsoftonline.com/${tenantId}`;
    return {
        issuer: `${base}/v2.0`,
        authorization_endpoint: `${base}/oauth2/v2.0/authorize`,
        token_endpoint: `${base}/oauth2/v2.0/token`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
    };
}
