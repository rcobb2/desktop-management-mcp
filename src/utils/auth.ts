import { timingSafeEqual } from "node:crypto";
import { Request, Response, NextFunction } from "express";
import { EntraAuthInfo } from "./entra-jwt.js";
import { AuthMode, resolveRolesFromAuthInfo } from "./roles.js";

declare module "express-serve-static-core" {
    interface Request {
        /** Set by `requireMcpAuth` once a request has been authenticated. */
        auth?: EntraAuthInfo;
        /** Which of the two auth paths in `requireMcpAuth` succeeded. */
        authMode?: AuthMode;
    }
}

function safeCompare(expected: string, provided: string): boolean {
    const expectedBuf = Buffer.from(expected);
    const providedBuf = Buffer.from(provided);
    if (expectedBuf.length !== providedBuf.length) {
        // Still run a same-cost comparison so the early-return itself doesn't leak length via timing.
        timingSafeEqual(expectedBuf, expectedBuf);
        return false;
    }
    return timingSafeEqual(expectedBuf, providedBuf);
}

/**
 * Express middleware requiring `Authorization: Bearer <token>` matching one of the
 * comma-separated tokens in `envVarName`. Fails closed: if the env var is unset or
 * empty, every request is rejected rather than silently allowed through.
 */
export function requireBearerAuth(envVarName: string) {
    const tokens = (process.env[envVarName] ?? "")
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

    return (req: Request, res: Response, next: NextFunction) => {
        if (tokens.length === 0) {
            res.status(503).json({ error: `Server misconfigured: ${envVarName} is not set` });
            return;
        }

        const header = req.header("authorization") ?? "";
        const match = /^Bearer (.+)$/.exec(header);
        if (!match) {
            res.status(401).json({ error: "Missing or malformed Authorization header. Expected: Bearer <token>" });
            return;
        }

        const provided = match[1];
        const isValid = tokens.some((t) => safeCompare(t, provided));
        if (!isValid) {
            res.status(401).json({ error: "Invalid bearer token" });
            return;
        }

        next();
    };
}

/**
 * Express middleware requiring `Authorization: Bearer <token>` that is EITHER:
 *   1. one of the comma-separated tokens in `staticTokenEnvVar` (same check as
 *      `requireBearerAuth`, mapped to `allRoles` — full access, matching that
 *      token's existing behavior exactly), or
 *   2. when `entraEnabledEnvVar` is set to `"true"`, a valid Entra-issued JWT
 *      (verified via `entraVerifier`), whose own `roles` claim becomes the
 *      caller's effective role set.
 *
 * Fails closed exactly like `requireBearerAuth` when neither auth mode is
 * configured (the static token env var is unset AND Entra is not enabled).
 */
export function requireMcpAuth(options: {
    staticTokenEnvVar: string;
    allRoles: string[];
    entraVerifier: (token: string) => Promise<EntraAuthInfo>;
    entraEnabledEnvVar: string;
    resourceMetadataUrl?: string;
}) {
    const staticTokens = (process.env[options.staticTokenEnvVar] ?? "")
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    const entraEnabled = process.env[options.entraEnabledEnvVar] === "true";

    return async (req: Request, res: Response, next: NextFunction) => {
        if (staticTokens.length === 0 && !entraEnabled) {
            res.status(503).json({ error: `Server misconfigured: ${options.staticTokenEnvVar} is not set` });
            return;
        }

        const header = req.header("authorization") ?? "";
        const match = /^Bearer (.+)$/.exec(header);
        if (!match) {
            if (options.resourceMetadataUrl) {
                res.set("WWW-Authenticate", `Bearer resource_metadata="${options.resourceMetadataUrl}"`);
            }
            res.status(401).json({ error: "Missing or malformed Authorization header. Expected: Bearer <token>" });
            return;
        }

        const provided = match[1];

        if (staticTokens.some((t) => safeCompare(t, provided))) {
            req.auth = {
                token: provided,
                clientId: "static-token",
                scopes: [],
                extra: { roles: resolveRolesFromAuthInfo("static-token", undefined, options.allRoles) },
            };
            req.authMode = "static-token";
            next();
            return;
        }

        if (entraEnabled) {
            try {
                const entraAuth = await options.entraVerifier(provided);
                entraAuth.extra.roles = resolveRolesFromAuthInfo("entra", entraAuth.extra.roles, options.allRoles);
                req.auth = entraAuth;
                req.authMode = "entra";
                next();
                return;
            } catch {
                // Falls through to the generic 401 below — deliberately not
                // distinguishing "bad Entra token" from "bad static token" in
                // the response, to avoid leaking which auth mode a caller was
                // attempting.
            }
        }

        if (options.resourceMetadataUrl) {
            res.set("WWW-Authenticate", `Bearer resource_metadata="${options.resourceMetadataUrl}"`);
        }
        res.status(401).json({ error: "Invalid bearer token" });
    };
}
