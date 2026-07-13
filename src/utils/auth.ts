import { timingSafeEqual } from "node:crypto";
import { Request, Response, NextFunction } from "express";

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
