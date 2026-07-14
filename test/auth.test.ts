/**
 * Unit tests for requireMcpAuth and the roles helpers (node:test, no extra deps).
 * No network access, no real Entra tenant required.
 *
 * Run:  npm test
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import type { Request, Response, NextFunction } from "express";
import { requireMcpAuth } from "../src/utils/auth.js";
import { hasRole, assertRole, resolveRolesFromAuthInfo, JAMF_READ, JAMF_WRITE } from "../src/utils/roles.js";
import type { EntraAuthInfo } from "../src/utils/entra-jwt.js";

// ── roles.ts ──────────────────────────────────────────────────────────────────

describe("roles", () => {
    test("hasRole reports membership", () => {
        assert.equal(hasRole([JAMF_READ], JAMF_READ), true);
        assert.equal(hasRole([JAMF_READ], JAMF_WRITE), false);
        assert.equal(hasRole([], JAMF_READ), false);
    });

    test("assertRole throws when the role is missing", () => {
        assert.doesNotThrow(() => assertRole([JAMF_WRITE], JAMF_WRITE));
        assert.throws(() => assertRole([JAMF_READ], JAMF_WRITE), /Missing required role: Jamf\.Write/);
    });

    test("resolveRolesFromAuthInfo maps static-token callers to the server's full role set", () => {
        const roles = resolveRolesFromAuthInfo("static-token", undefined, [JAMF_READ, JAMF_WRITE]);
        assert.deepEqual(roles, [JAMF_READ, JAMF_WRITE]);
    });

    test("resolveRolesFromAuthInfo passes through the Entra token's own roles claim", () => {
        assert.deepEqual(resolveRolesFromAuthInfo("entra", [JAMF_READ], [JAMF_READ, JAMF_WRITE]), [JAMF_READ]);
        assert.deepEqual(resolveRolesFromAuthInfo("entra", undefined, [JAMF_READ, JAMF_WRITE]), []);
    });
});

// ── auth.ts: requireMcpAuth ──────────────────────────────────────────────────

function fakeReq(authorization?: string): Request {
    return {
        header: (name: string) => (name.toLowerCase() === "authorization" ? authorization : undefined),
    } as unknown as Request;
}

function fakeRes(): Response & { statusCode?: number; body?: unknown; headers: Record<string, string> } {
    const res = {
        headers: {} as Record<string, string>,
        statusCode: undefined as number | undefined,
        body: undefined as unknown,
        status(code: number) {
            res.statusCode = code;
            return res;
        },
        json(payload: unknown) {
            res.body = payload;
            return res;
        },
        set(name: string, value: string) {
            res.headers[name] = value;
            return res;
        },
    };
    return res as unknown as Response & { statusCode?: number; body?: unknown; headers: Record<string, string> };
}

const noopEntraVerifier = async (_token: string): Promise<EntraAuthInfo> => {
    throw new Error("not used in this test");
};

describe("requireMcpAuth", () => {
    test("fails closed with 503 when neither static token nor Entra is configured", async () => {
        delete process.env.TEST_STATIC_TOKEN;
        delete process.env.TEST_ENTRA_ENABLED;
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: noopEntraVerifier,
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
        });
        const req = fakeReq("Bearer anything");
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(res.statusCode, 503);
        assert.equal(nextCalled, false);
    });

    test("accepts a valid static token and grants the full role set", async () => {
        process.env.TEST_STATIC_TOKEN = "secret-token";
        delete process.env.TEST_ENTRA_ENABLED;
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: noopEntraVerifier,
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
        });
        const req = fakeReq("Bearer secret-token");
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(nextCalled, true);
        assert.equal(req.authMode, "static-token");
        assert.deepEqual(req.auth?.extra.roles, [JAMF_READ, JAMF_WRITE]);
        delete process.env.TEST_STATIC_TOKEN;
    });

    test("rejects a wrong static token with 401 when Entra is not enabled", async () => {
        process.env.TEST_STATIC_TOKEN = "secret-token";
        delete process.env.TEST_ENTRA_ENABLED;
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: noopEntraVerifier,
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
        });
        const req = fakeReq("Bearer wrong-token");
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(res.statusCode, 401);
        assert.equal(nextCalled, false);
        delete process.env.TEST_STATIC_TOKEN;
    });

    test("missing Authorization header is rejected with 401", async () => {
        process.env.TEST_STATIC_TOKEN = "secret-token";
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: noopEntraVerifier,
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
        });
        const req = fakeReq(undefined);
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(res.statusCode, 401);
        assert.equal(nextCalled, false);
        delete process.env.TEST_STATIC_TOKEN;
    });

    test("falls back to a passing Entra verification and uses its roles claim", async () => {
        delete process.env.TEST_STATIC_TOKEN;
        process.env.TEST_ENTRA_ENABLED = "true";
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: async (token) => ({
                token,
                clientId: "some-client",
                scopes: [],
                extra: { roles: [JAMF_READ], oid: "user-oid" },
            }),
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
        });
        const req = fakeReq("Bearer a-real-looking-jwt");
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(nextCalled, true);
        assert.equal(req.authMode, "entra");
        assert.deepEqual(req.auth?.extra.roles, [JAMF_READ]);
        assert.equal(req.auth?.extra.oid, "user-oid");
        delete process.env.TEST_ENTRA_ENABLED;
    });

    test("a failing Entra verification falls through to 401, not a crash", async () => {
        delete process.env.TEST_STATIC_TOKEN;
        process.env.TEST_ENTRA_ENABLED = "true";
        const middleware = requireMcpAuth({
            staticTokenEnvVar: "TEST_STATIC_TOKEN",
            allRoles: [JAMF_READ, JAMF_WRITE],
            entraVerifier: async () => {
                throw new Error("signature verification failed");
            },
            entraEnabledEnvVar: "TEST_ENTRA_ENABLED",
            resourceMetadataUrl: "https://example.com/.well-known/oauth-protected-resource/mcp",
        });
        const req = fakeReq("Bearer bogus.jwt.token");
        const res = fakeRes();
        let nextCalled = false;
        await middleware(req, res, (() => (nextCalled = true)) as NextFunction);
        assert.equal(res.statusCode, 401);
        assert.equal(nextCalled, false);
        assert.match(res.headers["WWW-Authenticate"], /resource_metadata=/);
        delete process.env.TEST_ENTRA_ENABLED;
    });
});
