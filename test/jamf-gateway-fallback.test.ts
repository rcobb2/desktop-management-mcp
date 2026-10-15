/**
 * Unit tests for credential routing in JamfClient: restGet()'s tenant-first,
 * Gateway-fallback order, and lapsGet()'s LAPS-client-first, Gateway-fallback order.
 *
 * History: before 2026-09-04 restGet() routed all ~30 non-Classic REST GETs through
 * the Platform API Gateway unconditionally, so an expired Gateway secret took down
 * ~30 tools the tenant credential serves fine. Since 2026-10-15 the tenant client is
 * the default (least privilege — the Gateway credential can also delete records and
 * read LAPS) and the Gateway is only a fallback.
 *
 * Self-contained: uses fake credentials and stubs every axios instance, so it
 * needs no live Jamf tenant (unlike jamf-api.test.ts).
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { JamfClient } from "../src/jamf/jamf-api.js";

// JamfClient reads all of its config in the constructor, not at module load,
// so setting these here (before any makeClient() call) is sufficient.
process.env.JAMF_URL ??= "https://unit-test.invalid";
process.env.JAMF_CLIENT_ID ??= "unit-test";
process.env.JAMF_CLIENT_SECRET ??= "unit-test";

function httpError(status: number) {
    return Object.assign(new Error(`Request failed with status code ${status}`), {
        response: { status },
    });
}

/**
 * Builds a client with the Gateway "configured" and every HTTP client stubbed.
 * `tenantResults` is consumed one per tenant-client call: an Error is thrown,
 * anything else is returned as the response data.
 */
function makeClient(tenantResults: unknown[], { gateway = true } = {}) {
    process.env.JAMF_PLATFORM_TENANT_ID = "tenant-uuid";
    const c: any = new JamfClient();
    c.platformClientId = gateway ? "gw-id" : "";
    c.platformClientSecret = gateway ? "gw-secret" : "";
    c.platformTokenUrl = gateway ? "https://us.apigw.jamf.com/auth/token" : "";

    const calls = { tenantMint: 0, tenant: 0, gateway: 0, gatewayPaths: [] as string[] };
    c.authenticate = async () => { calls.tenantMint++; c.token = "t"; c.tokenExpiresAt = Date.now() + 60_000; };
    c.ensurePlatformAuthenticated = async () => {};
    c.client = {
        get: async () => {
            const r = tenantResults[calls.tenant++];
            if (r instanceof Error) throw r;
            return { data: r };
        },
    };
    c.platformClient = { get: async (p: string) => { calls.gateway++; calls.gatewayPaths.push(p); return { data: "gateway" }; } };
    c.logger = { info() {}, warn() {}, error() {} };
    return { c, calls };
}

describe("restGet credential routing", () => {
    test("serves ordinary reads from the tenant client, never touching the Gateway", async () => {
        const { c, calls } = makeClient(["direct", "direct"]);
        assert.equal((await c.restGet("/api/v1/scripts")).data, "direct");
        assert.equal((await c.restGet("/api/v1/sites")).data, "direct");
        assert.equal(calls.gateway, 0);
    });

    test("falls back to the Gateway when the tenant client gets 403", async () => {
        const { c, calls } = makeClient([httpError(403)]);
        assert.equal((await c.restGet("/api/v1/scripts")).data, "gateway");
        assert.deepEqual(calls.gatewayPaths, ["/pro/v1/tenant/tenant-uuid/scripts"]);
    });

    test("re-mints the tenant token once on 401 before falling back", async () => {
        const { c, calls } = makeClient([httpError(401), "direct"]);
        assert.equal((await c.restGet("/api/v1/scripts")).data, "direct");
        assert.equal(calls.tenantMint, 2, "should mint, get 401, re-mint, then succeed");
        assert.equal(calls.gateway, 0);
    });

    test("does NOT mask a non-auth tenant failure", async () => {
        const { c, calls } = makeClient([httpError(503)]);
        await assert.rejects(() => c.restGet("/api/v1/scripts"), /503/);
        assert.equal(calls.gateway, 0, "a 5xx must propagate, not silently fall back");
    });

    test("propagates a tenant 403 when no Gateway is configured", async () => {
        const { c } = makeClient([httpError(403)], { gateway: false });
        await assert.rejects(() => c.restGet("/api/v1/scripts"), /403/);
    });

    test("concurrent requests share one tenant token mint", async () => {
        const { c, calls } = makeClient(["a", "b", "c"]);
        let release!: () => void;
        const gate = new Promise<void>(r => { release = r; });
        c.authenticate = async () => { calls.tenantMint++; await gate; c.token = "t"; c.tokenExpiresAt = Date.now() + 60_000; };
        const all = Promise.all(["/api/v1/a", "/api/v1/b", "/api/v1/c"].map(p => c.restGet(p)));
        release();
        await all;
        assert.equal(calls.tenantMint, 1);
    });
});

describe("lapsGet credential routing", () => {
    function withLaps(c: any, lapsResult: unknown) {
        c.lapsClientId = "laps-id";
        c.lapsClientSecret = "laps-secret";
        c.ensureLapsAuthenticated = async () => {};
        c.lapsClient = { get: async () => { if (lapsResult instanceof Error) throw lapsResult; return { data: lapsResult }; } };
    }

    test("uses the LAPS client when configured", async () => {
        const { c, calls } = makeClient([]);
        withLaps(c, "laps");
        assert.equal((await c.lapsGet("/api/v2/local-admin-password/m/accounts")).data, "laps");
        assert.equal(calls.gateway, 0);
    });

    test("falls back to the Gateway when the LAPS client is rejected", async () => {
        const { c, calls } = makeClient([]);
        withLaps(c, httpError(401));
        assert.equal((await c.lapsGet("/api/v2/local-admin-password/m/accounts")).data, "gateway");
        assert.deepEqual(calls.gatewayPaths, ["/pro/v2/tenant/tenant-uuid/local-admin-password/m/accounts"]);
    });

    test("does NOT fall back on a 404 (no LAPS on that Mac)", async () => {
        const { c, calls } = makeClient([]);
        withLaps(c, httpError(404));
        await assert.rejects(() => c.lapsGet("/api/v2/local-admin-password/m/accounts"), /404/);
        assert.equal(calls.gateway, 0);
    });

    test("errors clearly when neither LAPS credential is configured", async () => {
        const { c } = makeClient([], { gateway: false });
        await assert.rejects(() => c.lapsGet("/api/v2/local-admin-password/m/accounts"), /JAMF_LAPS_CLIENT_ID/);
    });
});
