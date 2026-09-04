/**
 * Unit test for restGet()'s Platform API Gateway fallback.
 *
 * Regression cover for the 2026-09-04 outage: an expired account.jamf.com
 * Integration secret made every Gateway token mint 401, and because restGet()
 * routed all ~30 non-Classic REST GETs through the Gateway unconditionally,
 * roughly 30 tools failed with a bare 401 — even though the tenant credential
 * serves every one of those endpoints perfectly well.
 *
 * Self-contained: uses fake credentials and stubs both axios instances, so it
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

function authError(status: number) {
    return Object.assign(new Error(`Request failed with status code ${status}`), {
        response: { status },
    });
}

/** Builds a client with the Gateway "configured" and both HTTP clients stubbed. */
function makeClient(gatewayFailure: unknown) {
    process.env.JAMF_PLATFORM_TENANT_ID = "tenant-uuid";
    const c: any = new JamfClient();
    c.platformClientId = "gw-id";
    c.platformClientSecret = "gw-secret";
    c.platformTokenUrl = "https://us.apigw.jamf.com/auth/token";

    const calls = { gateway: 0, direct: 0 };
    c.ensurePlatformAuthenticated = async () => {
        calls.gateway++;
        throw gatewayFailure;
    };
    c.client = { get: async () => { calls.direct++; return { data: "direct" }; } };
    c.platformClient = { get: async () => ({ data: "gateway" }) };
    c.logger = { info() {}, warn() {}, error() {} };
    return { c, calls };
}

describe("restGet Platform API Gateway fallback", () => {
    for (const status of [401, 403]) {
        test(`falls back to the tenant credential when the Gateway returns ${status}`, async () => {
            const { c, calls } = makeClient(authError(status));
            const res = await c.restGet("/api/v1/scripts");
            assert.equal(res.data, "direct", "should have served the call from the direct client");
            assert.equal(calls.direct, 1);
        });
    }

    test("latches off so a doomed token mint is paid only once", async () => {
        const { c, calls } = makeClient(authError(401));
        for (const p of ["/api/v1/scripts", "/api/v1/categories", "/api/v3/computers-inventory"]) {
            await c.restGet(p);
        }
        assert.equal(calls.gateway, 1, "Gateway auth should be attempted once, then latched off");
        assert.equal(calls.direct, 3, "every call should still be served by the direct client");
    });

    test("does NOT mask a non-auth Gateway failure", async () => {
        const { c, calls } = makeClient(authError(503));
        await assert.rejects(() => c.restGet("/api/v1/scripts"), /503/);
        assert.equal(calls.direct, 0, "a 5xx must propagate, not silently fall back");
    });
});
