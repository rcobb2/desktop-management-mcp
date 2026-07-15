/**
 * Integration test suite for JamfClient (node:test, no extra deps).
 *
 * Reads credentials from local.settings.json automatically.
 * Destructive / write operations are skipped unless JAMF_TEST_WRITE=1 is set.
 *
 * Run:  npm test
 */

import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import { JamfClient } from "../src/jamf/jamf-api.js";

function requireEnv(name: string): string {
    const v = process.env[name];
    if (!v) throw new Error(`${name} environment variable is required`);
    return v;
}

// ── Test constants ────────────────────────────────────────────────────────────
const WRITE_ENABLED = process.env.JAMF_TEST_WRITE === "1";
const TEST_COMPUTER_NAME   = requireEnv("TEST_COMPUTER_NAME");
const TEST_COMPUTER_SERIAL = requireEnv("TEST_COMPUTER_SERIAL");
const TEST_USER_EMAIL      = requireEnv("TEST_USER_EMAIL");

// ── Helpers ───────────────────────────────────────────────────────────────────
function skipWrite(name: string, fn: (t?: any) => Promise<void>) {
    if (WRITE_ENABLED) {
        return test(name, fn);
    }
    return test(`[SKIP - set JAMF_TEST_WRITE=1 to enable] ${name}`, { skip: true }, fn);
}

function isPermissionOrNotFound(err: unknown): boolean {
    const msg = String(err instanceof Error ? err.message : err);
    return /40[134]|not found|permission denied/i.test(msg);
}

function permissionAwareTest(name: string, fn: () => Promise<void>) {
    return test(name, async (t) => {
        try {
            await fn();
        } catch (err) {
            if (isPermissionOrNotFound(err)) {
                t.diagnostic(`Skipping — API client lacks permission or endpoint unavailable: ${(err as Error).message}`);
                return;
            }
            throw err;
        }
    });
}

// ── Suite ─────────────────────────────────────────────────────────────────────
describe("JamfClient", () => {
    let client: JamfClient;

    before(() => {
        client = new JamfClient();
    });

    // ── Computer inventory (read) ─────────────────────────────────────────────
    describe("Computer inventory", () => {

        test("list computers returns paginated results with serial and OS", async () => {
            const data = await client.getComputersByAssetTag(undefined, 0, 5);
            assert.ok(data.totalCount > 0, "totalCount should be > 0");
            assert.ok(Array.isArray(data.results), "results should be an array");
            assert.ok(data.results.length > 0, "should return at least one computer");

            const c = data.results[0];
            assert.ok(typeof c.name === "string" && c.name.length > 0, "name should be a non-empty string");
            assert.ok(typeof c.serialNumber === "string" && c.serialNumber.length > 0, "serialNumber should be populated");
            assert.ok(typeof c.osVersion === "string" && c.osVersion.length > 0, "osVersion should be populated");
            assert.ok(typeof c.model === "string" && c.model.length > 0, "model should be populated");
        });

        test("list computers filtered by asset tag returns matching subset", async () => {
            const all = await client.getComputersByAssetTag(undefined, 0, 5);
            const firstTag = all.results.find((c: any) => c.assetTag)?.assetTag;
            if (!firstTag) {
                // no asset tags in env — just verify empty filter works
                const noTag = await client.getComputersByAssetTag("", 0, 5);
                assert.ok(Array.isArray(noTag.results));
                return;
            }
            const filtered = await client.getComputersByAssetTag(firstTag, 0, 10);
            assert.ok(filtered.results.every((c: any) => c.assetTag === firstTag), "all results should match the asset tag");
        });

        test("get computer by name returns full inventory detail", async () => {
            const data = await client.getComputerByName(TEST_COMPUTER_NAME);
            assert.ok(data.totalCount === 1, `should find exactly one computer named "${TEST_COMPUTER_NAME}"`);
            const c: any = data.results[0];
            assert.ok(c.general?.name, "general.name should be present");
            assert.ok(c.hardware, "hardware section should be present");
            assert.ok(c.operatingSystem, "operatingSystem section should be present");
        });

        test("get computer by name returns empty for unknown name", async () => {
            const data = await client.getComputerByName("DOES-NOT-EXIST-XYZ-999");
            assert.equal(data.totalCount, 0);
            assert.deepEqual(data.results, []);
        });

        test("get computer by serial returns full inventory detail", async () => {
            const data = await client.getComputerBySerial(TEST_COMPUTER_SERIAL);
            assert.ok(data.totalCount === 1, `should find exactly one computer with serial "${TEST_COMPUTER_SERIAL}"`);
            const c: any = data.results[0];
            assert.ok(c.hardware?.serialNumber === TEST_COMPUTER_SERIAL, "serialNumber should match");
        });

        test("get computer by serial returns empty for unknown serial", async () => {
            const data = await client.getComputerBySerial("XXXXXXXXXXXX");
            assert.equal(data.totalCount, 0);
        });

        test("get computers by user returns results for known user", async () => {
            const data = await client.getComputersByUserIdentifier(TEST_USER_EMAIL);
            assert.ok(typeof data.totalCount === "number");
            assert.ok(Array.isArray(data.results));
            if (data.results.length > 0) {
                const c: any = data.results[0];
                assert.ok(typeof c.name === "string", "each result should have a name");
            }
        });

        test("get computers by user returns empty for unknown user", async () => {
            const data = await client.getComputersByUserIdentifier("nobody@nowhere-fake-domain-xyz.edu");
            assert.equal(data.totalCount, 0);
            assert.deepEqual(data.results, []);
        });

        test("get FileVault status by serial returns disk encryption data", async () => {
            const data: any = await client.getFilevaultStatus(TEST_COMPUTER_SERIAL);
            assert.ok(data !== null, "should return data for known serial");
            assert.ok(data.name, "should include computer name");
            assert.ok(data.diskEncryption !== undefined, "diskEncryption section should be present");
        });
    });

    // ── Mobile devices ────────────────────────────────────────────────────────
    describe("Mobile devices", () => {

        test("get mobile device by name returns empty for unknown device", async () => {
            const data = await client.getMobileDeviceByName("DOES-NOT-EXIST-DEVICE-XYZ");
            assert.equal(data.totalCount, 0);
            assert.deepEqual(data.results, []);
        });
    });

    // ── Groups ────────────────────────────────────────────────────────────────
    describe("Groups", () => {

        test("list smart computer groups returns array with id and name", async () => {
            const data = await client.getSmartComputerGroups();
            const groups: any[] = Array.isArray(data) ? data : (data as any).results ?? [];
            assert.ok(groups.length > 0, "should have at least one smart computer group");
            assert.ok(groups[0].id !== undefined, "group should have an id");
            assert.ok(typeof groups[0].name === "string", "group should have a name");
        });

        test("list smart mobile device groups returns array", async () => {
            const data = await client.getSmartMobileDeviceGroups();
            const groups: any[] = Array.isArray(data) ? data : (data as any).results ?? [];
            assert.ok(Array.isArray(groups), "should return an array");
        });

        test("list static computer groups returns only non-smart groups", async () => {
            const data = await client.getStaticComputerGroups();
            assert.ok(typeof data.totalCount === "number");
            assert.ok(Array.isArray(data.computerGroups));
            // All returned groups should be static (not smart)
            for (const g of data.computerGroups) {
                assert.ok(!g.isSmart, `group "${g.name}" should not be a smart group`);
            }
        });

        test("get smart group members by id returns member list", async () => {
            const groups = await client.getSmartComputerGroups();
            const list: any[] = Array.isArray(groups) ? groups : (groups as any).results ?? [];
            if (list.length === 0) return;

            // Pick a small group (≤10 members) to avoid the N+1 problem at scale
            const small = list.find((g: any) => (g.memberCount ?? 999) <= 10);
            if (!small) {
                // All groups are large — just verify the method exists and returns the right shape
                // by calling a group with memberCount 0 if any
                const empty = list.find((g: any) => g.memberCount === 0);
                if (!empty) return;
                const data = await client.getSmartComputerGroupMembers(String(empty.id));
                assert.ok(typeof data.totalCount === "number");
                assert.ok(Array.isArray(data.members));
                return;
            }
            const data = await client.getSmartComputerGroupMembers(String(small.id));
            assert.ok(typeof data.totalCount === "number");
            assert.ok(Array.isArray(data.members));
        });
    });

    // ── Policies ──────────────────────────────────────────────────────────────
    describe("Policies", () => {

        test("list policies returns results with id and name", async () => {
            const data = await client.getPolicies(undefined, 0, 10);
            assert.ok(data.totalCount > 0, "should have policies");
            assert.ok(data.results.length > 0, "should return results");
            assert.ok(data.results[0].id !== undefined, "policy should have an id");
            assert.ok(typeof data.results[0].name === "string", "policy should have a name");
        });

        test("list policies filtered by name returns matching subset", async () => {
            const all = await client.getPolicies(undefined, 0, 10);
            if (all.results.length === 0) return;
            const firstName: string = all.results[0].name;
            const fragment = firstName.slice(0, 4);
            const filtered = await client.getPolicies(fragment, 0, 50);
            assert.ok(filtered.results.every((p: any) =>
                p.name.toLowerCase().includes(fragment.toLowerCase())
            ), "all results should match the name filter");
        });

        test("get policy detail returns full policy object", async () => {
            const list = await client.getPolicies(undefined, 0, 1);
            if (list.results.length === 0) return;
            const policyId = String(list.results[0].id);
            const policy: any = await client.getPolicyDetail(policyId);
            assert.ok(policy, "should return a policy");
            assert.ok(policy.general?.id !== undefined || policy.id !== undefined, "policy should have an id");
            assert.ok(policy.general?.name ?? policy.name, "policy should have a name");
        });

        test("get policy detail throws for unknown id", async () => {
            await assert.rejects(
                () => client.getPolicyDetail("999999999"),
                /not found|404/i
            );
        });
    });

    // ── Configuration profiles ────────────────────────────────────────────────
    describe("Configuration profiles", () => {

        permissionAwareTest("list configuration profiles returns results", async () => {
            const data = await client.getComputerConfigurationProfiles();
            assert.ok(typeof data.totalCount === "number");
            assert.ok(Array.isArray(data.results));
            if (data.results.length > 0) {
                assert.ok(data.results[0].id !== undefined, "profile should have an id");
                assert.ok(typeof data.results[0].name === "string", "profile should have a name");
            }
        });

        permissionAwareTest("list configuration profiles filtered by name", async () => {
            const all = await client.getComputerConfigurationProfiles();
            if (all.results.length === 0) return;
            const fragment = all.results[0].name.slice(0, 3);
            const filtered = await client.getComputerConfigurationProfiles(fragment);
            assert.ok(filtered.results.every((p: any) =>
                p.name.toLowerCase().includes(fragment.toLowerCase())
            ), "all results should match the name filter");
        });
    });

    // ── Patch policies ────────────────────────────────────────────────────────
    describe("Patch policies", () => {

        permissionAwareTest("list patch policies returns response", async () => {
            const data = await client.getPatchPolicies(0, 10);
            assert.ok(data !== null && data !== undefined);
            assert.ok(Array.isArray((data as any).results ?? []));
        });
    });

    // ── Scripts and packages ──────────────────────────────────────────────────
    describe("Scripts and packages", () => {

        test("list scripts returns results with id and name", async () => {
            const data = await client.getScripts(undefined, 0, 10);
            const scripts: any[] = (data as any).scripts ?? (data as any).results ?? [];
            if (scripts.length > 0) {
                assert.ok(scripts[0].id !== undefined, "script should have an id");
                assert.ok(typeof scripts[0].name === "string", "script should have a name");
            }
        });

        test("list scripts filtered by name returns matching subset", async () => {
            const all = await client.getScripts(undefined, 0, 10);
            const scripts: any[] = (all as any).scripts ?? (all as any).results ?? [];
            if (scripts.length === 0) return;
            const fragment = scripts[0].name.slice(0, 4);
            const filtered = await client.getScripts(fragment, 0, 100);
            const filteredScripts: any[] = (filtered as any).scripts ?? (filtered as any).results ?? [];
            assert.ok(filteredScripts.every((s: any) =>
                s.name.toLowerCase().includes(fragment.toLowerCase())
            ), "all results should match the name filter");
        });

        test("list packages returns results", async () => {
            const data = await client.getPackages(undefined, 0, 10);
            const packages: any[] = (data as any).packages ?? (data as any).results ?? [];
            if (packages.length > 0) {
                assert.ok(packages[0].id !== undefined, "package should have an id");
            }
        });
    });

    // ── Reference data ────────────────────────────────────────────────────────
    describe("Reference data", () => {

        test("list sites returns array with id and name", async () => {
            const data = await client.getSites();
            const sites: any[] = Array.isArray(data) ? data : (data as any).results ?? [];
            if (sites.length > 0) {
                assert.ok(sites[0].id !== undefined);
                assert.ok(typeof sites[0].name === "string");
            }
        });

        permissionAwareTest("list departments returns results", async () => {
            const data = await client.getDepartments();
            assert.ok(data !== null);
            const depts: any[] = (data as any).results ?? [];
            if (depts.length > 0) {
                assert.ok(depts[0].id !== undefined);
                assert.ok(typeof depts[0].name === "string");
            }
        });

        permissionAwareTest("list categories returns results with name and priority", async () => {
            const data = await client.getCategories(0, 10);
            assert.ok(data !== null);
            const cats: any[] = (data as any).results ?? [];
            if (cats.length > 0) {
                assert.ok(cats[0].id !== undefined);
                assert.ok(typeof cats[0].name === "string");
            }
        });
    });

    // ── Enrollment ────────────────────────────────────────────────────────────
    describe("Enrollment", () => {

        test("list inventory preload returns paginated response", async () => {
            const data = await client.getInventoryPreload(0, 5);
            assert.ok(data !== null);
            assert.ok(Array.isArray((data as any).results ?? []));
        });

        permissionAwareTest("list prestage configs returns prestage objects", async () => {
            const data = await client.getPrestageAssignments();
            assert.ok(data !== null);
            const prestages: any[] = (data as any).results ?? [];
            if (prestages.length > 0) {
                assert.ok(prestages[0].id !== undefined);
            }
        });
    });

    // ── Write operations (skipped unless JAMF_TEST_WRITE=1) ──────────────────
    describe("Write operations", () => {

        skipWrite("send BlankPush MDM command to test computer", async () => {
            const result = await client.sendComputerMdmCommand(TEST_COMPUTER_SERIAL, "BlankPush");
            assert.ok(result.success === true);
            assert.equal(result.command, "BlankPush");
        });

        skipWrite("trigger inventory update on test computer", async () => {
            const result = await client.sendComputerMdmCommand(TEST_COMPUTER_SERIAL, "UpdateInventory");
            assert.ok(result.success === true);
        });

        skipWrite("update computer record and restore original values", async () => {
            // Read current values first
            const before = await client.getComputerBySerial(TEST_COMPUTER_SERIAL);
            const loc: any = before.results[0]?.userAndLocation ?? {};

            const originalRoom = loc.room ?? "";
            const testRoom = `test-${Date.now()}`;

            // Write a test value
            const update = await client.updateComputerRecord(TEST_COMPUTER_SERIAL, { room: testRoom });
            assert.ok(update.success);

            // Restore original value
            await client.updateComputerRecord(TEST_COMPUTER_SERIAL, { room: originalRoom });
        });

        skipWrite("flush pending MDM commands from test computer", async () => {
            const result = await client.flushComputerMdmCommands(TEST_COMPUTER_SERIAL, "Pending");
            assert.ok(result.success === true);
        });

        // The API client's role has Create/Update but not Delete permission for
        // scripts, smart groups, or policies (confirmed live against the real
        // tenant) — a test that creates a new one of these would leave it behind
        // permanently. So unlike the package test below, these look for a
        // pre-existing fixture (created once, manually, via the corresponding MCP
        // tool or the JAMF Pro UI) and only exercise the update-in-place path,
        // skipping gracefully if the named fixture doesn't exist yet.

        skipWrite("upsert script updates a pre-existing fixture in place", async (t: any) => {
            const fixtureName = process.env.TEST_SCRIPT_NAME;
            if (!fixtureName) {
                t.skip("set TEST_SCRIPT_NAME to a script name that already exists in JAMF Pro to exercise this test");
                return;
            }
            const found = await client.getScripts(fixtureName, 0, 200);
            const existing = found.results.find((s: any) => s.name === fixtureName);
            if (!existing) {
                t.skip(`no script named "${fixtureName}" exists yet — create one once via jamf_create_script`);
                return;
            }
            const updated = await client.upsertScript({
                name: fixtureName,
                scriptContents: `#!/bin/sh\necho test-${Date.now()}\n`,
            });
            assert.equal(updated.action, "updated");
            assert.equal(updated.id, String(existing.id));
        });

        skipWrite("upsert application smart group updates a pre-existing fixture in place", async (t: any) => {
            const fixtureName = process.env.TEST_SMART_GROUP_NAME;
            if (!fixtureName) {
                t.skip("set TEST_SMART_GROUP_NAME to a smart group name that already exists in JAMF Pro to exercise this test");
                return;
            }
            const smart = await client.getSmartComputerGroups();
            const groups: any[] = Array.isArray(smart) ? smart : (smart as any).results ?? [];
            const existing = groups.find((g: any) => g.name === fixtureName);
            if (!existing) {
                t.skip(`no smart group named "${fixtureName}" exists yet — create one once via jamf_create_smart_group`);
                return;
            }
            const updated = await client.upsertApplicationSmartGroup({
                name: fixtureName,
                applicationTitle: "zzz-test-app.app",
                applicationVersion: `test-${Date.now()}`,
            });
            assert.equal(updated.action, "updated");
            assert.equal(updated.id, String(existing.id));
        });

        skipWrite("update policy scope toggles enabled state and restores it", async (t: any) => {
            const fixtureName = process.env.TEST_POLICY_NAME;
            if (!fixtureName) {
                t.skip("set TEST_POLICY_NAME to a policy name that already exists in JAMF Pro to exercise this test");
                return;
            }
            const found = await client.getPolicies(fixtureName, 0, 200);
            const existing = found.results.find((p: any) => p.name === fixtureName);
            if (!existing) {
                t.skip(`no policy named "${fixtureName}" exists yet — create one once via jamf_create_policy`);
                return;
            }
            const originalDetail = await client.getPolicyDetail(String(existing.id));
            const originalEnabled: boolean = originalDetail.general.enabled;

            const flipped = await client.updatePolicyScope(fixtureName, { enabled: !originalEnabled });
            assert.equal(flipped.enabled, !originalEnabled);

            const restored = await client.updatePolicyScope(fixtureName, { enabled: originalEnabled });
            assert.equal(restored.enabled, originalEnabled);
        });

        // Package delete permission is confirmed present (unlike the three above),
        // so this one is fully self-cleaning — no manual fixture needed, just a
        // small file on disk and JAMF_PACKAGE_UPLOAD_DIR pointing at its directory.
        skipWrite("upsert package uploads a fixture file then cleans up", async (t: any) => {
            const fixturePath = process.env.TEST_PACKAGE_PATH;
            if (!fixturePath) {
                t.skip("set TEST_PACKAGE_PATH (and JAMF_PACKAGE_UPLOAD_DIR) to a small .pkg/.dmg file to exercise this test");
                return;
            }
            const testName = `zzz-test-package-${Date.now()}`;
            const created = await client.upsertPackage({ localFilePath: fixturePath, packageName: testName });
            assert.equal(created.action, "created");
            await client.deletePackage(created.id);
        });
    });
});
