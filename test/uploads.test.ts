/**
 * Unit tests for staged uploads (src/utils/uploads.ts) and the file-based
 * .intunewin parser. node:test, no network access or credentials required.
 *
 * Run:  npm run test:unit
 */

import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";
import type { AddressInfo } from "node:net";
import express, { Request, Response } from "express";
import {
    createUploadRouter, requireUploadRole, isInsideUploadDir, removeStagedFile, sweepUploadDir, stagedOriginalName,
} from "../src/utils/uploads.js";
import { INTUNE_ALL_ROLES, INTUNE_READ, INTUNE_WRITE } from "../src/utils/roles.js";
import { parseIntunewinPackage, parseIntunewinPackageFile } from "../src/intune/graph-api.js";

const TOKEN = "test-static-token";
let tmpRoot: string;
let uploadDir: string;
let server: http.Server;
let port: number;

before(async () => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "uploads-test-"));
    uploadDir = path.join(tmpRoot, "staging");
    process.env.MCP_UPLOAD_DIR = uploadDir;
    process.env.UPLOAD_TEST_TOKEN = TOKEN;
    process.env.MCP_UPLOAD_MAX_BYTES = "1000";

    const app = express();
    app.use(
        createUploadRouter({
            auth: {
                staticTokenEnvVar: "UPLOAD_TEST_TOKEN",
                allRoles: INTUNE_ALL_ROLES,
                entraVerifier: async () => { throw new Error("entra disabled"); },
                entraEnabledEnvVar: "UPLOAD_TEST_ENTRA_ENABLED",
            },
            requiredRole: INTUNE_WRITE,
            allowedExtensions: [".intunewin"],
            label: "test",
        })
    );
    await new Promise<void>((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
    port = (server.address() as AddressInfo).port;
});

after(() => {
    server.close();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    delete process.env.MCP_UPLOAD_DIR;
    delete process.env.UPLOAD_TEST_TOKEN;
    delete process.env.MCP_UPLOAD_MAX_BYTES;
});

beforeEach(() => {
    for (const f of fs.readdirSync(uploadDir)) fs.rmSync(path.join(uploadDir, f), { recursive: true, force: true });
});

function put(name: string, body: Buffer | Buffer[], headers: Record<string, string> = {}, auth = true) {
    return new Promise<{ status: number; body: any }>((resolve, reject) => {
        const req = http.request(
            { host: "127.0.0.1", port, method: "PUT", path: `/uploads/${name}`, headers: { ...(auth ? { Authorization: `Bearer ${TOKEN}` } : {}), ...headers } },
            (res) => {
                const chunks: Buffer[] = [];
                res.on("data", (c) => chunks.push(c));
                res.on("end", () => {
                    const text = Buffer.concat(chunks).toString();
                    resolve({ status: res.statusCode!, body: text ? JSON.parse(text) : undefined });
                });
            }
        );
        // An early 413 can reset the socket mid-write; the response (if any) is what matters.
        req.on("error", reject);
        for (const b of Array.isArray(body) ? body : [body]) req.write(b);
        req.end();
    });
}

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

describe("PUT /uploads/:fileName", () => {
    test("stores the file and returns path, size and sha256", async () => {
        const data = Buffer.from("hello intunewin");
        const res = await put("App.intunewin", data, { "X-Content-SHA256": sha(data) });
        assert.equal(res.status, 201);
        assert.equal(res.body.fileName, "App.intunewin");
        assert.equal(res.body.size, data.length);
        assert.equal(res.body.sha256, sha(data));
        assert.ok(Date.parse(res.body.expiresAt) > Date.now());
        assert.deepEqual(fs.readFileSync(res.body.path), data);
        assert.ok(isInsideUploadDir(res.body.path));
        assert.equal(stagedOriginalName(res.body.path), "App.intunewin");
        assert.deepEqual(fs.readdirSync(uploadDir).filter((f) => f.endsWith(".part")), []);
    });

    test("wrong X-Content-SHA256 -> 400 and nothing left behind", async () => {
        const res = await put("App.intunewin", Buffer.from("abc"), { "X-Content-SHA256": "0".repeat(64) });
        assert.equal(res.status, 400);
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });

    test("Content-Length over the cap -> 413 up front", async () => {
        const res = await put("App.intunewin", Buffer.alloc(1001));
        assert.equal(res.status, 413);
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });

    test("streamed body over the cap (chunked, no Content-Length) -> 413 and no file left", async () => {
        const res = await put("App.intunewin", [Buffer.alloc(600), Buffer.alloc(600)], { "Transfer-Encoding": "chunked" });
        assert.equal(res.status, 413);
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });

    test("bad file names and extensions -> 400", async () => {
        for (const name of ["App.exe", "..%2Fevil.intunewin", ".hidden.intunewin", "a%5Cb.intunewin", "noext"]) {
            const res = await put(name, Buffer.from("x"));
            assert.equal(res.status, 400, name);
        }
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });

    test("missing or wrong token -> 401", async () => {
        assert.equal((await put("App.intunewin", Buffer.from("x"), {}, false)).status, 401);
        assert.equal((await put("App.intunewin", Buffer.from("x"), { Authorization: "Bearer nope" }, false)).status, 401);
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });

    test("client disconnect mid-upload leaves no partial file", async () => {
        await new Promise<void>((resolve) => {
            const req = http.request({ host: "127.0.0.1", port, method: "PUT", path: "/uploads/App.intunewin", headers: { Authorization: `Bearer ${TOKEN}`, "Transfer-Encoding": "chunked" } });
            req.on("error", () => resolve());
            req.write(Buffer.alloc(100));
            setTimeout(() => req.destroy(), 50);
        });
        await new Promise((r) => setTimeout(r, 200));
        assert.deepEqual(fs.readdirSync(uploadDir), []);
    });
});

describe("requireUploadRole", () => {
    function run(roles: string[] | undefined) {
        let status: number | undefined;
        let nextCalled = false;
        const req = { auth: roles ? { extra: { roles } } : undefined } as unknown as Request;
        const res = { status(s: number) { status = s; return this; }, json() { return this; } } as unknown as Response;
        requireUploadRole(INTUNE_WRITE)(req, res, () => { nextCalled = true; });
        return { status, nextCalled };
    }

    test("403s a caller lacking the Write role (e.g. Read-only Entra token)", () => {
        assert.deepEqual(run([INTUNE_READ]), { status: 403, nextCalled: false });
        assert.deepEqual(run(undefined), { status: 403, nextCalled: false });
    });

    test("passes a caller with the Write role", () => {
        assert.deepEqual(run([INTUNE_READ, INTUNE_WRITE]), { status: undefined, nextCalled: true });
    });
});

describe("isInsideUploadDir / removeStagedFile", () => {
    test("accepts a real staged file, rejects .., symlink escapes, the dir itself and missing files", () => {
        const inside = path.join(uploadDir, "ok.intunewin");
        fs.writeFileSync(inside, "x");
        const outside = path.join(tmpRoot, "secret.txt");
        fs.writeFileSync(outside, "secret");
        fs.symlinkSync(outside, path.join(uploadDir, "link.intunewin"));

        assert.equal(isInsideUploadDir(inside), true);
        assert.equal(isInsideUploadDir(path.join(uploadDir, "..", "secret.txt")), false);
        assert.equal(isInsideUploadDir(path.join(uploadDir, "link.intunewin")), false);
        assert.equal(isInsideUploadDir(uploadDir), false);
        assert.equal(isInsideUploadDir(path.join(uploadDir, "missing.intunewin")), false);

        removeStagedFile(path.join(uploadDir, "link.intunewin")); // symlink escapes -> must not delete target
        removeStagedFile(outside);
        assert.ok(fs.existsSync(outside));
        removeStagedFile(inside);
        assert.ok(!fs.existsSync(inside));
    });
});

describe("sweepUploadDir", () => {
    test("deletes expired files and stale .part files, keeps fresh ones", () => {
        const old = path.join(uploadDir, "old.intunewin");
        const fresh = path.join(uploadDir, "fresh.intunewin");
        const stalePart = path.join(uploadDir, ".abc.part");
        const freshPart = path.join(uploadDir, ".def.part");
        for (const f of [old, fresh, stalePart, freshPart]) fs.writeFileSync(f, "x");
        const ago = (ms: number) => new Date(Date.now() - ms);
        fs.utimesSync(old, ago(25 * 3600_000), ago(25 * 3600_000));
        fs.utimesSync(stalePart, ago(2 * 3600_000), ago(2 * 3600_000));
        fs.utimesSync(freshPart, ago(60_000), ago(60_000));

        assert.equal(sweepUploadDir(), 2);
        assert.ok(!fs.existsSync(old) && !fs.existsSync(stalePart));
        assert.ok(fs.existsSync(fresh) && fs.existsSync(freshPart));
    });
});

// ── file-based .intunewin parsing ────────────────────────────────────────────

/** Minimal ZIP writer (stored or deflated) so tests need no archive dependency. */
function buildZip(entries: { name: string; data: Buffer; deflate?: boolean }[]): Buffer {
    const zlib = require("node:zlib") as typeof import("node:zlib");
    const locals: Buffer[] = [];
    const centrals: Buffer[] = [];
    let offset = 0;
    for (const e of entries) {
        const name = Buffer.from(e.name);
        const body = e.deflate ? zlib.deflateRawSync(e.data) : e.data;
        const method = e.deflate ? 8 : 0;
        const crc = crc32(e.data);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6);
        local.writeUInt16LE(method, 8); local.writeUInt32LE(0, 10); local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(body.length, 18); local.writeUInt32LE(e.data.length, 22);
        local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
        locals.push(local, name, body);
        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
        central.writeUInt16LE(0, 8); central.writeUInt16LE(method, 10); central.writeUInt32LE(0, 12);
        central.writeUInt32LE(crc, 16); central.writeUInt32LE(body.length, 20); central.writeUInt32LE(e.data.length, 24);
        central.writeUInt16LE(name.length, 28); central.writeUInt32LE(offset, 42);
        centrals.push(central, name);
        offset += 30 + name.length + body.length;
    }
    const centralBuf = Buffer.concat(centrals);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, centralBuf, eocd]);
}

describe("file-based .intunewin parser", () => {
    const detection = `<?xml version="1.0"?><ApplicationInfo><FileName>IntunePackage.intunewin</FileName>` +
        `<SetupFile>install.ps1</SetupFile><UnencryptedContentSize>12345</UnencryptedContentSize>` +
        `<EncryptionInfo><EncryptionKey>ek</EncryptionKey><MacKey>mk</MacKey><InitializationVector>iv</InitializationVector>` +
        `<Mac>mac</Mac><ProfileIdentifier>ProfileVersion1</ProfileIdentifier><FileDigest>fd</FileDigest>` +
        `<FileDigestAlgorithm>SHA256</FileDigestAlgorithm></EncryptionInfo></ApplicationInfo>`;

    for (const deflate of [false, true]) {
        test(`matches the buffer parser (metadata, size, bytes) — ${deflate ? "deflated" : "stored"} payload`, async () => {
            // Non-block-aligned payload so streaming spans several zip chunks.
            const payload = Buffer.alloc(200_003);
            for (let i = 0; i < payload.length; i++) payload[i] = (i * 31 + 7) & 0xff;
            const zip = buildZip([
                { name: "IntuneWinPackage/Metadata/Detection.xml", data: Buffer.from(detection), deflate },
                { name: "IntuneWinPackage/Contents/IntunePackage.intunewin", data: payload, deflate },
            ]);
            const zipPath = path.join(tmpRoot, `fake-${deflate}.intunewin`);
            fs.writeFileSync(zipPath, zip);

            const fromBuffer = await parseIntunewinPackage(zip);
            const fromFile = await parseIntunewinPackageFile(zipPath);

            const { encryptedContent, ...bufferMeta } = fromBuffer;
            assert.deepEqual(fromFile.metadata, bufferMeta);
            assert.equal(fromFile.encryptedSize, encryptedContent.length);

            const chunks: Buffer[] = [];
            for await (const c of fromFile.streamEncryptedContent()) chunks.push(c);
            assert.ok(Buffer.concat(chunks).equals(encryptedContent));
        });
    }

    test("rejects a package without Detection.xml", async () => {
        const zipPath = path.join(tmpRoot, "nodetect.intunewin");
        fs.writeFileSync(zipPath, buildZip([{ name: "IntuneWinPackage/Contents/x.intunewin", data: Buffer.from("x") }]));
        await assert.rejects(parseIntunewinPackageFile(zipPath), /missing Metadata\/Detection\.xml/);
    });
});
