/**
 * Staged uploads: a plain HTTP side door for getting large files (Jamf .pkg/.dmg,
 * Intune .intunewin) onto the MCP server's own disk.
 *
 * Why this exists: MCP tool calls travel as JSON through express.json() (100KB
 * default body limit), so a tool argument can never carry an installer — base64
 * in a tool call 413s long before it gets anywhere near a real package size.
 * Instead the client PUTs the raw bytes to `/uploads/<fileName>` (streamed to
 * disk, never buffered), gets back a server-local `path`, and then passes that
 * path to a tool (`jamf_upload_package.localFilePath` /
 * `intune_create_win32_app.intunewinFilePath`), which streams from disk.
 *
 * The staging directory is container-local and ephemeral on purpose — it only
 * has to survive from "PUT" to "tool call", so a TTL sweeper cleans up anything
 * a caller never consumed.
 */

import { Router, Request, Response, NextFunction } from "express";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { requireMcpAuth } from "./auth.js";
import { hasRole } from "./roles.js";

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024; // 8 GiB
const DEFAULT_TTL_HOURS = 24;
const PART_TTL_MS = 60 * 60 * 1000; // abandoned partial uploads go after 1h regardless of TTL
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const MAX_CONCURRENT_UPLOADS = 2;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$/;
/** `<uuid>-` prefix added when a file is moved into its final staged name. */
const STAGED_PREFIX_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-/;

export function getUploadDir(): string {
    return process.env.MCP_UPLOAD_DIR || path.join(os.tmpdir(), "mcp-uploads");
}

/** Creates the staging directory (mode 0700 — staged installers aren't for other local users). */
export function ensureUploadDir(): string {
    const dir = getUploadDir();
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
}

function getMaxBytes(): number {
    const n = parseInt(process.env.MCP_UPLOAD_MAX_BYTES ?? "", 10);
    return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_BYTES;
}

function getTtlMs(): number {
    const n = parseFloat(process.env.MCP_UPLOAD_TTL_HOURS ?? "");
    return (Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_HOURS) * 60 * 60 * 1000;
}

/**
 * True only if `p` exists and its REAL path (symlinks resolved) is inside the
 * real staging directory. A lexical startsWith check alone would let `..` or a
 * symlink planted in the directory point a tool at an arbitrary server file.
 */
export function isInsideUploadDir(p: string): boolean {
    try {
        const realDir = fs.realpathSync(getUploadDir());
        const realFile = fs.realpathSync(p);
        return realFile.startsWith(realDir + path.sep);
    } catch {
        return false;
    }
}

/** Deletes a staged file if (and only if) it's inside the staging dir. Errors are ignored. */
export function removeStagedFile(p: string): void {
    try {
        if (isInsideUploadDir(p)) fs.unlinkSync(p);
    } catch {
        // Best effort — the TTL sweeper is the backstop.
    }
}

/** Strips the `<uuid>-` prefix so tools see the file's original name, not the staging name. */
export function stagedOriginalName(p: string): string {
    return path.basename(p).replace(STAGED_PREFIX_RE, "");
}

/** Deletes expired files. Exported separately from the timer so tests can drive it directly. */
export function sweepUploadDir(now = Date.now()): number {
    const dir = getUploadDir();
    const ttlMs = getTtlMs();
    let removed = 0;
    let entries: fs.Dirent[];
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return 0;
    }
    for (const entry of entries) {
        if (!entry.isFile()) continue;
        const full = path.join(dir, entry.name);
        try {
            const age = now - fs.statSync(full).mtimeMs;
            const limit = entry.name.endsWith(".part") ? Math.min(PART_TTL_MS, ttlMs) : ttlMs;
            if (age > limit) {
                fs.unlinkSync(full);
                removed++;
            }
        } catch {
            // Raced with a delete/rename — nothing to do.
        }
    }
    return removed;
}

export function startUploadSweeper(): NodeJS.Timeout {
    ensureUploadDir();
    const run = () => {
        const n = sweepUploadDir();
        if (n > 0) console.log(`[uploads] sweeper removed ${n} expired file(s)`);
    };
    run();
    // unref(): a pending sweep must never keep the process alive on shutdown.
    const timer = setInterval(run, SWEEP_INTERVAL_MS);
    timer.unref();
    return timer;
}

class UploadTooLargeError extends Error {}
class UploadChecksumError extends Error {}

export interface UploadRouterOptions {
    /** Exactly the options the server passes to requireMcpAuth for /mcp. */
    auth: Parameters<typeof requireMcpAuth>[0];
    /** Role the caller needs (Jamf.Write / Intune.Write). */
    requiredRole: string;
    /** Lowercase extensions including the dot, e.g. [".pkg", ".dmg"]. */
    allowedExtensions: string[];
    /** Log prefix, e.g. "jamf-mcp". */
    label: string;
}

/**
 * Role gate for the upload route. Reads the same `req.auth.extra.roles` that
 * /mcp feeds into createXMcpServer(roles) — requireMcpAuth already resolved it
 * (static token -> every role; Entra -> the token's roles claim).
 */
export function requireUploadRole(requiredRole: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        const roles = req.auth?.extra.roles ?? [];
        if (!hasRole(roles, requiredRole)) {
            res.status(403).json({ error: `Missing required role: ${requiredRole}` });
            return;
        }
        next();
    };
}

export function createUploadRouter(opts: UploadRouterOptions): Router {
    const router = Router();
    ensureUploadDir();
    let active = 0;

    const fail = (res: Response, status: number, error: string) => {
        if (res.headersSent) return;
        // Close the connection: an early rejection leaves unread body bytes on the
        // socket, and a keep-alive reuse would misparse them as the next request.
        res.set("Connection", "close");
        res.status(status).json({ error });
    };

    router.put(
        "/uploads/:fileName",
        requireMcpAuth(opts.auth),
        requireUploadRole(opts.requiredRole),
        async (req: Request, res: Response) => {
            const raw = req.params.fileName;
            const fileName = path.basename(raw);
            const ext = path.extname(fileName).toLowerCase();
            if (fileName !== raw || !FILE_NAME_RE.test(fileName) || !opts.allowedExtensions.includes(ext)) {
                fail(res, 400, `Invalid file name. Must match ${FILE_NAME_RE} and end in one of: ${opts.allowedExtensions.join(", ")}`);
                return;
            }

            const maxBytes = getMaxBytes();
            const declared = req.header("content-length");
            if (declared !== undefined && Number(declared) > maxBytes) {
                fail(res, 413, `File exceeds the ${maxBytes}-byte upload limit (MCP_UPLOAD_MAX_BYTES)`);
                return;
            }

            const expectedSha = req.header("x-content-sha256")?.trim().toLowerCase();
            if (expectedSha !== undefined && !/^[0-9a-f]{64}$/.test(expectedSha)) {
                fail(res, 400, "X-Content-SHA256 must be a 64-character hex SHA-256");
                return;
            }

            if (active >= MAX_CONCURRENT_UPLOADS) {
                // Keeps multi-GB uploads from starving the /mcp concurrency limiter's share of the box.
                res.set("Retry-After", "30");
                fail(res, 429, "Too many concurrent uploads — retry shortly");
                return;
            }
            active++;

            const dir = ensureUploadDir();
            const id = randomUUID();
            const partPath = path.join(dir, `.${id}.part`);
            const hash = createHash("sha256");
            let size = 0;

            const meter = new Transform({
                transform(chunk: Buffer, _enc, cb) {
                    size += chunk.length;
                    if (size > maxBytes) {
                        cb(new UploadTooLargeError());
                        return;
                    }
                    hash.update(chunk);
                    cb(null, chunk);
                },
            });

            try {
                await pipeline(req, meter, fs.createWriteStream(partPath, { mode: 0o600 }));
                const sha256 = hash.digest("hex");
                if (expectedSha && expectedSha !== sha256) {
                    throw new UploadChecksumError();
                }
                const finalPath = path.join(dir, `${id}-${fileName}`);
                fs.renameSync(partPath, finalPath);

                const who = req.auth?.extra.upn ?? req.auth?.extra.oid ?? req.auth?.clientId ?? "unknown";
                // Never log the token — only identity, file and integrity info.
                console.log(`[${opts.label}] upload by ${who}: ${fileName} ${size} bytes sha256=${sha256}`);
                res.status(201).json({
                    path: finalPath,
                    fileName,
                    size,
                    sha256,
                    expiresAt: new Date(Date.now() + getTtlMs()).toISOString(),
                });
            } catch (err) {
                fs.rmSync(partPath, { force: true });
                if (err instanceof UploadTooLargeError) {
                    fail(res, 413, `File exceeds the ${maxBytes}-byte upload limit (MCP_UPLOAD_MAX_BYTES)`);
                } else if (err instanceof UploadChecksumError) {
                    fail(res, 400, "SHA-256 of the received bytes does not match X-Content-SHA256");
                } else {
                    // Client disconnect / disk error: nothing useful to say to a gone client.
                    console.error(`[${opts.label}] upload of ${fileName} failed:`, (err as Error).message);
                    fail(res, 500, "Upload failed");
                }
            } finally {
                active--;
            }
        }
    );

    return router;
}
