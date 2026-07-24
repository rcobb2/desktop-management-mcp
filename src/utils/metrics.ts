import client from "prom-client";
import type { Request, Response, NextFunction } from "express";

/**
 * Shared Prometheus registry/metrics for both MCP servers (jamf-server.ts,
 * intune-server.ts). One module rather than duplicated per server, following
 * the same precedent as auth.ts/entra-jwt.ts/roles.ts — a metric name/label
 * drifting between the two copies would silently break cross-app dashboards.
 *
 * Metric names/labels are kept identical to jamf-prestage-tool's
 * server/metrics.ts (a sibling app) on purpose, so the same Grafana
 * dashboards/alerts work unmodified across both apps.
 */

export const register = new client.Registry();
client.collectDefaultMetrics({ register });

export const httpRequestDuration = new client.Histogram({
    name: "http_request_duration_seconds",
    help: "Duration of HTTP requests in seconds",
    labelNames: ["method", "route", "status"] as const,
    buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5, 10],
    registers: [register],
});

export const httpRequestsTotal = new client.Counter({
    name: "http_requests_total",
    help: "Total number of HTTP requests",
    labelNames: ["method", "route", "status"] as const,
    registers: [register],
});

// Outbound calls to JAMF Pro / Microsoft Graph are these servers' external
// dependencies; tracked separately from inbound HTTP, and by target, so a
// slow/failing upstream is visible independent of how the MCP server itself
// is performing. Recorded from utils/logger.ts's logApiCall() — the one
// function both jamf-api.ts and graph-api.ts already funnel every outbound
// call's method/endpoint/status/duration through — rather than hooking each
// HTTP client individually (jamf-api.ts uses axios, graph-api.ts uses the
// Microsoft Graph SDK's own middleware chain plus a couple of raw `fetch`
// calls for blob upload, so there's no single shared HTTP client to
// instrument centrally the way jamf-prestage-tool's axios instance is).
export const externalApiRequestDuration = new client.Histogram({
    name: "external_api_request_duration_seconds",
    help: "Duration of outbound requests to external APIs (JAMF Pro, Microsoft Graph) in seconds",
    labelNames: ["target", "method", "status"] as const,
    buckets: [0.05, 0.1, 0.3, 0.5, 1, 2, 5, 10],
    registers: [register],
});

export const externalApiErrorsTotal = new client.Counter({
    name: "external_api_errors_total",
    help: "Total number of failed outbound requests to external APIs (JAMF Pro, Microsoft Graph)",
    labelNames: ["target", "method", "status"] as const,
    registers: [register],
});

/**
 * Express middleware recording inbound request count/duration. Mount before
 * routes (`app.use(metricsMiddleware)`) so it wraps everything, including
 * `/health` and `/metrics` itself. Both servers here expose only `/mcp`,
 * `/health`, and `/metrics` (plus the Entra OAuth protected-resource metadata
 * routes when enabled), so `req.path` is used directly as the route label —
 * no per-request identifiers (serials, device IDs, etc.) ever appear in a
 * label, matching jamf-prestage-tool's `withMetrics(route, handler)` fixed
 * label approach without needing that same wrapper shape here.
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
    const start = process.hrtime.bigint();
    res.on("finish", () => {
        const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9;
        const labels = { method: req.method, route: req.path, status: String(res.statusCode) };
        httpRequestDuration.observe(labels, durationSeconds);
        httpRequestsTotal.inc(labels);
    });
    next();
}

/** Route handler for `GET /metrics`, scraped by Prometheus. */
export async function metricsHandler(_req: Request, res: Response): Promise<void> {
    res.set("Content-Type", register.contentType);
    res.end(await register.metrics());
}
