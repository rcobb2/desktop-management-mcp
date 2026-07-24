import client from "prom-client";
import type { Request, Response, NextFunction } from "express";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

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

// Per-MCP-tool-call metrics — distinct from http_requests_total (which only
// sees one inbound POST /mcp per call, regardless of which tool it invoked
// or whether the tool itself succeeded). `caller` identifies who invoked the
// tool: the Entra token's `upn` when available, else its `clientId`, else the
// literal "static-token" for the legacy auth path — resolved once per request
// in jamf-server.ts/intune-server.ts (the only place req.auth is available)
// and threaded into instrumentToolCalls() below. Duration deliberately omits
// `caller` to keep histogram cardinality bounded (tool × status is already
// the useful axis for latency; who called it matters for volume/attribution,
// not for spotting a slow tool).
export const mcpToolCallsTotal = new client.Counter({
    name: "mcp_tool_calls_total",
    help: "Total number of MCP tool invocations",
    labelNames: ["server", "tool", "status", "caller"] as const,
    registers: [register],
});

export const mcpToolCallDuration = new client.Histogram({
    name: "mcp_tool_call_duration_seconds",
    help: "Duration of MCP tool invocations in seconds",
    labelNames: ["server", "tool", "status"] as const,
    buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5, 10],
    registers: [register],
});

/**
 * Wraps every tool a `McpServer` registers from this point forward with
 * call-count/duration/success-rate instrumentation, without touching each of
 * the dozens of individual `registerTool()` call sites in jamf-server.ts /
 * intune-server.ts. Call this immediately after constructing the server and
 * before any `registerTool()` calls — both servers build a fresh `McpServer`
 * per HTTP request (stateless mode), so this also runs fresh per request,
 * with `caller` resolved from that request's `req.auth`.
 *
 * A tool call counts as `status: "error"` either when its handler throws, or
 * when it returns normally with `isError: true` — every tool here catches its
 * own errors internally (see errorResult() in both server files) and returns
 * the latter shape rather than throwing, so both paths matter.
 */
export function instrumentToolCalls(server: McpServer, serverLabel: string, caller: string): void {
    const originalRegisterTool = server.registerTool.bind(server);
    server.registerTool = ((name: string, config: unknown, handler: (...args: unknown[]) => unknown) => {
        const wrapped = async (...handlerArgs: unknown[]) => {
            const start = process.hrtime.bigint();
            let status = "success";
            try {
                const result = await handler(...handlerArgs);
                if (result && typeof result === "object" && (result as { isError?: boolean }).isError) {
                    status = "error";
                }
                return result;
            } catch (err) {
                status = "error";
                throw err;
            } finally {
                const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9;
                mcpToolCallDuration.observe({ server: serverLabel, tool: name, status }, durationSeconds);
                mcpToolCallsTotal.inc({ server: serverLabel, tool: name, status, caller });
            }
        };
        return originalRegisterTool(name, config as never, wrapped as never);
    }) as typeof server.registerTool;
}

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
