import type { Request, Response, NextFunction } from "express";

/**
 * Express middleware capping the number of `/mcp` requests handled concurrently,
 * queuing anything past that limit (FIFO) rather than rejecting it. Added closing
 * `MCP_TOOL_GAPS.md` gaps #9 (Intune)/#15 (JAMF) — "firing several concurrent calls
 * wedges the entire server, not just those calls."
 *
 * A local repro (flooding a stateless-mode server with concurrent tool calls whose
 * outbound JAMF/Graph call hangs against an unreachable host) showed this codebase's
 * own Express/Node event loop does NOT block under that load — `/health` kept
 * responding in well under 200ms throughout a 25-call flood, and the flood's own
 * calls all failed independently at the client's own timeout rather than queuing
 * behind each other. So the reported "server wedge" isn't an event-loop-blocking bug
 * in this file — it's that N concurrent tool calls become N concurrent outbound
 * connections to JAMF Pro / Microsoft Graph, and enough of those at once appears to
 * trip something upstream (API-side rate limiting, or a network/firewall connection
 * cap) that then affects unrelated calls too. This middleware doesn't fix that upstream
 * behavior (out of this codebase's control) but bounds how many outbound connections a
 * single client burst can create in the first place, which is the mitigation both gaps'
 * "Ask" line requested either way. Default of 8 is picked from the one piece of
 * empirical data in the gap write-up: 6 concurrent `intune_get_autopilot_status` calls
 * succeeded in the same session that 35 later wedged.
 */
export function limitConcurrentRequests(max: number) {
    let active = 0;
    const queue: Array<() => void> = [];

    return function concurrencyLimiter(_req: Request, res: Response, next: NextFunction): void {
        const release = (() => {
            let released = false;
            return () => {
                if (released) return;
                released = true;
                active--;
                const runNext = queue.shift();
                if (runNext) runNext();
            };
        })();

        const run = () => {
            active++;
            res.on("finish", release);
            res.on("close", release);
            next();
        };

        if (active < max) {
            run();
        } else {
            queue.push(run);
        }
    };
}
