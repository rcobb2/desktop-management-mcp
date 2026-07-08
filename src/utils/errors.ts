/**
 * Shared error helpers for the JAMF and Intune MCP servers.
 */

/** Thrown by name-resolution helpers when multiple candidates match and none is exact. */
export class AmbiguousMatchError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AmbiguousMatchError';
    }
}

function extractStatusCode(err: unknown): number | undefined {
    if (err && typeof err === 'object') {
        const anyErr = err as any;
        if (typeof anyErr.statusCode === 'number') return anyErr.statusCode; // Microsoft Graph SDK errors
        if (anyErr.response && typeof anyErr.response.status === 'number') return anyErr.response.status; // axios
        if (typeof anyErr.status === 'number') return anyErr.status;
    }
    return undefined;
}

function extractRetryAfter(err: unknown): string | undefined {
    const anyErr = err as any;
    const header = anyErr?.response?.headers?.['retry-after'] ?? anyErr?.headers?.get?.('retry-after');
    return header ? String(header) : undefined;
}

/**
 * Maps common HTTP failure modes to actionable guidance for an LLM caller,
 * instead of surfacing a raw axios/Graph SDK message with no next step.
 */
export function translateApiError(err: unknown): string {
    const raw = err instanceof Error ? err.message : String(err);
    const status = extractStatusCode(err);

    switch (status) {
        case 401:
            return `Authentication failed (401). Credentials may be invalid, expired, or the app registration/API client lacks the required scope. Verify the configured client ID/secret and try again. (${raw})`;
        case 403:
            return raw; // call sites already attach specific permission guidance
        case 404:
            return `Not found (404): the requested resource does not exist or the ID/name is wrong. (${raw})`;
        case 429: {
            const retryAfter = extractRetryAfter(err);
            return `Rate limited (429)${retryAfter ? ` — retry after ${retryAfter}s` : ''}. Wait before retrying this request. (${raw})`;
        }
        default:
            if (status !== undefined && status >= 500) {
                return `Upstream service error (${status}). This is likely transient on the JAMF/Intune side — retry the request. (${raw})`;
            }
            return raw;
    }
}
