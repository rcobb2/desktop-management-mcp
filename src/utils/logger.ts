/**
 * Simplified logger for Azure Functions.
 * Azure Functions captures console output into Application Insights automatically.
 * This module preserves the same API surface used by the API client classes
 * (jamf-api.ts, graph-api.ts) so they require zero changes.
 */

import { externalApiRequestDuration, externalApiErrorsTotal } from './metrics.js';

// Minimal logger interface matching what API clients expect
interface Logger {
    info(message: string, meta?: Record<string, any>): void;
    warn(message: string, meta?: Record<string, any>): void;
    error(message: string, meta?: Record<string, any>): void;
    debug(message: string, meta?: Record<string, any>): void;
    // Set by createLogger; read back by logApiCall() below to label external-API
    // metrics without every jamf-api.ts/graph-api.ts call site having to pass a
    // target explicitly.
    readonly service: string;
}

function formatMeta(meta?: Record<string, any>): string {
    if (!meta || Object.keys(meta).length === 0) return '';
    return ' ' + JSON.stringify(meta);
}

export const createLogger = (service: string): Logger => {
    return {
        service,
        info: (message: string, meta?: Record<string, any>) => {
            console.log(`[INFO] [${service}]: ${message}${formatMeta(meta)}`);
        },
        warn: (message: string, meta?: Record<string, any>) => {
            console.warn(`[WARN] [${service}]: ${message}${formatMeta(meta)}`);
        },
        error: (message: string, meta?: Record<string, any>) => {
            console.error(`[ERROR] [${service}]: ${message}${formatMeta(meta)}`);
        },
        debug: (message: string, meta?: Record<string, any>) => {
            if (process.env.LOG_LEVEL === 'debug') {
                console.log(`[DEBUG] [${service}]: ${message}${formatMeta(meta)}`);
            }
        },
    };
};

// 'jamf-api' -> 'jamf', 'intune-api' -> 'intune' (matches the `target` label
// jamf-prestage-tool's metrics use for its own external dependencies).
function targetFromService(service: string): string {
    return service.replace(/-api$/, '');
}

// Best-effort status extraction from a caught error, for metric labeling only
// (never thrown/logged as-is). Handles both axios errors (jamf-api.ts) and the
// Microsoft Graph SDK's GraphError shape (graph-api.ts), falling back to
// 'network_error' the same way jamf-prestage-tool's axios interceptor does.
function statusFromError(error?: Error): string {
    const status = (error as any)?.response?.status ?? (error as any)?.statusCode ?? (error as any)?.code;
    return status !== undefined ? String(status) : 'network_error';
}

// Convenience function for logging API calls (used by jamf-api.ts, graph-api.ts)
export const logApiCall = (
    logger: Logger,
    method: string,
    endpoint: string,
    statusCode?: number,
    duration?: number,
    error?: Error
) => {
    const target = targetFromService(logger.service);

    if (error) {
        logger.error('API call failed', {
            method,
            endpoint,
            statusCode,
            duration: duration ? `${duration}ms` : undefined,
            error: error.message,
        });
        const status = statusCode !== undefined ? String(statusCode) : statusFromError(error);
        externalApiErrorsTotal.inc({ target, method, status });
        if (duration !== undefined) {
            externalApiRequestDuration.observe({ target, method, status }, duration / 1000);
        }
    } else {
        logger.info('API call completed', {
            method,
            endpoint,
            statusCode,
            duration: duration ? `${duration}ms` : undefined,
        });
        if (duration !== undefined) {
            externalApiRequestDuration.observe({ target, method, status: String(statusCode ?? 'unknown') }, duration / 1000);
        }
    }
};

// Convenience function for logging authentication events (used by jamf-api.ts)
export const logAuth = (
    logger: Logger,
    action: 'attempt' | 'success' | 'failure',
    service: string,
    error?: Error
) => {
    if (action === 'failure' && error) {
        logger.error('Authentication failed', { action, service, error: error.message });
    } else {
        logger.info('Authentication event', { action, service });
    }
};
