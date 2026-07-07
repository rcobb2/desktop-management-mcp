/**
 * Simplified logger for Azure Functions.
 * Azure Functions captures console output into Application Insights automatically.
 * This module preserves the same API surface used by the API client classes
 * (jamf-api.ts, graph-api.ts) so they require zero changes.
 */

// Minimal logger interface matching what API clients expect
interface Logger {
    info(message: string, meta?: Record<string, any>): void;
    warn(message: string, meta?: Record<string, any>): void;
    error(message: string, meta?: Record<string, any>): void;
    debug(message: string, meta?: Record<string, any>): void;
}

function formatMeta(meta?: Record<string, any>): string {
    if (!meta || Object.keys(meta).length === 0) return '';
    return ' ' + JSON.stringify(meta);
}

export const createLogger = (service: string): Logger => {
    return {
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

// Convenience function for logging API calls (used by jamf-api.ts, graph-api.ts)
export const logApiCall = (
    logger: Logger,
    method: string,
    endpoint: string,
    statusCode?: number,
    duration?: number,
    error?: Error
) => {
    if (error) {
        logger.error('API call failed', {
            method,
            endpoint,
            statusCode,
            duration: duration ? `${duration}ms` : undefined,
            error: error.message,
        });
    } else {
        logger.info('API call completed', {
            method,
            endpoint,
            statusCode,
            duration: duration ? `${duration}ms` : undefined,
        });
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
