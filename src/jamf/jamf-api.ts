import axios, { AxiosInstance } from 'axios';
import { createLogger, logApiCall, logAuth } from '../utils/logger.js';

/**
 * Escapes a value for safe interpolation into a JAMF Pro RSQL filter string
 * literal (e.g. `general.name=="${escapeRsqlValue(name)}"`). Without this, an
 * unescaped `"` in caller-supplied input breaks out of the intended clause
 * and lets RSQL boolean operators be injected into the filter.
 */
function escapeRsqlValue(value: string): string {
    return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Pulls a human-readable detail string out of a failed axios call against a
 * v2 Jamf API endpoint. Those endpoints return `{"errors": [{"code": "...",
 * "description": "...", ...}]}` on failure (confirmed live — e.g.
 * `DEVICE_DOES_NOT_EXIST_ON_TOKEN` from computer-prestages scope writes) —
 * distinct from the Classic API's bare-status-code-no-body failures
 * elsewhere in this file. Falls back to whatever's available if the body
 * doesn't match that shape, rather than throwing away detail the caller
 * hasn't seen before.
 */
function extractJamfErrorDetail(error: unknown): string {
    if (axios.isAxiosError(error)) {
        const data = error.response?.data as { errors?: Array<{ code?: string; description?: string }>; message?: string } | string | undefined;
        if (data && typeof data === 'object') {
            if (Array.isArray(data.errors) && data.errors.length > 0) {
                return data.errors.map((e) => e.description ?? e.code ?? JSON.stringify(e)).join('; ');
            }
            if (data.message) return data.message;
            return JSON.stringify(data);
        }
        if (typeof data === 'string' && data) return data;
        return `HTTP ${error.response?.status ?? '?'}: ${error.message}`;
    }
    return error instanceof Error ? error.message : String(error);
}

/**
 * Escapes a value for safe use as XML element text content.
 */
function escapeXml(value: unknown): string {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

// Matches the legacy/imaging-era auto-generated policy naming pattern observed
// across this tenant's full policy list (e.g. "2014-05-27 at 1:47 PM |
// akhazaee | 1 Computer") — timestamp + admin username + computer count, none
// of which are real Self Service catalog entries. Used to cheaply narrow the
// ~2,724-policy list without an expensive per-policy detail fetch.
const JAMF_AUTO_GENERATED_POLICY_NAME = /^\d{4}-\d{2}-\d{2} at \d{1,2}:\d{2} ?(AM|PM) \| .+ \| \d+ Computers?$/i;

// Jamf's Classic API rejects JSON bodies on policy/computer-group POST/PUT with a
// 415 (confirmed live — only GETs on these endpoints accept the Accept:
// application/json trick; writes require real XML), unlike /JSSResource/computers
// which does accept a JSON body on PUT. Container keys whose value is a JS array
// need each item wrapped in the *singular* form of the container tag (e.g.
// <computer_groups><computer_group>...) — this maps the container keys this
// codebase actually emits to their singular tag name; anything else falls back to
// stripping a trailing "s".
const XML_PLURAL_TO_SINGULAR: Record<string, string> = {
    computer_groups: 'computer_group',
    computers: 'computer',
    buildings: 'building',
    departments: 'department',
    scripts: 'script',
    packages: 'package',
    criteria: 'criterion',
    jss_users: 'user',
    jss_user_groups: 'user_group',
};

/**
 * Recursively serializes a plain object into XML element bodies (no wrapping root
 * tag — callers add that). Null/undefined values are omitted entirely — a caller
 * that wants a field left untouched by a partial-update PUT passes `undefined`
 * (see e.g. upsertPolicy's `exclusions: exclusionGroups.length ? {...} : undefined`).
 *
 * Every array-backed element always gets an explicit `<size>` as its first child,
 * including `<size>0</size>` for an empty array. Confirmed live: Jamf's Classic API
 * silently no-ops a PUT that changes a list-typed field (e.g. `packages`, computer
 * group `criteria`, `scope`'s `computer_groups`/`exclusions`) unless `<size>` is
 * present — it returns 201 but a follow-up GET shows the field unchanged. Without
 * always emitting `<size>`, an explicit empty array (e.g. clearing a policy's scope
 * exclusions down to zero) would hit exactly this no-op, indistinguishable from the
 * field being merely absent.
 */
function serializeXmlObjectBody(obj: any): string {
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return escapeXml(obj);
    return Object.entries(obj)
        .filter(([, v]) => v !== undefined && v !== null)
        .map(([key, value]) => {
            if (Array.isArray(value)) {
                const singular = XML_PLURAL_TO_SINGULAR[key] ?? key.replace(/s$/, '');
                const items = value.map((item) => `<${singular}>${serializeXmlObjectBody(item)}</${singular}>`).join('');
                return `<${key}><size>${value.length}</size>${items}</${key}>`;
            }
            if (typeof value === 'object') return `<${key}>${serializeXmlObjectBody(value)}</${key}>`;
            return `<${key}>${escapeXml(value)}</${key}>`;
        })
        .join('');
}

function buildXmlDocument(rootTag: string, body: any): string {
    return `<?xml version="1.0" encoding="UTF-8"?><${rootTag}>${serializeXmlObjectBody(body)}</${rootTag}>`;
}

// Jamf's Platform API Gateway proxies most of Jamf Pro's own REST API (v1/v2/v3/v4,
// NOT Classic API) plus platform-native features (Compliance Benchmarks, Blueprints)
// that don't exist on the tenant's own Jamf Pro instance at all — a distinct host from
// every other endpoint in this file, and a GENUINELY SEPARATE OAuth2 client-credentials
// credential from JAMF_CLIENT_ID/SECRET above, not a token-reuse situation. Confirmed
// live 2026-07-29 against a real account.jamf.com Integration credential
// (JAMF_PLATFORM_CLIENT_ID/SECRET, exchanged at JAMF_PLATFORM_URL — NOT the
// `/oauth2/token` path the OpenAPI spec documents; the real deployed token endpoint
// differs from the spec):
//   - It has privileges the tenant's own JAMF_CLIENT_ID/SECRET role does NOT: bulk
//     FileVault (`read:env:filevault`) 403s directly but returns real data through
//     this Gateway credential.
//   - Its REST API coverage is broad, not narrow as first assumed — direct live testing
//     of every non-Classic REST resource this file uses (computers-inventory + detail,
//     categories, departments, sites, scripts, packages, computer-groups, mobile-devices,
//     computer-prestages, app-installers, cloud-idp, inventory-preload) all returned 200.
//     The ONLY confirmed exceptions are Classic API (GET .../api/proclassic/JSSResource/
//     categories returned a clean 403 BAD_PERMISSIONS) and patch-policies specifically
//     (GET .../api/pro/v3/tenant/{id}/patch-policies also 403s) — every other REST
//     resource tested is reachable. restGet(), below, is the shared entry point that
//     routes a direct-API GET through this Gateway when JAMF_PLATFORM_* is configured,
//     falling back to the direct client otherwise (so this stays a zero-config-required
//     optimization, not a new hard dependency).
// Base host per Jamf's spec (confirmed via jamf-docs MCP's get-server-variables):
// https://{region}.apigw.jamf.com/api, region defaulting to "us" (also "eu"/"apac").
// JAMF_PLATFORM_REGION overrides the default for tenants outside the US.
function platformApiBaseUrl(): string {
    const region = process.env.JAMF_PLATFORM_REGION || 'us';
    return `https://${region}.apigw.jamf.com/api`;
}

// Maps a direct Jamf Pro REST path like "/api/v3/computers-inventory" (or with a
// trailing segment, e.g. "/api/v3/computers-inventory-detail/123") to its Platform API
// Gateway mirror, e.g. "/pro/v3/tenant/{tenantId}/computers-inventory-detail/123" —
// confirmed live 2026-07-29 this is the exact shape the Gateway expects (tenantId
// inserted immediately after the version segment). Only handles versioned REST paths
// (`/api/v{n}/...`); Classic API paths (`/JSSResource/...`) are never passed here since
// the Gateway doesn't have Classic API access at all (see the section comment above).
function toGatewayProPath(directPath: string, tenantId: string): string {
    const match = directPath.match(/^\/api(\/v\d+)(\/.*)$/);
    if (!match) {
        throw new Error(`toGatewayProPath: cannot map non-versioned-REST path "${directPath}" to the Platform API Gateway`);
    }
    return `/pro${match[1]}/tenant/${tenantId}${match[2]}`;
}

export class JamfClient {
    private client: AxiosInstance;
    // Platform API Gateway client (see platformApiBaseUrl, above) — used for bulk
    // FileVault, Compliance Benchmarks, and Blueprints. Authenticated independently of
    // `client` via ensurePlatformAuthenticated(), its own token, its own lifecycle.
    private platformClient: AxiosInstance;
    private token: string | null = null;
    private tokenExpiresAt: number = 0;
    private platformToken: string | null = null;
    private platformTokenExpiresAt: number = 0;
    private jamfUrl: string;
    private jamfClientId: string;
    private jamfClientSecret: string;
    private platformClientId: string;
    private platformClientSecret: string;
    private platformTokenUrl: string;
    private logger = createLogger('jamf-api');

    constructor() {
        this.jamfUrl = process.env.JAMF_URL ?? '';
        this.jamfClientId = process.env.JAMF_CLIENT_ID ?? '';
        this.jamfClientSecret = process.env.JAMF_CLIENT_SECRET ?? '';

        if (!this.jamfUrl || !this.jamfClientId || !this.jamfClientSecret) {
            throw new Error('JAMF_URL, JAMF_CLIENT_ID, and JAMF_CLIENT_SECRET must be set as environment variables or App Settings.');
        }

        this.client = axios.create({
            baseURL: this.jamfUrl,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
        });

        // Platform Gateway credentials are optional — only jamf_list_filevault_status,
        // the Compliance Benchmarks tools, and the Blueprints tools need them; every
        // other tool in this file works without them. Missing/empty values are caught
        // lazily in ensurePlatformAuthenticated(), not here, so a client without them
        // configured can still be constructed and used for everything else.
        this.platformClientId = process.env.JAMF_PLATFORM_CLIENT_ID ?? '';
        this.platformClientSecret = process.env.JAMF_PLATFORM_CLIENT_SECRET ?? '';
        this.platformTokenUrl = process.env.JAMF_PLATFORM_URL ?? '';

        this.platformClient = axios.create({
            baseURL: platformApiBaseUrl(),
            headers: { 'Accept': 'application/json' },
        });
    }

    private async authenticate() {
        this.logger.info("Authenticating with JAMF");
        logAuth(this.logger, 'attempt', 'jamf');
        try {
            // User specified /api/v1/oauth/token
            const apiStart = Date.now();
            const response = await axios.post(`${this.jamfUrl}/api/v1/oauth/token`,
                new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: this.jamfClientId,
                    client_secret: this.jamfClientSecret
                }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
            );

            const apiDuration = Date.now() - apiStart;
        this.logger.info("JAMF Authentication successful");
            logAuth(this.logger, 'success', 'jamf');
            logApiCall(this.logger, 'POST', '/api/v1/oauth/token', response.status, apiDuration);

            this.token = response.data.access_token;
            // Set expiration time (subtracting a small buffer like 60 seconds)
            this.tokenExpiresAt = Date.now() + (response.data.expires_in * 1000) - 60000;

            this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
        } catch (error) {
            this.logger.error("Failed to authenticate with JAMF", { error: (error as Error).message });
            logAuth(this.logger, 'failure', 'jamf', error as Error);
            throw error;
        }
    }

    private async ensureAuthenticated() {
        if (!this.token || Date.now() >= this.tokenExpiresAt) {
            await this.authenticate();
        }
    }

    // Separate OAuth2 client-credentials flow for the Platform API Gateway — confirmed
    // live 2026-07-29 that this is a genuinely distinct token exchange from the tenant's
    // own /api/v1/oauth/token above (this Gateway rejects that token, and this token
    // isn't valid against the tenant's own Jamf Pro API either). Token TTL was 900s (15
    // min) on a live response — shorter than the tenant token's — so this uses the same
    // 60s-buffer lazy-refresh pattern as ensureAuthenticated() but on its own schedule.
    private async ensurePlatformAuthenticated() {
        if (!this.platformClientId || !this.platformClientSecret || !this.platformTokenUrl) {
            throw new Error(
                "JAMF_PLATFORM_CLIENT_ID, JAMF_PLATFORM_CLIENT_SECRET, and JAMF_PLATFORM_URL must all be set " +
                "to use Platform API Gateway tools (bulk FileVault, Compliance Benchmarks, Blueprints) — these " +
                "come from a separate account.jamf.com Integration credential, not the tenant's own " +
                "JAMF_CLIENT_ID/JAMF_CLIENT_SECRET."
            );
        }
        if (this.platformToken && Date.now() < this.platformTokenExpiresAt) return;

        this.logger.info("Authenticating with Jamf Platform API Gateway");
        try {
            const apiStart = Date.now();
            const response = await axios.post(this.platformTokenUrl,
                new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: this.platformClientId,
                    client_secret: this.platformClientSecret
                }), {
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
                }
            );
            logApiCall(this.logger, 'POST', this.platformTokenUrl, response.status, Date.now() - apiStart);
            this.platformToken = response.data.access_token;
            this.platformTokenExpiresAt = Date.now() + (response.data.expires_in * 1000) - 60000;
            this.platformClient.defaults.headers.common['Authorization'] = `Bearer ${this.platformToken}`;
            this.logger.info("Jamf Platform API Gateway authentication successful");
        } catch (error) {
            this.logger.error("Failed to authenticate with Jamf Platform API Gateway", { error: (error as Error).message });
            throw error;
        }
    }

    // Reads JAMF_PLATFORM_TENANT_ID — the Platform API Gateway's tenant UUID, distinct
    // from JAMF_URL/this tenant's own Jamf Pro instance.
    private getPlatformTenantId(): string {
        const tenantId = process.env.JAMF_PLATFORM_TENANT_ID;
        if (!tenantId) {
            throw new Error(
                "JAMF_PLATFORM_TENANT_ID is not set. Platform API Gateway tools need this tenant UUID " +
                "(distinct from JAMF_URL/this tenant's Jamf Pro instance) — see the Platform API Gateway " +
                "section of src/jamf/jamf-api.ts for details."
            );
        }
        return tenantId;
    }

    // Whether all four Platform API Gateway env vars are configured — used by restGet(),
    // below, to decide per-call whether the Gateway is even an option, rather than a
    // try-then-catch-and-retry pattern that would silently mask a genuinely broken Gateway
    // credential as "just fall back."
    private hasPlatformGateway(): boolean {
        return !!(this.platformClientId && this.platformClientSecret && this.platformTokenUrl && process.env.JAMF_PLATFORM_TENANT_ID);
    }

    // Shared entry point for every non-Classic REST GET in this file (see the Platform
    // API Gateway section comment near the top of this file for what's confirmed to work
    // through it). Routes through the Gateway when JAMF_PLATFORM_* is configured, else
    // uses the direct client — a static per-call decision based on config presence, not a
    // silent runtime fallback-on-error, so a genuinely broken Gateway credential still
    // surfaces as a real error instead of being masked.
    private async restGet(directPath: string, config?: { params?: Record<string, any> }) {
        if (this.hasPlatformGateway()) {
            await this.ensurePlatformAuthenticated();
            const tenantId = this.getPlatformTenantId();
            const gatewayPath = toGatewayProPath(directPath, tenantId);
            return this.platformClient.get(gatewayPath, config);
        }
        return this.client.get(directPath, config);
    }

    public async getComputerByName(name: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computer by name', { computerName: name });
        try {
            // First, get the computer's ID using the computers-inventory endpoint
            const apiStart = Date.now();
            const inventoryResponse = await this.restGet('/api/v3/computers-inventory', {
                params: {
                    filter: `general.name=="${escapeRsqlValue(name)}"`,
                    'page-size': 1
                }
            });
            
            let apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', inventoryResponse.status, apiDuration);

            const computerId = inventoryResponse.data.results?.[0]?.id;

            if (!computerId) {
                this.logger.warn('Computer not found', { computerName: name });
                return {
                    totalCount: 0,
                    results: []
                }; // Computer not found
            }

            // Now, use the ID to get detailed information from computers-inventory-detail
            const apiStart2 = Date.now();
            const detailResponse = await this.restGet(`/api/v3/computers-inventory-detail/${computerId}`);
            apiDuration = Date.now() - apiStart2;
            logApiCall(this.logger, 'GET', `/api/v3/computers-inventory-detail/${computerId}`, detailResponse.status, apiDuration);
            
            this.logger.info('Computer details retrieved successfully', { computerName: name, computerId });
            // The detail endpoint usually returns the object directly, not wrapped in results.
            // We need to wrap it to match the expected tool output schema.
            return {
                totalCount: 1,
                results: [detailResponse.data]
            };

        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching computer', { computerName: name });
                logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
                // Adjust error message for detail endpoint if necessary, or keep general
                throw new Error(`Permission denied (403). The API client may be missing necessary 'Read' permissions for 'Computer Inventory' and 'Computer Inventory Details' in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computer ${name}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getMobileDeviceByName(name: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching mobile device by name', { deviceName: name });
        try {
            // v2's filter param is confirmed (live) to be a silent no-op, so find the matching
            // device from the list endpoint first, then fetch its /detail record below — the list
            // endpoint alone lacks osVersion, managed/supervised, and assigned-user fields.
            const apiStart = Date.now();
            const response = await this.restGet('/api/v2/mobile-devices', {
                params: {
                    'page-size': 1000 // Ensure we get enough devices to find the one we need
                }
            });

            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', response.status, apiDuration);

            // Manual filtering since v2 doesn't support server-side filtering for name
            const allDevices = response.data.results || [];
            const foundDevice = allDevices.find((device: any) => device.name === name);

            if (!foundDevice) {
                this.logger.warn('Mobile device not found', { deviceName: name });
                return {
                    totalCount: 0,
                    results: []
                };
            }

            const detailStart = Date.now();
            const detailResponse = await this.restGet(`/api/v2/mobile-devices/${foundDevice.id}/detail`);
            logApiCall(this.logger, 'GET', `/api/v2/mobile-devices/${foundDevice.id}/detail`, detailResponse.status, Date.now() - detailStart);

            // Model/modelIdentifier/supervised live under a type-specific section (ios/tvos/watchos/
            // visionos) in the detail response, not at the top level — flatten them out here so
            // callers get a consistent shape regardless of device type.
            const detail = detailResponse.data;
            const typeSection = detail.ios ?? detail.tvos ?? detail.watchos ?? detail.visionos ?? {};

            this.logger.info('Mobile device found', { deviceName: name, deviceId: foundDevice.id });
            return {
                totalCount: 1,
                results: [{
                    ...detail,
                    model: typeSection.model ?? foundDevice.model,
                    modelIdentifier: typeSection.modelIdentifier ?? foundDevice.modelIdentifier,
                    supervised: typeSection.supervised ?? null,
                    osType: detail.type,
                    locationInformation: detail.location
                }]
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching mobile device', { deviceName: name });
                logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Mobile Devices' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching mobile device ${name}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * List mobile devices tenant-wide, optionally filtered by type, managed state, or supervised
     * state. Merges two sources because neither alone has the fields needed for an accurate fleet
     * breakdown: v2 /mobile-devices carries `type`/`model` but not `managed`/`supervised`, while the
     * Classic API carries `managed`/`supervised` but not `type`. Paginates the v2 side (up to a
     * safety cap) so counts reflect the whole fleet rather than a single page.
     */
    public async listMobileDevices(options?: { type?: string; managed?: boolean; supervised?: boolean }) {
        await this.ensureAuthenticated();
        this.logger.info('Listing mobile devices', options ?? {});

        const MAX_PAGES = 20; // 20 * 1000 = 20k devices — far above any real fleet size here
        const PAGE_SIZE = 1000;

        try {
            const v2Devices: any[] = [];
            let page = 0;
            let totalCount = 0;
            let truncated = false;

            while (page < MAX_PAGES) {
                const apiStart = Date.now();
                const response = await this.restGet('/api/v2/mobile-devices', {
                    params: { page, 'page-size': PAGE_SIZE }
                });
                logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', response.status, Date.now() - apiStart);

                const pageResults: any[] = response.data.results || [];
                totalCount = response.data.totalCount ?? totalCount;
                v2Devices.push(...pageResults);

                if (pageResults.length === 0 || v2Devices.length >= totalCount) break;
                page++;
                if (page >= MAX_PAGES) {
                    truncated = true;
                    this.logger.warn('listMobileDevices hit the pagination safety cap; results are truncated', {
                        pagesFetched: page,
                        deviceCount: v2Devices.length,
                        totalCount
                    });
                }
            }

            // Classic API returns managed/supervised in one shot (no pagination controls on this
            // endpoint) — merged in by id to fill the gap in v2's field set.
            const classicStart = Date.now();
            const classicResponse = await this.client.get('/JSSResource/mobiledevices', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/mobiledevices', classicResponse.status, Date.now() - classicStart);
            const classicDevices: any[] = classicResponse.data.mobile_devices || [];
            const classicById = new Map(classicDevices.map((d: any) => [String(d.id), d]));

            let devices = v2Devices.map((d: any) => {
                const classic = classicById.get(String(d.id));
                return {
                    id: d.id,
                    name: d.name,
                    model: d.model,
                    modelIdentifier: d.modelIdentifier,
                    serialNumber: d.serialNumber,
                    udid: d.udid,
                    type: d.type,
                    username: d.username || classic?.username || null,
                    managed: classic?.managed ?? null,
                    supervised: classic?.supervised ?? null
                };
            });

            if (options?.type) {
                const typeLower = options.type.toLowerCase();
                devices = devices.filter((d) => String(d.type ?? '').toLowerCase() === typeLower);
            }
            if (options?.managed !== undefined) {
                devices = devices.filter((d) => d.managed === options.managed);
            }
            if (options?.supervised !== undefined) {
                devices = devices.filter((d) => d.supervised === options.supervised);
            }

            this.logger.info('Mobile devices listed', { count: devices.length, rawTotalCount: totalCount, truncated });
            return { devices, totalCount: devices.length, rawTotalCount: totalCount, truncated };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied listing mobile devices');
                logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Mobile Devices' permissions in JAMF Pro.`);
            }
            this.logger.error('Error listing mobile devices', { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v2/mobile-devices', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getSmartComputerGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart computer groups');
        const PAGE_SIZE = 200;
        const MAX_PAGES = 20; // 20 * 200 = 4k groups — far above any real tenant size here
        try {
            const results: any[] = [];
            let page = 0;
            let totalCount = 0;
            while (page < MAX_PAGES) {
                const apiStart = Date.now();
                const response = await this.restGet('/api/v2/computer-groups/smart-groups', {
                    params: { page, 'page-size': PAGE_SIZE }
                });
                logApiCall(this.logger, 'GET', '/api/v2/computer-groups/smart-groups', response.status, Date.now() - apiStart);
                const pageResults: any[] = response.data.results ?? [];
                totalCount = response.data.totalCount ?? totalCount;
                results.push(...pageResults);
                // Confirmed live: this endpoint's default page returns only the first
                // page-size worth of groups with no indication more exist unless you
                // check totalCount — a tenant with >100 smart groups silently truncated
                // name-based lookups (e.g. resolveComputerGroupIdByName) before this fix.
                if (pageResults.length === 0 || results.length >= totalCount) break;
                page++;
            }
            this.logger.info('Smart computer groups retrieved successfully', { count: results.length, totalCount });
            return { totalCount, results };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching smart computer groups');
                logApiCall(this.logger, 'GET', '/api/v2/computer-groups/smart-groups', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching smart computer groups", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v2/computer-groups/smart-groups', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getSmartMobileDeviceGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart mobile device groups');
        try {
            // Using Jamf Pro API v1
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/mobile-device-groups/smart-groups');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/mobile-device-groups/smart-groups', response.status, apiDuration);
            this.logger.info('Smart mobile device groups retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching smart mobile device groups');
                logApiCall(this.logger, 'GET', '/api/v1/mobile-device-groups/smart-groups', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Mobile Device Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching smart mobile device groups", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/mobile-device-groups/smart-groups', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getSmartComputerGroupMembers(groupId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart computer group members', { groupId });
        try {
            // Using Jamf Pro API v2 to get member IDs
            const apiStart = Date.now();
            const response = await this.restGet(`/api/v2/computer-groups/smart-group-membership/${groupId}`);
            let apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', `/api/v2/computer-groups/smart-group-membership/${groupId}`, response.status, apiDuration);
            
            const memberIds = response.data.members || [];

            // Fetch computer details for each member to get hostname
            const membersWithNames = await Promise.all(
                memberIds.map(async (id: number) => {
                    try {
                        const apiStart2 = Date.now();
                        const computerResponse = await this.restGet(`/api/v3/computers-inventory/${id}`, {
                            params: { section: 'GENERAL' }
                        });
                        apiDuration = Date.now() - apiStart2;
                        logApiCall(this.logger, 'GET', `/api/v3/computers-inventory/${id}`, computerResponse.status, apiDuration);
                        return {
                            id: id,
                            name: computerResponse.data.general?.name || 'Unknown'
                        };
                    } catch (error) {
                        this.logger.error(`Error fetching details for computer ID ${id}`, { error: (error as Error).message });
                        logApiCall(this.logger, 'GET', `/api/v3/computers-inventory/${id}`, undefined, undefined, error as Error);
                        return {
                            id: id,
                            name: 'Error fetching name'
                        };
                    }
                })
            );

            this.logger.info('Smart computer group members retrieved successfully', { groupId, memberCount: membersWithNames.length });
            return {
                totalCount: membersWithNames.length,
                members: membersWithNames
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching smart computer group members', { groupId });
                logApiCall(this.logger, 'GET', `/api/v2/computer-groups/smart-group-membership/${groupId}`, undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Computer Groups' and/or 'Read Computers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                this.logger.warn('Smart computer group not found', { groupId });
                throw new Error(`Smart Computer Group with ID ${groupId} not found.`);
            }
            this.logger.error(`Error fetching smart computer group members for group ${groupId}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', `/api/v2/computer-groups/smart-group-membership/${groupId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getComputersByAssetTag(assetTag?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computers', { assetTag: assetTag === undefined ? '(all)' : assetTag || '(no tag)', page: page ?? 0, pageSize: pageSize ?? 200 });
        try {
            const params: Record<string, any> = {
                section: ['GENERAL', 'OPERATING_SYSTEM', 'HARDWARE'],
                page: page ?? 0,
                'page-size': pageSize ?? 200,
            };

            // Only apply a filter when the caller explicitly passes an assetTag value.
            // undefined  → no filter → return ALL computers
            // ""         → filter for computers with no asset tag
            // "ABC123"   → filter for that specific tag
            if (assetTag !== undefined) {
                params.filter = `general.assetTag=="${escapeRsqlValue(assetTag)}"`;
            }

            const apiStart = Date.now();
            const response = await this.restGet('/api/v3/computers-inventory', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', response.status, apiDuration);

            const results = response.data.results || [];
            const computers = results.map((computer: any) => ({
                id: computer.id,
                name: computer.general?.name || 'Unknown',
                serialNumber: computer.hardware?.serialNumber || '',
                model: computer.hardware?.model || '',
                assetTag: computer.general?.assetTag || '',
                lastContactTime: computer.general?.lastContactTime || '',
                lastIpAddress: computer.general?.lastIpAddress || '',
                osName: computer.operatingSystem?.name || '',
                osVersion: computer.operatingSystem?.version || '',
            }));

            this.logger.info('Computers retrieved successfully', { count: computers.length, totalCount: response.data.totalCount });
            return {
                totalCount: response.data.totalCount ?? computers.length,
                results: computers
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching computers', { assetTag });
                logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computers`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getComputersByUserIdentifier(userIdentifier: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computers by user identifier', { userIdentifier });

        const identifier = userIdentifier.trim();
        if (!identifier) {
            this.logger.error('User identifier is empty');
            throw new Error("User identifier must not be empty.");
        }

        const escapedIdentifier = escapeRsqlValue(identifier);

        const fetchByFilter = async (filter: string) => {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/computers-inventory', {
                params: {
                    filter,
                    'page-size': 1000,
                    section: ['GENERAL', 'USER_AND_LOCATION']
                }
            });
            
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/computers-inventory', response.status, apiDuration);

            const results = response.data.results || [];
            return results.map((computer: any) => ({
                id: computer.id,
                name: computer.general?.name || 'Unknown',
                userName: computer.userAndLocation?.username || '',
                realName: computer.userAndLocation?.realname || '',
                email: computer.userAndLocation?.email || '',
                department: computer.userAndLocation?.department || '',
                building: computer.userAndLocation?.building || '',
                lastContactTime: computer.general?.lastContactTime || ''
            }));
        };

        try {
            const filters = [];

            if (identifier.includes('@')) {
                filters.push(`userAndLocation.email=="${escapedIdentifier}"`);
            }

            filters.push(`userAndLocation.username=="${escapedIdentifier}"`);
            filters.push(`userAndLocation.realname=="${escapedIdentifier}"`);

            const resultsByFilter = await Promise.all(filters.map((filter) => fetchByFilter(filter)));

            const uniqueResults = new Map<number, any>();
            resultsByFilter.flat().forEach((computer) => {
                uniqueResults.set(computer.id, computer);
            });

            const results = Array.from(uniqueResults.values());

            this.logger.info('Computers by user identifier retrieved successfully', { userIdentifier, count: results.length });
            return {
                totalCount: results.length,
                results
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching computers by user identifier', { userIdentifier });
                logApiCall(this.logger, 'GET', '/api/v1/computers-inventory', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computers by user identifier ${identifier}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/computers-inventory', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getSites() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF sites');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/sites');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/sites', response.status, apiDuration);
            this.logger.info('Sites retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching sites');
                logApiCall(this.logger, 'GET', '/api/v1/sites', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Sites' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching sites", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/sites', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getScripts(name?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF scripts', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100 });
        try {
            if (name) {
                // Same fix as getPackages: the API has no server-side name filter, so
                // filtering only the caller's requested page silently missed matches
                // sitting on other pages. Page through the whole catalog first, then
                // filter, then paginate the filtered set.
                const FETCH_PAGE_SIZE = 200;
                const MAX_PAGES = 20; // 20 * 200 = 4k scripts — far above any real tenant size here
                const all: any[] = [];
                let fetchPage = 0;
                let totalCount = 0;
                while (fetchPage < MAX_PAGES) {
                    const apiStart = Date.now();
                    const response = await this.restGet('/api/v1/scripts', {
                        params: { page: fetchPage, 'page-size': FETCH_PAGE_SIZE }
                    });
                    logApiCall(this.logger, 'GET', '/api/v1/scripts', response.status, Date.now() - apiStart);
                    const pageResults: any[] = response.data.results ?? [];
                    totalCount = response.data.totalCount ?? totalCount;
                    all.push(...pageResults);
                    if (pageResults.length === 0 || all.length >= totalCount) break;
                    fetchPage++;
                }
                const nameLower = name.toLowerCase();
                const filtered = all.filter((script: any) =>
                    script.name && script.name.toLowerCase().includes(nameLower)
                );
                const start = (page || 0) * (pageSize || 100);
                const paged = filtered.slice(start, start + (pageSize || 100));
                this.logger.info('Scripts retrieved successfully', { name, page: page || 0, pageSize: pageSize || 100, filteredCount: filtered.length });
                return { totalCount: filtered.length, results: paged };
            }

            const params: any = {
                page: page || 0,
                'page-size': pageSize || 100
            };
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/scripts', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/scripts', response.status, apiDuration);
            this.logger.info('Scripts retrieved successfully', { name: '(all)', page: page || 0, pageSize: pageSize || 100, totalInPage: response.data.results?.length || 0 });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 403) {
                    this.logger.error('Permission denied fetching scripts');
                    logApiCall(this.logger, 'GET', '/api/v1/scripts', undefined, undefined, error as Error);
                    throw new Error(`Permission denied (403). The API client may be missing 'Read Scripts' permissions in JAMF Pro.`);
                }
                if (error.response?.status === 400) {
                    this.logger.error('Bad request fetching scripts', { status: error.response.status, data: error.response.data, config: { url: error.config?.url, params: error.config?.params } });
                    logApiCall(this.logger, 'GET', '/api/v1/scripts', undefined, undefined, error as Error);
                    throw new Error(`Bad request (400). ${error.response.data?.message || 'Invalid filter or parameter format'}`);
                }
            }
            this.logger.error("Error fetching scripts", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/scripts', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getPackages(name?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF packages', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100 });
        try {
            if (name) {
                // The API has no server-side name filter, and filtering only the caller's
                // requested page silently missed matches sitting elsewhere in the full
                // catalog — confirmed live: with the default page-size (100), a 110th
                // package was invisible to every name search regardless of substring.
                // Page through the whole catalog first (same fix already applied to
                // getSmartComputerGroups), then filter, then paginate the filtered set.
                const FETCH_PAGE_SIZE = 200;
                const MAX_PAGES = 20; // 20 * 200 = 4k packages — far above any real tenant size here
                const all: any[] = [];
                let fetchPage = 0;
                let totalCount = 0;
                while (fetchPage < MAX_PAGES) {
                    const apiStart = Date.now();
                    const response = await this.restGet('/api/v1/packages', {
                        params: { page: fetchPage, 'page-size': FETCH_PAGE_SIZE }
                    });
                    logApiCall(this.logger, 'GET', '/api/v1/packages', response.status, Date.now() - apiStart);
                    const pageResults: any[] = response.data.results ?? [];
                    totalCount = response.data.totalCount ?? totalCount;
                    all.push(...pageResults);
                    if (pageResults.length === 0 || all.length >= totalCount) break;
                    fetchPage++;
                }
                const nameLower = name.toLowerCase();
                const filtered = all.filter((pkg: any) =>
                    pkg.packageName && pkg.packageName.toLowerCase().includes(nameLower)
                );
                const start = (page || 0) * (pageSize || 100);
                const paged = filtered.slice(start, start + (pageSize || 100));
                this.logger.info('Packages retrieved successfully', { name, page: page || 0, pageSize: pageSize || 100, filteredCount: filtered.length });
                return { totalCount: filtered.length, results: paged };
            }

            const params: any = {
                page: page || 0,
                'page-size': pageSize || 100
            };
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/packages', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/packages', response.status, apiDuration);
            this.logger.info('Packages retrieved successfully', { name: '(all)', page: page || 0, pageSize: pageSize || 100, totalInPage: response.data.results?.length || 0 });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 403) {
                    this.logger.error('Permission denied fetching packages');
                    logApiCall(this.logger, 'GET', '/api/v1/packages', undefined, undefined, error as Error);
                    throw new Error(`Permission denied (403). The API client may be missing 'Read Packages' permissions in JAMF Pro.`);
                }
                if (error.response?.status === 400) {
                    this.logger.error('Bad request fetching packages', { status: error.response.status, data: error.response.data, config: { url: error.config?.url, params: error.config?.params } });
                    logApiCall(this.logger, 'GET', '/api/v1/packages', undefined, undefined, error as Error);
                    throw new Error(`Bad request (400). ${error.response.data?.message || 'Invalid filter or parameter format'}`);
                }
            }
            this.logger.error("Error fetching packages", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/packages', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getScriptById(id: string) {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.restGet(`/api/v1/scripts/${id}`);
            logApiCall(this.logger, 'GET', `/api/v1/scripts/${id}`, response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Scripts' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Script with ID ${id} not found.`);
            }
            this.logger.error('Error fetching script by id', { id, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/api/v1/scripts/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Read a script's full record (including scriptContents) by name or numeric ID —
    // jamf_create_script is upsert-by-name and will happily overwrite an existing
    // script's body, but until now there was no way to see what a script currently
    // contains before changing it. Reuses getScriptById/findScriptByName rather than
    // adding new API surface, mirroring the list-vs-get split jamf_get_smart_group
    // already established for smart groups.
    public async getScript(nameOrId: string): Promise<any> {
        await this.ensureAuthenticated();
        if (/^\d+$/.test(nameOrId)) {
            return this.getScriptById(nameOrId);
        }
        const found = await this.findScriptByName(nameOrId);
        if (!found) {
            throw new Error(`Script not found: "${nameOrId}"`);
        }
        return found;
    }

    private async findScriptByName(name: string): Promise<any | null> {
        const data = await this.getScripts(name, 0, 200);
        const scripts: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        const match = scripts.find((s) => s.name?.toLowerCase() === lower);
        if (!match) return null;
        // The list endpoint's items already include the full record (confirmed live),
        // but re-fetch by id for a stable, single source of truth to merge updates into.
        return this.getScriptById(String(match.id));
    }

    private async createScript(fields: Record<string, any>): Promise<string> {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.post('/api/v1/scripts', fields);
            logApiCall(this.logger, 'POST', '/api/v1/scripts', response.status, Date.now() - apiStart);
            return String(response.data.id);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create Scripts' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating script', { error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/api/v1/scripts', undefined, undefined, error as Error);
            throw error;
        }
    }

    private async updateScriptById(id: string, fields: Record<string, any>, existing: any): Promise<void> {
        await this.ensureAuthenticated();
        const body = { ...existing, ...fields };
        try {
            const apiStart = Date.now();
            const response = await this.client.put(`/api/v1/scripts/${id}`, body);
            logApiCall(this.logger, 'PUT', `/api/v1/scripts/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Scripts' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating script', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/api/v1/scripts/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Upsert by name: creates a new script if none exists with this name, otherwise
    // merges the given fields into the existing script and PUTs the whole thing
    // back — re-running with the same name is how a script gets updated in place
    // rather than duplicated (e.g. a yearly package's install script revision).
    public async upsertScript(fields: {
        name: string;
        scriptContents: string;
        categoryName?: string;
        info?: string;
        notes?: string;
        priority?: 'BEFORE' | 'AFTER';
        osRequirements?: string;
        parameter4?: string; parameter5?: string; parameter6?: string; parameter7?: string;
        parameter8?: string; parameter9?: string; parameter10?: string; parameter11?: string;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting script', { name: fields.name });

        const { categoryName, ...rest } = fields;
        const body: Record<string, any> = { ...rest };
        if (categoryName) body.categoryId = await this.resolveCategoryId(categoryName);

        const existing = await this.findScriptByName(fields.name);
        if (!existing) {
            const id = await this.createScript(body);
            this.logger.info('Script created', { name: fields.name, id });
            return { action: 'created' as const, id, name: fields.name };
        }
        await this.updateScriptById(String(existing.id), body, existing);
        this.logger.info('Script updated', { name: fields.name, id: existing.id });
        return { action: 'updated' as const, id: String(existing.id), name: fields.name };
    }

    private async findPackageByName(packageName: string): Promise<any | null> {
        const data = await this.getPackages(packageName, 0, 200);
        const packages: any[] = data.results ?? [];
        const lower = packageName.trim().toLowerCase();
        return packages.find((p) => p.packageName?.toLowerCase() === lower) ?? null;
    }

    // Only these fields are user-writable on POST/PUT /api/v1/packages — the read
    // response (confirmed live) also includes server-computed fields (size,
    // hashType, hashValue, md5, sha256, sha3512, cloudTransferStatus, indexed,
    // osInstallerVersion, manifest, format) that must NOT be echoed back on write.
    private pickWritablePackageFields(pkg: any): Record<string, any> {
        const keys = [
            'packageName', 'fileName', 'categoryId', 'priority', 'info', 'notes',
            'osRequirements', 'fillUserTemplate', 'fillExistingUsers', 'swu',
            'rebootRequired', 'selfHealNotify', 'selfHealingAction', 'osInstall',
            'serialNumber', 'parentPackageId', 'basePath', 'suppressUpdates',
            'ignoreConflicts', 'suppressFromDock', 'suppressEula', 'suppressRegistration',
            'installLanguage', 'manifestFileName',
        ];
        return Object.fromEntries(keys.filter((k) => pkg[k] !== undefined).map((k) => [k, pkg[k]]));
    }

    private async createPackageMetadata(fields: Record<string, any>): Promise<string> {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.post('/api/v1/packages', fields);
            logApiCall(this.logger, 'POST', '/api/v1/packages', response.status, Date.now() - apiStart);
            return String(response.data.id);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create Packages' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating package metadata', { error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/api/v1/packages', undefined, undefined, error as Error);
            throw error;
        }
    }

    private async updatePackageMetadata(id: string, fields: Record<string, any>, existing: any): Promise<void> {
        await this.ensureAuthenticated();
        const body = { ...this.pickWritablePackageFields(existing), ...fields };
        try {
            const apiStart = Date.now();
            const response = await this.client.put(`/api/v1/packages/${id}`, body);
            logApiCall(this.logger, 'PUT', `/api/v1/packages/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Packages' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating package metadata', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/api/v1/packages/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Streams the file off disk without loading it fully into memory (installers
    // can be hundreds of MB to multiple GB) using node:fs's openAsBlob, and native
    // fetch/FormData rather than axios — axios's Node adapter doesn't cleanly
    // multipart-encode a standard FormData without the extra `form-data` package,
    // which isn't a dependency here.
    private async uploadPackageFile(id: string, localFilePath: string): Promise<any> {
        await this.ensureAuthenticated();
        const { openAsBlob } = await import('node:fs');
        const path = await import('node:path');
        const fileBlob = await openAsBlob(localFilePath);
        const form = new FormData();
        form.append('file', fileBlob, path.basename(localFilePath));

        const apiStart = Date.now();
        const response = await fetch(`${this.jamfUrl}/api/v1/packages/${id}/upload`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${this.token}` },
            body: form,
        });
        logApiCall(this.logger, 'POST', `/api/v1/packages/${id}/upload`, response.status, Date.now() - apiStart);
        if (response.status === 403) {
            throw new Error(`Permission denied (403). The API client may be missing 'Create/Update Packages' permissions in JAMF Pro.`);
        }
        if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(`Package upload failed (${response.status}): ${text}`);
        }
        return response.json().catch(() => ({}));
    }

    // Same upload endpoint as uploadPackageFile, but from an in-memory Buffer —
    // for the fileContentBase64 path, where there's no on-disk file to stream.
    private async uploadPackageFileBuffer(id: string, fileBuffer: Buffer, fileName: string): Promise<any> {
        await this.ensureAuthenticated();
        const form = new FormData();
        form.append('file', new Blob([new Uint8Array(fileBuffer)]), fileName);

        const apiStart = Date.now();
        const response = await fetch(`${this.jamfUrl}/api/v1/packages/${id}/upload`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${this.token}` },
            body: form,
        });
        logApiCall(this.logger, 'POST', `/api/v1/packages/${id}/upload`, response.status, Date.now() - apiStart);
        if (response.status === 403) {
            throw new Error(`Permission denied (403). The API client may be missing 'Create/Update Packages' permissions in JAMF Pro.`);
        }
        if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(`Package upload failed (${response.status}): ${text}`);
        }
        return response.json().catch(() => ({}));
    }

    // Upsert by packageName: creates a new package object if none exists with this
    // name, otherwise updates its metadata in place — then always (re-)uploads the
    // file, so re-running against an existing name replaces both the metadata and
    // the bytes (the yearly Office/MATLAB/Adobe re-publish case).
    //
    // Accepts the file two ways — exactly one must be given:
    //  - `localFilePath`: a path inside JAMF_PACKAGE_UPLOAD_DIR on THIS SERVER's
    //    own filesystem (the original mechanism — still the only sane option for
    //    large installers, since it streams off disk without buffering).
    //  - `fileContentBase64` + `fileName`: bytes supplied directly by the MCP
    //    client, for when the file lives on the client's machine instead of the
    //    server's. Practical for the package sizes typical scripts/small
    //    installers run to; base64's ~33% size overhead plus buffering the whole
    //    decoded file in memory (no streaming path exists for this branch) makes
    //    it a poor fit for multi-GB installers — use localFilePath for those.
    public async upsertPackage(params: {
        localFilePath?: string;
        fileContentBase64?: string;
        fileName?: string;
        packageName: string;
        categoryName?: string;
        priority?: number;
        fillUserTemplate?: boolean;
        rebootRequired?: boolean;
        osInstall?: boolean;
        suppressUpdates?: boolean;
        suppressFromDock?: boolean;
        suppressEula?: boolean;
        suppressRegistration?: boolean;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting package', { packageName: params.packageName, localFilePath: params.localFilePath, viaBase64: Boolean(params.fileContentBase64) });

        if (Boolean(params.localFilePath) === Boolean(params.fileContentBase64)) {
            throw new Error("Pass exactly one of `localFilePath` (server-side path) or `fileContentBase64` (client-supplied bytes), not both/neither.");
        }

        let resolvedFilePath: string | undefined;
        let fileName: string;
        let fileBuffer: Buffer | undefined;
        const path = await import('node:path');

        if (params.localFilePath) {
            const uploadDir = process.env.JAMF_PACKAGE_UPLOAD_DIR;
            if (!uploadDir) {
                throw new Error(
                    "JAMF_PACKAGE_UPLOAD_DIR is not set — refusing to read any local file for package upload. " +
                    "Set this env var to the directory package files are staged in, or pass fileContentBase64 " +
                    "instead if the file lives on the MCP client's machine rather than this server's."
                );
            }
            const resolvedUploadDir = path.resolve(uploadDir);
            resolvedFilePath = path.resolve(params.localFilePath);
            if (resolvedFilePath !== resolvedUploadDir && !resolvedFilePath.startsWith(resolvedUploadDir + path.sep)) {
                throw new Error(
                    `Refusing to read file outside the allowed upload directory. "${params.localFilePath}" is not inside JAMF_PACKAGE_UPLOAD_DIR ("${uploadDir}").`
                );
            }

            const fsPromises = await import('node:fs/promises');
            const stat = await fsPromises.stat(resolvedFilePath).catch(() => null);
            if (!stat || !stat.isFile()) {
                throw new Error(`Local file not found or not a regular file: "${params.localFilePath}"`);
            }
            fileName = path.basename(resolvedFilePath);
        } else {
            if (!params.fileName) {
                throw new Error("`fileName` is required when uploading via fileContentBase64 (there's no local path to derive it from).");
            }
            fileName = params.fileName;
            fileBuffer = Buffer.from(params.fileContentBase64!, 'base64');
        }

        const categoryId = params.categoryName ? await this.resolveCategoryId(params.categoryName) : '-1';
        const metadata: Record<string, any> = {
            packageName: params.packageName,
            fileName,
            categoryId,
            priority: params.priority ?? 10,
            fillUserTemplate: params.fillUserTemplate ?? false,
            rebootRequired: params.rebootRequired ?? false,
            osInstall: params.osInstall ?? false,
            suppressUpdates: params.suppressUpdates ?? false,
            suppressFromDock: params.suppressFromDock ?? false,
            suppressEula: params.suppressEula ?? false,
            suppressRegistration: params.suppressRegistration ?? false,
        };

        const existing = await this.findPackageByName(params.packageName);
        let id: string;
        let action: 'created' | 'updated';
        if (!existing) {
            id = await this.createPackageMetadata(metadata);
            action = 'created';
        } else {
            id = String(existing.id);
            await this.updatePackageMetadata(id, metadata, existing);
            action = 'updated';
        }

        const uploadResult = fileBuffer
            ? await this.uploadPackageFileBuffer(id, fileBuffer, fileName)
            : await this.uploadPackageFile(id, resolvedFilePath!);
        this.logger.info('Package upserted and uploaded', { id, packageName: params.packageName, action });
        return { action, id, packageName: params.packageName, fileName, uploadResult };
    }

    // Test-hygiene only — no corresponding MCP tool. Confirmed live that the API
    // client's role has Delete Packages permission (unlike scripts/policies/smart
    // groups, where it does not), so this is the one object type in this batch that
    // a test can safely create-then-clean-up.
    public async deletePackage(id: string): Promise<void> {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.delete(`/api/v1/packages/${id}`);
            logApiCall(this.logger, 'DELETE', `/api/v1/packages/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Delete Packages' permissions in JAMF Pro.`);
            }
            this.logger.error('Error deleting package', { id, error: (error as Error).message });
            logApiCall(this.logger, 'DELETE', `/api/v1/packages/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // The list endpoint (getSmartComputerGroups, /api/v2/computer-groups/smart-groups)
    // only returns id/name/membershipCount — no criteria. This is the only way to
    // read a smart group's actual criteria/boolean logic, mirroring getPolicyDetail's
    // single-object GET against the same Classic API family.
    public async getSmartGroupDetail(groupId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart group detail', { groupId });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/JSSResource/computergroups/id/${groupId}`, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', `/JSSResource/computergroups/id/${groupId}`, response.status, Date.now() - apiStart);
            this.logger.info('Smart group detail retrieved', { groupId });
            return response.data.computer_group ?? response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Computer Groups' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Computer group with ID ${groupId} not found.`);
            }
            this.logger.error('Error fetching smart group detail', { groupId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/computergroups/id/${groupId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Only ever checks getSmartComputerGroups() (not static groups) — a match found
    // there is smart by construction, so there's no separate isSmart check needed.
    private async findComputerGroupByNameExact(name: string): Promise<any | null> {
        const smart = await this.getSmartComputerGroups();
        const smartGroups: any[] = Array.isArray(smart) ? smart : (smart as any).results ?? [];
        const lower = name.trim().toLowerCase();
        return smartGroups.find((g) => g.name?.toLowerCase() === lower) ?? null;
    }

    private async createSmartGroup(fields: Record<string, any>): Promise<string> {
        await this.ensureAuthenticated();
        try {
            const xml = buildXmlDocument('computer_group', fields);
            const apiStart = Date.now();
            const response = await this.client.post('/JSSResource/computergroups/id/0', xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'POST', '/JSSResource/computergroups/id/0', response.status, Date.now() - apiStart);
            const match = String(response.data).match(/<id>(\d+)<\/id>/);
            if (!match) throw new Error('Smart group created but no ID could be determined from the response.');
            return match[1];
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create Smart Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating smart group', { error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/computergroups/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    private async updateSmartGroupById(id: string, fields: Record<string, any>): Promise<void> {
        await this.ensureAuthenticated();
        try {
            const xml = buildXmlDocument('computer_group', fields);
            const apiStart = Date.now();
            const response = await this.client.put(`/JSSResource/computergroups/id/${id}`, xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'PUT', `/JSSResource/computergroups/id/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Smart Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating smart group', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/JSSResource/computergroups/id/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Upsert by name: two-criterion "Application Title is X AND Application
    // Version is Y" smart group — the common "detection" pattern. Re-running for a
    // version bump (e.g. MATLAB 2025b -> 2026a) updates the existing group's
    // criteria in place rather than creating a duplicate.
    public async upsertApplicationSmartGroup(params: {
        name: string;
        applicationTitle: string;
        applicationVersion: string;
        siteId?: string;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting application smart group', { name: params.name });

        const criteria = [
            { name: 'Application Title', priority: 0, and_or: 'and', search_type: 'is', value: params.applicationTitle, opening_paren: false, closing_paren: false },
            { name: 'Application Version', priority: 1, and_or: 'and', search_type: 'is', value: params.applicationVersion, opening_paren: false, closing_paren: false },
        ];
        const fields: Record<string, any> = { name: params.name, is_smart: true, criteria };
        if (params.siteId) fields.site = { id: params.siteId };

        const existing = await this.findComputerGroupByNameExact(params.name);
        if (!existing) {
            const id = await this.createSmartGroup(fields);
            this.logger.info('Smart group created', { name: params.name, id });
            return { action: 'created' as const, id, name: params.name };
        }
        await this.updateSmartGroupById(String(existing.id), fields);
        this.logger.info('Smart group updated', { name: params.name, id: existing.id });
        return { action: 'updated' as const, id: String(existing.id), name: params.name };
    }

    // Upsert by name with an arbitrary criteria list — the generic sibling of
    // upsertApplicationSmartGroup (which is just this with a hardcoded 2-criterion
    // app-detection shape). Lets a caller build any smart group Jamf's Classic API
    // supports: extension attributes, Directory Service Group, Department, Last
    // Check-in, hardware fields, etc. Reuses the same createSmartGroup/
    // updateSmartGroupById/findComputerGroupByNameExact plumbing.
    public async upsertSmartGroup(params: {
        name: string;
        criteria: {
            name: string;
            priority?: number;
            and_or?: 'and' | 'or';
            search_type: string;
            value: string;
            opening_paren?: boolean;
            closing_paren?: boolean;
        }[];
        siteId?: string;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting smart group', { name: params.name, criteriaCount: params.criteria.length });

        const criteria = params.criteria.map((c, i) => ({
            name: c.name,
            priority: c.priority ?? i,
            and_or: c.and_or ?? 'and',
            search_type: c.search_type,
            value: c.value,
            opening_paren: c.opening_paren ?? false,
            closing_paren: c.closing_paren ?? false,
        }));
        const fields: Record<string, any> = { name: params.name, is_smart: true, criteria };
        if (params.siteId) fields.site = { id: params.siteId };

        const existing = await this.findComputerGroupByNameExact(params.name);
        if (!existing) {
            const id = await this.createSmartGroup(fields);
            this.logger.info('Smart group created', { name: params.name, id });
            return { action: 'created' as const, id, name: params.name };
        }
        await this.updateSmartGroupById(String(existing.id), fields);
        this.logger.info('Smart group updated', { name: params.name, id: existing.id });
        return { action: 'updated' as const, id: String(existing.id), name: params.name };
    }

    // No modern (v1/v2) Jamf Pro API surface exists for user groups — confirmed
    // against current developer.jamf.com docs: the only CRUD is Classic API
    // (/JSSResource/usergroups), same family as policies and computer groups
    // elsewhere in this file. The one modern-API endpoint that touches user groups
    // (POST /v1/smart-user-groups/{id}/recalculate) is a narrow recalculate-and-list
    // action, not a CRUD resource, so it isn't a substitute for list/get/create here.
    public async getUserGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching user groups');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/JSSResource/usergroups', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/usergroups', response.status, Date.now() - apiStart);
            const results: any[] = response.data.user_groups ?? [];
            this.logger.info('User groups retrieved', { count: results.length });
            return { totalCount: results.length, results };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read User Groups' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching user groups', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/JSSResource/usergroups', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getUserGroupDetail(groupId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching user group detail', { groupId });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/JSSResource/usergroups/id/${groupId}`, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', `/JSSResource/usergroups/id/${groupId}`, response.status, Date.now() - apiStart);
            return response.data.user_group ?? response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read User Groups' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`User group with ID ${groupId} not found.`);
            }
            this.logger.error('Error fetching user group detail', { groupId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/usergroups/id/${groupId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    private async findUserGroupByName(name: string): Promise<any | null> {
        const data = await this.getUserGroups();
        const lower = name.trim().toLowerCase();
        return data.results.find((g: any) => g.name?.toLowerCase() === lower) ?? null;
    }

    // Jamf User objects (not directory accounts — see the separate, unimplemented
    // directory-search/import gap) already exist as a plain Classic API resource;
    // this only resolves an existing one's ID for static user group membership, it
    // does not create/import anyone.
    private async resolveJamfUserIdByUsername(username: string): Promise<{ id: string; name: string } | null> {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/JSSResource/users/name/${encodeURIComponent(username)}`, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', `/JSSResource/users/name/${username}`, response.status, Date.now() - apiStart);
            const user = response.data.user ?? response.data;
            return { id: String(user.id), name: user.name };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 404) return null;
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Users' permissions in JAMF Pro.`);
            }
            throw error;
        }
    }

    private async createUserGroup(fields: Record<string, any>): Promise<string> {
        await this.ensureAuthenticated();
        try {
            const xml = buildXmlDocument('user_group', fields);
            const apiStart = Date.now();
            const response = await this.client.post('/JSSResource/usergroups/id/0', xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'POST', '/JSSResource/usergroups/id/0', response.status, Date.now() - apiStart);
            const match = String(response.data).match(/<id>(\d+)<\/id>/);
            if (!match) throw new Error('User group created but no ID could be determined from the response.');
            return match[1];
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create User Groups' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating user group', { error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/usergroups/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    private async updateUserGroupById(id: string, fields: Record<string, any>): Promise<void> {
        await this.ensureAuthenticated();
        try {
            const xml = buildXmlDocument('user_group', fields);
            const apiStart = Date.now();
            const response = await this.client.put(`/JSSResource/usergroups/id/${id}`, xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'PUT', `/JSSResource/usergroups/id/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update User Groups' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating user group', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/JSSResource/usergroups/id/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Upsert by name for either a smart user group (criteria-driven, e.g. "Directory
    // Service Group like X") or a static one (explicit member list by username) —
    // exactly one of `criteria`/`memberUsernames` should be passed; which one
    // determines is_smart. Mirrors upsertSmartGroup's computer-group shape and
    // create-vs-update branching.
    public async upsertUserGroup(params: {
        name: string;
        criteria?: {
            name: string;
            priority?: number;
            and_or?: 'and' | 'or';
            search_type: string;
            value: string;
            opening_paren?: boolean;
            closing_paren?: boolean;
        }[];
        memberUsernames?: string[];
        siteId?: string;
    }) {
        await this.ensureAuthenticated();
        const isSmart = Boolean(params.criteria?.length);
        if (isSmart === Boolean(params.memberUsernames?.length)) {
            throw new Error("Pass exactly one of `criteria` (smart group) or `memberUsernames` (static group), not both/neither.");
        }
        this.logger.info('Upserting user group', { name: params.name, isSmart });

        const fields: Record<string, any> = { name: params.name, is_smart: isSmart };
        if (params.siteId) fields.site = { id: params.siteId };

        if (isSmart) {
            fields.criteria = params.criteria!.map((c, i) => ({
                name: c.name,
                priority: c.priority ?? i,
                and_or: c.and_or ?? 'and',
                search_type: c.search_type,
                value: c.value,
                opening_paren: c.opening_paren ?? false,
                closing_paren: c.closing_paren ?? false,
            }));
        } else {
            const resolved = await Promise.all((params.memberUsernames ?? []).map(async (username) => {
                const found = await this.resolveJamfUserIdByUsername(username);
                if (!found) throw new Error(`Jamf User not found: "${username}" — import/create the user in JAMF Pro first.`);
                return found;
            }));
            fields.users = resolved.map((u) => ({ id: u.id, name: u.name }));
        }

        const existing = await this.findUserGroupByName(params.name);
        if (!existing) {
            const id = await this.createUserGroup(fields);
            this.logger.info('User group created', { name: params.name, id });
            return { action: 'created' as const, id, name: params.name, isSmart };
        }
        await this.updateUserGroupById(String(existing.id), fields);
        this.logger.info('User group updated', { name: params.name, id: existing.id });
        return { action: 'updated' as const, id: String(existing.id), name: params.name, isSmart };
    }

    public async getInventoryPreload(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching inventory preload records', { page, pageSize });
        try {
            const params: any = {};
            if (page !== undefined) params.page = page;
            if (pageSize !== undefined) params['page-size'] = pageSize;

            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/inventory-preload', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/inventory-preload', response.status, apiDuration);
            this.logger.info('Inventory preload records retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching inventory preload records');
                logApiCall(this.logger, 'GET', '/api/v1/inventory-preload', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Inventory Preload Records' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching inventory preload records", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/inventory-preload', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Inventory Preload has no serial-number filter query param (confirmed against
    // the live API — passing filter= is silently ignored), so finding an existing
    // record means paging through the full set client-side.
    private async findInventoryPreloadRecordBySerial(serialNumber: string): Promise<any | null> {
        const target = serialNumber.trim().toUpperCase();
        const pageSize = 200;
        let page = 0;
        while (true) {
            const data = await this.getInventoryPreload(page, pageSize);
            const results: any[] = data.results ?? [];
            const match = results.find((r) => r.serialNumber?.toUpperCase() === target);
            if (match) return match;
            const totalCount = data.totalCount ?? 0;
            if ((page + 1) * pageSize >= totalCount || results.length === 0) return null;
            page++;
        }
    }

    public async createInventoryPreloadRecord(record: {
        serialNumber: string;
        assetTag?: string;
        building?: string;
        room?: string;
        username?: string;
        fullName?: string;
        emailAddress?: string;
        deviceType?: string;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Creating inventory preload record', { serialNumber: record.serialNumber });
        try {
            const body = {
                serialNumber: record.serialNumber,
                assetTag: record.assetTag ?? '',
                building: record.building ?? '',
                room: record.room ?? '',
                username: record.username ?? '',
                fullName: record.fullName ?? '',
                emailAddress: record.emailAddress ?? '',
                deviceType: record.deviceType ?? 'Computer',
            };
            const apiStart = Date.now();
            const response = await this.client.post('/api/v1/inventory-preload', body);
            logApiCall(this.logger, 'POST', '/api/v1/inventory-preload', response.status, Date.now() - apiStart);
            this.logger.info('Inventory preload record created', { serialNumber: record.serialNumber });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create Inventory Preload Records' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating inventory preload record', { serialNumber: record.serialNumber, error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/api/v1/inventory-preload', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async updateInventoryPreloadRecordById(id: string, updates: {
        assetTag?: string;
        building?: string;
        room?: string;
        username?: string;
        fullName?: string;
        emailAddress?: string;
    }, existing: any) {
        await this.ensureAuthenticated();
        this.logger.info('Updating inventory preload record', { id });
        try {
            const body = { ...existing, ...updates };
            const apiStart = Date.now();
            const response = await this.client.put(`/api/v1/inventory-preload/${id}`, body);
            logApiCall(this.logger, 'PUT', `/api/v1/inventory-preload/${id}`, response.status, Date.now() - apiStart);
            this.logger.info('Inventory preload record updated', { id });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Inventory Preload Records' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating inventory preload record', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/api/v1/inventory-preload/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Upsert by serial: creates a new record if none exists for this serial,
    // otherwise merges the given fields into the existing record and PUTs the
    // whole thing back (Jamf's PUT here replaces the record, not a partial patch).
    public async upsertInventoryPreloadRecord(record: {
        serialNumber: string;
        assetTag?: string;
        building?: string;
        room?: string;
        username?: string;
        fullName?: string;
        emailAddress?: string;
        deviceType?: string;
    }) {
        const existing = await this.findInventoryPreloadRecordBySerial(record.serialNumber);
        if (!existing) {
            const created = await this.createInventoryPreloadRecord(record);
            return { action: 'created', serialNumber: record.serialNumber, record: created };
        }
        const updated = await this.updateInventoryPreloadRecordById(String(existing.id), record, existing);
        return { action: 'updated', serialNumber: record.serialNumber, id: existing.id, record: updated };
    }

    public async getPrestageAssignments() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computer prestage assignments');
        try {
            const pageSize = 100;
            let page = 0;
            const results: any[] = [];
            let totalCount = 0;

            while (true) {
                const apiStart = Date.now();
                const response = await this.restGet('/api/v3/computer-prestages', {
                    params: { page, 'page-size': pageSize, sort: 'id:desc' }
                });
                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', '/api/v3/computer-prestages', response.status, apiDuration);

                totalCount = response.data.totalCount ?? 0;
                results.push(...(response.data.results ?? []));
                if (results.length >= totalCount || (response.data.results ?? []).length < pageSize) break;
                page++;
            }

            this.logger.info('Computer prestage assignments retrieved successfully', { count: results.length });
            return { totalCount, results };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching prestage assignments');
                logApiCall(this.logger, 'GET', '/api/v3/computer-prestages', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Prestage Assignments' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching prestage assignments", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v3/computer-prestages', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getPrestageScope(prestageId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching prestage scope', { prestageId });
        try {
            const apiStart = Date.now();
            const response = await this.restGet(`/api/v2/computer-prestages/${prestageId}/scope`);
            logApiCall(this.logger, 'GET', `/api/v2/computer-prestages/${prestageId}/scope`, response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Prestage Assignments' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching prestage scope', { prestageId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/api/v2/computer-prestages/${prestageId}/scope`, undefined, undefined, error as Error);
            throw error;
        }
    }

    private async resolvePrestage(nameOrId: string): Promise<{ id: string; displayName: string }> {
        const data = await this.getPrestageAssignments();
        const prestages: any[] = Array.isArray(data) ? data : (data as any).results ?? [];
        const lower = nameOrId.toLowerCase();
        const match =
            prestages.find((p) => String(p.id) === nameOrId || p.displayName?.toLowerCase() === lower) ??
            prestages.find((p) => p.displayName?.toLowerCase().includes(lower));
        if (!match) throw new Error(`Prestage not found: "${nameOrId}"`);
        return { id: String(match.id), displayName: match.displayName ?? String(match.id) };
    }

    // Adds serials to a computer prestage's scope without disturbing existing
    // assignments, one serial per POST rather than one PUT with the whole
    // merged list. Confirmed live (scripts/reassign-prestage-scope.sh in the
    // DesktopManagementContext repo, built investigating a bulk-unassignment
    // incident): Jamf's v2 scope endpoint's POST verb adds a single serial
    // without needing/replacing the full existing list, and validates each
    // serial independently — unlike PUT (a full-replace), which 400s the
    // *entire* batch with no per-serial detail if even one serial fails
    // Jamf's server-side ADE validation (most commonly
    // `DEVICE_DOES_NOT_EXIST_ON_TOKEN`: the serial's Apple Business Manager
    // assignment has moved off this MDM server's token, even though the
    // computer's own Jamf record may still show a past PreStage enrollment —
    // an ABM-side state, not a Jamf or tool bug). Doing one serial per
    // request means a bad serial only fails itself instead of blocking every
    // other, otherwise-valid serial behind it in the same call. Does NOT
    // remove a serial from any other prestage it may already be scoped to.
    public async assignSerialsToPrestage(prestageNameOrId: string, serialNumbers: string[]) {
        await this.ensureAuthenticated();
        const { id: prestageId, displayName } = await this.resolvePrestage(prestageNameOrId);
        this.logger.info('Assigning serials to prestage', { prestageId, displayName, count: serialNumbers.length });

        const scope = await this.getPrestageScope(prestageId);
        const existing: string[] = (scope.assignments ?? []).map((a: any) => a.serialNumber);
        let versionLock = scope.versionLock;

        const normalized = serialNumbers.map((s) => s.trim().toUpperCase()).filter(Boolean);
        const alreadyScoped = normalized.filter((s) => existing.includes(s));
        const toAdd = normalized.filter((s) => !existing.includes(s));

        if (toAdd.length === 0) {
            this.logger.info('No new serials to add', { prestageId });
            return { success: true, prestageId, prestageName: displayName, added: [], failed: [], alreadyScoped, totalScoped: existing.length };
        }

        const added: string[] = [];
        const failed: { serial: string; error: string }[] = [];

        for (const serial of toAdd) {
            try {
                const apiStart = Date.now();
                const response = await this.client.post(`/api/v2/computer-prestages/${prestageId}/scope`, {
                    serialNumbers: [serial],
                    versionLock,
                });
                logApiCall(this.logger, 'POST', `/api/v2/computer-prestages/${prestageId}/scope`, response.status, Date.now() - apiStart);
                versionLock = response.data?.versionLock ?? versionLock;
                added.push(serial);
            } catch (error) {
                if (axios.isAxiosError(error) && error.response?.status === 403) {
                    throw new Error(`Permission denied (403). The API client may be missing 'Update Prestage Assignments' permissions in JAMF Pro.`);
                }
                const detail = extractJamfErrorDetail(error);
                failed.push({ serial, error: detail });
                this.logger.warn('Serial failed prestage assignment', { prestageId, serial, error: detail });
            }
        }

        this.logger.info('Serials assigned to prestage', { prestageId, added: added.length, failed: failed.length });
        return {
            success: failed.length === 0,
            prestageId,
            prestageName: displayName,
            added,
            failed,
            alreadyScoped,
            totalScoped: existing.length + added.length,
        };
    }

    public async getStaticComputerGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching static computer groups');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/computer-groups');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/computer-groups', response.status, apiDuration);

            // Filter to only static groups (exclude smart groups)
            const allGroups = response.data.computerGroups || [];
            const staticGroups = allGroups.filter((group: any) => !group.isSmart);

            this.logger.info('Static computer groups retrieved successfully', { totalGroups: allGroups.length, staticGroups: staticGroups.length });
            return {
                totalCount: staticGroups.length,
                computerGroups: staticGroups
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching computer groups');
                logApiCall(this.logger, 'GET', '/api/v1/computer-groups', undefined, undefined, error as Error);
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching static computer groups", { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/api/v1/computer-groups', undefined, undefined, error as Error);
            throw error;
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private async resolveComputerId(nameOrSerial: string): Promise<string> {
        const escaped = escapeRsqlValue(nameOrSerial);
        for (const filter of [
            `hardware.serialNumber=="${escaped}"`,
            `general.name=="${escaped}"`
        ]) {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v3/computers-inventory', {
                params: { filter, 'page-size': 1, section: 'GENERAL' }
            });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', response.status, Date.now() - apiStart);
            const id = response.data.results?.[0]?.id;
            if (id) return String(id);
        }
        throw new Error(`Computer not found: "${nameOrSerial}"`);
    }

    private async resolveCategoryId(name: string): Promise<string> {
        const data = await this.getCategories(0, 200);
        const categories: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        const match = categories.find((c) => c.name?.toLowerCase() === lower)
            ?? categories.find((c) => c.name?.toLowerCase().includes(lower));
        if (!match) throw new Error(`Category not found: "${name}"`);
        return String(match.id);
    }

    private async resolveDiskEncryptionConfigIdByName(name: string): Promise<string> {
        const data = await this.getDiskEncryptionConfigurations();
        const configs: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        const match = configs.find((c) => c.name?.toLowerCase() === lower)
            ?? configs.find((c) => c.name?.toLowerCase().includes(lower));
        if (!match) throw new Error(`Disk Encryption Configuration not found: "${name}"`);
        return String(match.id);
    }

    // Policy scoping can target either a smart or static computer group — Classic
    // API's scope.computer_groups doesn't distinguish the two structurally, so this
    // searches both lists.
    private async resolveComputerGroupIdByName(name: string): Promise<{ id: string; name: string }> {
        const [smart, staticData] = await Promise.all([
            this.getSmartComputerGroups(),
            this.getStaticComputerGroups(),
        ]);
        const smartGroups: any[] = Array.isArray(smart) ? smart : (smart as any).results ?? [];
        const staticGroups: any[] = (staticData as any).computerGroups ?? [];
        const all = [...smartGroups, ...staticGroups];
        const lower = name.trim().toLowerCase();
        const match = all.find((g) => g.name?.toLowerCase() === lower)
            ?? all.find((g) => g.name?.toLowerCase().includes(lower));
        if (!match) throw new Error(`Computer group not found: "${name}"`);
        return { id: String(match.id), name: match.name };
    }

    private async resolvePolicyId(nameOrId: string): Promise<{ id: string; name: string }> {
        if (/^\d+$/.test(nameOrId)) {
            const detail = await this.getPolicyDetail(nameOrId);
            return { id: nameOrId, name: detail.general?.name ?? nameOrId };
        }
        const data = await this.getPolicies(nameOrId, 0, 200);
        const results: any[] = data.results ?? [];
        const lower = nameOrId.toLowerCase();
        const match = results.find((p) => p.name?.toLowerCase() === lower)
            ?? results.find((p) => p.name?.toLowerCase().includes(lower));
        if (!match) throw new Error(`Policy not found: "${nameOrId}"`);
        return { id: String(match.id), name: match.name };
    }

    // ── New public methods ───────────────────────────────────────────────────

    public async getComputerBySerial(serial: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computer by serial', { serial });
        try {
            const apiStart = Date.now();
            const inventoryResponse = await this.restGet('/api/v3/computers-inventory', {
                params: { filter: `hardware.serialNumber=="${escapeRsqlValue(serial)}"`, 'page-size': 1 }
            });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', inventoryResponse.status, Date.now() - apiStart);
            const computerId = inventoryResponse.data.results?.[0]?.id;
            if (!computerId) return { totalCount: 0, results: [] };

            const apiStart2 = Date.now();
            const detailResponse = await this.restGet(`/api/v3/computers-inventory-detail/${computerId}`);
            logApiCall(this.logger, 'GET', `/api/v3/computers-inventory-detail/${computerId}`, detailResponse.status, Date.now() - apiStart2);
            this.logger.info('Computer by serial retrieved', { serial, computerId });
            return { totalCount: 1, results: [detailResponse.data] };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching computer by serial', { serial, error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async updateComputerRecord(
        nameOrSerial: string,
        updates: {
            username?: string;
            realName?: string;
            emailAddress?: string;
            department?: string;
            building?: string;
            room?: string;
            assetTag?: string;
        }
    ) {
        await this.ensureAuthenticated();
        this.logger.info('Updating computer record', { nameOrSerial, updates });
        try {
            const computerId = await this.resolveComputerId(nameOrSerial);
            const body: any = { computer: {} };

            const location: any = {};
            if (updates.username !== undefined) location.username = updates.username;
            if (updates.realName !== undefined) location.real_name = updates.realName;
            if (updates.emailAddress !== undefined) location.email_address = updates.emailAddress;
            if (updates.department !== undefined) location.department = updates.department;
            if (updates.building !== undefined) location.building = updates.building;
            if (updates.room !== undefined) location.room = updates.room;
            if (Object.keys(location).length > 0) body.computer.location = location;

            if (updates.assetTag !== undefined) {
                body.computer.general = { asset_tag: updates.assetTag };
            }

            const apiStart = Date.now();
            const response = await this.client.put(`/JSSResource/computers/id/${computerId}`, body);
            logApiCall(this.logger, 'PUT', `/JSSResource/computers/id/${computerId}`, response.status, Date.now() - apiStart);
            this.logger.info('Computer record updated', { nameOrSerial, computerId });
            return { success: true, computerId };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Computers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating computer record', { nameOrSerial, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/JSSResource/computers/id/${nameOrSerial}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Deletes a computer record. Gateway-only, deliberately — confirmed live that the two
    // direct-API paths behave completely differently and neither works: Classic API
    // (`DELETE /JSSResource/computers/id/{id}`) returns a generic pre-auth 401 HTML page
    // for every attempt (same failure signature as the retired jamf_send_mdm_command —
    // this Classic API sub-resource appears to reject OAuth client-credentials auth
    // entirely, not a privilege gap), and the modern API (`DELETE
    // /api/v1/computers-inventory/{id}`) gets real auth but a genuine 403 INVALID_PRIVILEGE
    // (this tenant's own API client just lacks a delete privilege). The JAMF_PLATFORM_*
    // Gateway credential is the one path confirmed to work — `DELETE
    // {baseUrl}/pro/v1/tenant/{tenantId}/computers-inventory/{id}` returned 204 on all 35
    // records tested live. Unlike restGet()'s opportunistic Gateway-or-direct-client
    // fallback, this method requires the Gateway outright (via ensurePlatformAuthenticated()
    // throwing if unconfigured) rather than attempting the direct client first, since the
    // direct client is already confirmed not to work for this operation.
    public async deleteComputer(nameOrSerial: string) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Deleting computer record', { nameOrSerial });
        try {
            const computerId = await this.resolveComputerId(nameOrSerial);
            const apiStart = Date.now();
            const path = `/pro/v1/tenant/${tenantId}/computers-inventory/${computerId}`;
            const response = await this.platformClient.delete(path);
            logApiCall(this.logger, 'DELETE', path, response.status, Date.now() - apiStart);
            this.logger.info('Computer record deleted', { nameOrSerial, computerId });
            return { success: true, computerId };
        } catch (error) {
            this.logger.error('Error deleting computer record', { nameOrSerial, error: (error as Error).message });
            logApiCall(this.logger, 'DELETE', `/computers-inventory (${nameOrSerial})`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getPolicies(name?: string, page?: number, pageSize?: number, options?: { categoryName?: string; excludeAutoGeneratedNames?: boolean }) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching policies', { name, page, pageSize, options });
        try {
            const apiStart = Date.now();
            // Classic API's /JSSResource/policies/category/{category} filters
            // server-side, avoiding a full-fleet fetch when the caller already
            // knows the category — the plain /JSSResource/policies endpoint
            // returns every policy (id + name only, no other fields) with no
            // query-param filtering support at all.
            const endpoint = options?.categoryName
                ? `/JSSResource/policies/category/${encodeURIComponent(options.categoryName)}`
                : '/JSSResource/policies';
            const response = await this.client.get(endpoint, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', endpoint, response.status, Date.now() - apiStart);
            let policies: any[] = response.data.policies ?? [];
            if (name) {
                const lower = name.toLowerCase();
                policies = policies.filter((p: any) => p.name?.toLowerCase().includes(lower));
            }
            if (options?.excludeAutoGeneratedNames) {
                policies = policies.filter((p: any) => !JAMF_AUTO_GENERATED_POLICY_NAME.test(p.name ?? ''));
            }
            const start = (page ?? 0) * (pageSize ?? 100);
            const paged = policies.slice(start, start + (pageSize ?? 100));
            this.logger.info('Policies retrieved', { total: policies.length, returned: paged.length });
            return { totalCount: policies.length, results: paged };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Policies' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404 && options?.categoryName) {
                throw new Error(`No category named "${options.categoryName}" found (or it has no policies) — use jamf_list_categories to see valid names.`);
            }
            this.logger.error('Error fetching policies', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', options?.categoryName ? `/JSSResource/policies/category/${encodeURIComponent(options.categoryName)}` : '/JSSResource/policies', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getPolicyDetail(policyId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching policy detail', { policyId });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/JSSResource/policies/id/${policyId}`, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', `/JSSResource/policies/id/${policyId}`, response.status, Date.now() - apiStart);
            this.logger.info('Policy detail retrieved', { policyId });
            return response.data.policy ?? response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Policies' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Policy with ID ${policyId} not found.`);
            }
            this.logger.error('Error fetching policy detail', { policyId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/policies/id/${policyId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Get policy execution history for a single computer — JAMF Pro's computer History >
     * Policy Logs view. Classic-API-only (no v1/v3 equivalent), via the `Policy_Logs` subset of
     * `/JSSResource/computerhistory` — confirmed live that this subset name (with underscore)
     * correctly narrows the response to just `policy_logs` (an invalid subset silently returns an
     * empty object rather than erroring, so the subset name matters). Results come back from JAMF
     * in an arbitrary (not date-sorted) order — confirmed live against a real computer with 71
     * entries — so this always sorts by `date_completed_epoch` descending before returning.
     * Extracted as `fetchPolicyLogsForComputerId` so getPolicyFleetStatus can reuse the same
     * fetch/sort/filter logic against computer IDs it already has from scope resolution, without
     * paying for `resolveComputerId`'s extra name/serial lookup round-trip per computer.
     */
    private async fetchPolicyLogsForComputerId(
        computerId: string,
        options?: { policyId?: string | number; policyName?: string; status?: string; limit?: number }
    ) {
        try {
            const apiStart = Date.now();
            const response = await this.client.get(
                `/JSSResource/computerhistory/id/${computerId}/subset/Policy_Logs`,
                { headers: { Accept: 'application/json' } }
            );
            logApiCall(this.logger, 'GET', `/JSSResource/computerhistory/id/${computerId}/subset/Policy_Logs`, response.status, Date.now() - apiStart);

            const allLogs: any[] = response.data.computer_history?.policy_logs ?? [];
            const sorted = [...allLogs].sort((a, b) => (b.date_completed_epoch ?? 0) - (a.date_completed_epoch ?? 0));

            const policyId = options?.policyId !== undefined ? String(options.policyId) : undefined;
            const policyName = options?.policyName?.trim().toLowerCase();
            const status = options?.status?.trim().toLowerCase();
            let filtered = sorted;
            if (policyId !== undefined) {
                filtered = filtered.filter((l: any) => String(l.policy_id) === policyId);
            }
            if (policyName) {
                filtered = filtered.filter((l: any) => String(l.policy_name || '').toLowerCase().includes(policyName));
            }
            if (status) {
                filtered = filtered.filter((l: any) => String(l.status || '').toLowerCase() === status);
            }

            const limit = options?.limit ?? 100;
            const limited = filtered.slice(0, limit);

            return {
                computerId,
                logs: limited,
                summary: {
                    totalLogs: allLogs.length,
                    filteredLogs: filtered.length,
                    returnedLogs: limited.length,
                    truncated: filtered.length > limited.length
                }
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read' permissions for Computer History in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Computer with ID ${computerId} not found.`);
            }
            this.logger.error('Error fetching computer policy logs', { computerId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/computerhistory/id/${computerId}/subset/Policy_Logs`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getComputerPolicyLogs(
        computerNameOrSerial: string,
        options?: { policyName?: string; status?: string; limit?: number }
    ) {
        await this.ensureAuthenticated();
        const computerId = await this.resolveComputerId(computerNameOrSerial);
        this.logger.info('Fetching computer policy logs', { computerNameOrSerial, computerId });
        const result = await this.fetchPolicyLogsForComputerId(computerId, options);
        this.logger.info('Computer policy logs retrieved', {
            computerId, totalLogs: result.summary.totalLogs, filteredLogs: result.summary.filteredLogs, returnedLogs: result.summary.returnedLogs
        });
        return result;
    }

    /**
     * Get fleet-wide rollout status for a single policy: resolves its scope (direct computers plus
     * computer groups, minus exclusions), then checks each scoped computer's policy history for its
     * most recent run of this specific policy. Answers "is this policy actually rolling out /
     * failing broadly?" — the harder question `jamf_get_policy` (scope definition) and
     * `jamf_get_computer_policy_logs` (single computer) can't answer alone.
     *
     * `scope.limitations` (network segments, LDAP users/groups) are NOT resolved — those narrow
     * scope in ways this method can't cheaply cross-reference (they gate on session context, not a
     * static computer list), so a computer matched via computers/computer_groups may still be
     * excluded by a limitation in ways this result won't reflect. Known simplification, not a bug.
     *
     * Group membership is resolved via `getSmartGroupDetail`, which — confirmed live — embeds the
     * current `computers` array in its Classic API response for BOTH smart and static groups (the
     * same call already used for `jamf_get_smart_group`), so no separate static-group-membership
     * method is needed.
     *
     * Scoped-to-"All Computers" policies are refused rather than enumerated — checking history for
     * the entire fleet one-by-one isn't practical as a single call. Sequential (not parallel)
     * per-computer history fetches, matching `listSelfServicePolicies`'s existing convention of not
     * hammering JAMF with concurrent requests; `maxComputers` (default 100) caps how many are
     * checked, with `droppedCount` reporting how many scoped computers were left unchecked rather
     * than silently truncating.
     */
    public async getPolicyFleetStatus(policyIdentifier: string, options?: { maxComputers?: number }) {
        await this.ensureAuthenticated();
        const { id: policyId, name: policyName } = await this.resolvePolicyId(policyIdentifier);
        this.logger.info('Fetching policy fleet status', { policyId, policyName });

        const policy = await this.getPolicyDetail(policyId);
        const scope = policy.scope ?? {};

        if (scope.all_computers) {
            return {
                policyId,
                policyName,
                allComputers: true,
                computers: [],
                summary: { totalTargeted: 0, checked: 0, droppedCount: 0, byStatus: {} },
                note: 'This policy is scoped to All Computers — checking every computer\'s history individually isn\'t practical as a single call. Narrow the policy\'s scope, or check specific computers via jamf_get_computer_policy_logs.'
            };
        }

        const targets = new Map<number, { id: number; name: string; serial: string | null }>();
        const addComputer = (c: any) => {
            if (c?.id !== undefined) targets.set(c.id, { id: c.id, name: c.name, serial: c.serial_number ?? null });
        };
        const addGroup = async (g: any) => {
            const detail = await this.getSmartGroupDetail(String(g.id));
            for (const c of detail.computers ?? []) addComputer(c);
        };

        for (const c of scope.computers ?? []) addComputer(c);
        for (const g of scope.computer_groups ?? []) await addGroup(g);

        const exclusions = scope.exclusions ?? {};
        for (const c of exclusions.computers ?? []) targets.delete(c.id);
        for (const g of exclusions.computer_groups ?? []) {
            const detail = await this.getSmartGroupDetail(String(g.id));
            for (const c of detail.computers ?? []) targets.delete(c.id);
        }

        const allTargets = Array.from(targets.values());
        const maxComputers = options?.maxComputers ?? 100;
        const toCheck = allTargets.slice(0, maxComputers);
        const droppedCount = allTargets.length - toCheck.length;

        this.logger.info('Checking scoped computers for policy fleet status', {
            policyId, totalTargeted: allTargets.length, checking: toCheck.length, droppedCount
        });

        const results: any[] = [];
        for (const target of toCheck) {
            try {
                const logResult = await this.fetchPolicyLogsForComputerId(String(target.id), { policyId, limit: 1 });
                const latest = logResult.logs[0];
                results.push({
                    id: target.id,
                    name: target.name,
                    serial: target.serial,
                    status: latest?.status ?? 'Never run',
                    lastRun: latest?.date_completed ?? null
                });
            } catch (error) {
                results.push({
                    id: target.id,
                    name: target.name,
                    serial: target.serial,
                    status: 'Error',
                    lastRun: null,
                    error: (error as Error).message
                });
            }
        }

        const byStatus: Record<string, number> = {};
        for (const r of results) {
            byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
        }

        this.logger.info('Policy fleet status retrieved', { policyId, checked: results.length, byStatus });

        return {
            policyId,
            policyName,
            allComputers: false,
            computers: results,
            summary: {
                totalTargeted: allTargets.length,
                checked: toCheck.length,
                droppedCount,
                byStatus
            }
        };
    }

    // Narrows the full policy list down to real Self Service catalog entries.
    // The Classic API's bulk /JSSResource/policies list only ever returns
    // id+name (confirmed — no self_service field, no query-param filter for
    // it), so there's no way to filter server-side by
    // `self_service.use_for_self_service` the way categoryName can. This
    // narrows candidates as cheaply as possible first (optional category
    // filter via the server-side-filtered endpoint, then the
    // auto-generated-name exclusion heuristic, both free), then hydrates only
    // the remaining candidates via getPolicyDetail — capped at
    // `maxDetailChecks` (default 300) since hydrating the full ~2,724-policy
    // fleet one-by-one isn't practical as a single tool call. Reports how
    // many candidates were dropped by the cap rather than silently
    // truncating, so a caller knows the result may be incomplete.
    public async listSelfServicePolicies(options?: { categoryName?: string; name?: string; maxDetailChecks?: number }) {
        await this.ensureAuthenticated();
        const maxDetailChecks = options?.maxDetailChecks ?? 300;
        const candidates = await this.getPolicies(options?.name, 0, 100000, {
            categoryName: options?.categoryName,
            excludeAutoGeneratedNames: true,
        });
        const toCheck = candidates.results.slice(0, maxDetailChecks);
        const droppedCount = candidates.results.length - toCheck.length;

        this.logger.info('Checking candidates for Self Service status', {
            totalCandidates: candidates.totalCount,
            checking: toCheck.length,
            droppedCount,
        });

        const matches: Array<{
            id: number;
            name: string;
            categoryName?: string;
            displayName?: string;
            hasIcon: boolean;
            iconFilename?: string;
        }> = [];

        for (const candidate of toCheck) {
            let detail: any;
            try {
                detail = await this.getPolicyDetail(String(candidate.id));
            } catch (error) {
                this.logger.warn('Skipping candidate — detail fetch failed', { id: candidate.id, error: (error as Error).message });
                continue;
            }
            const selfService = detail?.self_service;
            if (selfService?.use_for_self_service) {
                matches.push({
                    id: candidate.id,
                    name: candidate.name,
                    categoryName: detail?.general?.category?.name,
                    displayName: selfService.self_service_display_name,
                    hasIcon: Boolean(selfService.self_service_icon?.id),
                    iconFilename: selfService.self_service_icon?.filename,
                });
            }
        }

        return {
            totalCandidates: candidates.totalCount,
            checked: toCheck.length,
            droppedCount,
            matches,
        };
    }

    // Exact-name match only (like findScriptByName) — getPolicies already supports a
    // substring `name` filter for listing, but upsert needs an exact match so a
    // differently-named policy sharing a substring doesn't get silently overwritten.
    private async findPolicyByName(name: string): Promise<any | null> {
        const data = await this.getPolicies(name, 0, 200);
        const policies: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        return policies.find((p) => p.name?.toLowerCase() === lower) ?? null;
    }

    // Upsert by name: creates a new policy if none exists with this name, otherwise
    // rebuilds the same known-safe section set (general/scope/self_service/
    // package_configuration/scripts/maintenance) and PUTs it in place of the existing
    // policy — mirroring upsertScript/upsertPackage/upsertApplicationSmartGroup so a
    // retried or re-run "create the deployment policy" request updates in place
    // rather than producing a duplicate. Deliberately does NOT echo back the existing
    // policy's full object first (unlike a naive read-merge-write) — same reasoning
    // as updatePolicyScope: Jamf returns sections on GET (e.g. `printers`) that 409
    // when resubmitted verbatim, so only the sections this method itself constructs
    // are ever sent.
    public async upsertPolicy(params: {
        name: string;
        enabled?: boolean;
        triggerCheckin?: boolean;
        triggerEnrollmentComplete?: boolean;
        triggerLogin?: boolean;
        triggerStartup?: boolean;
        triggerOther?: string;
        frequency?: string;
        categoryName?: string;
        targetGroupNames?: string[];
        exclusionGroupNames?: string[];
        scripts?: { name: string; priority?: 'Before' | 'After'; parameter4?: string }[];
        packages?: { name: string; action?: 'Install' | 'Cache' | 'Install Cached' }[];
        selfService?: { useForSelfService: boolean; displayName?: string; installButtonText?: string; description?: string };
        maintenanceRecon?: boolean;
        // Confirmed live gotcha (MCP_TOOL_GAPS.md #6): `apply` and `remediate` are
        // mutually exclusive intents — `apply` enables FileVault on an unencrypted
        // Mac, `remediate` re-issues/escrows a key on an already-encrypted one.
        // Combining fields from both in one policy silently drops the whole section.
        // Model these as two distinct shapes so a caller can't accidentally mix them.
        diskEncryption?:
            | { action: 'apply'; configurationName: string; authRestart?: boolean }
            | { action: 'remediate'; remediateKeyType: 'Individual' | 'Institutional'; configurationName?: string };
        userInteraction?: {
            messageStart?: string;
            allowUserToDefer?: boolean;
            allowDeferralUntilUtc?: string;
            allowDeferralMinutes?: number;
            messageFinish?: string;
        };
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting policy', { name: params.name });
        try {
            const existing = await this.findPolicyByName(params.name);
            const [targetGroups, exclusionGroups, categoryId, scripts, packages, diskEncryptionConfigId] = await Promise.all([
                Promise.all((params.targetGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                Promise.all((params.exclusionGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                params.categoryName ? this.resolveCategoryId(params.categoryName) : Promise.resolve(undefined),
                Promise.all((params.scripts ?? []).map(async (s) => {
                    const found = await this.findScriptByName(s.name);
                    if (!found) throw new Error(`Script not found: "${s.name}"`);
                    return { id: String(found.id), name: found.name, priority: s.priority ?? 'After', parameter4: s.parameter4 };
                })),
                Promise.all((params.packages ?? []).map(async (p) => {
                    const found = await this.findPackageByName(p.name);
                    if (!found) throw new Error(`Package not found: "${p.name}"`);
                    return { id: String(found.id), name: found.packageName, action: p.action ?? 'Install' };
                })),
                params.diskEncryption?.configurationName
                    ? this.resolveDiskEncryptionConfigIdByName(params.diskEncryption.configurationName)
                    : Promise.resolve(undefined),
            ]);

            const policy: Record<string, any> = {
                general: {
                    name: params.name,
                    enabled: params.enabled ?? true,
                    trigger_checkin: params.triggerCheckin ?? false,
                    trigger_enrollment_complete: params.triggerEnrollmentComplete ?? false,
                    trigger_login: params.triggerLogin ?? false,
                    trigger_startup: params.triggerStartup ?? false,
                    trigger_other: params.triggerOther ?? '',
                    frequency: params.frequency ?? 'Once per computer',
                    category: categoryId ? { id: categoryId } : undefined,
                },
                scope: {
                    all_computers: false,
                    computer_groups: targetGroups.map((g) => ({ id: g.id, name: g.name })),
                    exclusions: exclusionGroups.length
                        ? { computer_groups: exclusionGroups.map((g) => ({ id: g.id, name: g.name })) }
                        : undefined,
                },
                self_service: params.selfService
                    ? {
                          use_for_self_service: params.selfService.useForSelfService,
                          self_service_display_name: params.selfService.displayName,
                          install_button_text: params.selfService.installButtonText,
                          self_service_description: params.selfService.description,
                      }
                    : undefined,
                package_configuration: packages.length ? { packages } : undefined,
                scripts: scripts.length ? scripts : undefined,
                maintenance: { recon: params.maintenanceRecon ?? false },
                // Confirmed live (Jamf Pro 11.29.1): both sections' field names/values
                // were verified against a real policy (apply + remediate actions, and a
                // user_interaction update) via a follow-up GET. Note the field name is
                // `allow_users_to_defer` (plural) — Jamf silently ignores an unrecognized
                // singular `allow_user_to_defer` rather than erroring, so a naive test
                // could pass while doing nothing; caught this only by decoding a real 409
                // ("When 'allow_users_to_defer' is false, ... cannot be configured").
                // `allow_deferral_minutes` must be a multiple of 1440 (Jamf only exposes
                // whole days in its own UI) — a non-multiple also 409s, not a silent no-op.
                // Also observed: reads for a just-written disk_encryption/user_interaction
                // section can be genuinely NON-MONOTONIC for up to ~60s after the write —
                // a GET at +5s showed the new value, +10s through +20s reverted to the OLD
                // value, then it settled on the new value from +10s onward on a retry populated
                // by wait, and never reverted (60s+ steady) — consistent with multiple
                // Jamf app-server nodes with independently-expiring caches behind a load
                // balancer, not a simple linear propagation delay. A single quick
                // follow-up GET cannot be trusted either way; wait a full minute (not
                // just "a few seconds") before concluding a disk_encryption/
                // user_interaction change didn't apply.
                disk_encryption: params.diskEncryption
                    ? params.diskEncryption.action === 'apply'
                        ? {
                              action: 'apply',
                              disk_encryption_configuration_id: diskEncryptionConfigId,
                              auth_restart: params.diskEncryption.authRestart ?? false,
                          }
                        : {
                              action: 'remediate',
                              remediate_key_type: params.diskEncryption.remediateKeyType,
                              remediate_disk_encryption_configuration_id: diskEncryptionConfigId,
                          }
                    : undefined,
                user_interaction: params.userInteraction
                    ? {
                          message_start: params.userInteraction.messageStart ?? '',
                          allow_users_to_defer: params.userInteraction.allowUserToDefer ?? false,
                          allow_deferral_until_utc: params.userInteraction.allowDeferralUntilUtc ?? '',
                          allow_deferral_minutes: params.userInteraction.allowDeferralMinutes ?? 0,
                          message_finish: params.userInteraction.messageFinish ?? '',
                      }
                    : undefined,
            };

            if (!existing) {
                const xml = buildXmlDocument('policy', policy);
                const apiStart = Date.now();
                const response = await this.client.post('/JSSResource/policies/id/0', xml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'POST', '/JSSResource/policies/id/0', response.status, Date.now() - apiStart);
                const match = String(response.data).match(/<id>(\d+)<\/id>/);
                if (!match) throw new Error('Policy created but no ID could be determined from the response.');
                this.logger.info('Policy created', { name: params.name, id: match[1] });
                return { action: 'created' as const, id: match[1], name: params.name };
            }

            // Confirmed live (Jamf Pro 11.29.1): a single PUT combining certain
            // top-level sections (e.g. package_configuration + scope) returns 201 but
            // silently drops BOTH changes — a follow-up GET shows neither applied.
            // Sending one top-level section per sequential PUT is the only combination
            // confirmed to reliably apply every section; slower, but correct.
            const id = String(existing.id);
            const sections = Object.entries(policy).filter(([, v]) => v !== undefined);
            for (const [key, value] of sections) {
                const sectionXml = buildXmlDocument('policy', { [key]: value });
                const apiStart = Date.now();
                const response = await this.client.put(`/JSSResource/policies/id/${id}`, sectionXml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'PUT', `/JSSResource/policies/id/${id} (${key})`, response.status, Date.now() - apiStart);
            }
            this.logger.info('Policy updated', { name: params.name, id, sections: sections.map(([k]) => k) });
            return { action: 'updated' as const, id, name: params.name };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create/Update Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error upserting policy', { name: params.name, error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/policies/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Enable/disable and/or widen/narrow the scope of an EXISTING policy. Reads the
    // full current policy, merges only the requested changes into its scope, and
    // PUTs the whole merged policy back — defensive read-modify-write regardless of
    // whether Classic API PUT partially merges or fully replaces `scope` specifically
    // (unconfirmed either way; sending the full object back is safe under both).
    public async updatePolicyScope(nameOrId: string, changes: {
        enabled?: boolean;
        frequency?: string;
        addTargetGroupNames?: string[];
        removeTargetGroupNames?: string[];
        addExclusionGroupNames?: string[];
        removeExclusionGroupNames?: string[];
    }) {
        await this.ensureAuthenticated();
        const { id, name } = await this.resolvePolicyId(nameOrId);
        this.logger.info('Updating policy scope', { id, name, changes });
        try {
            const current = await this.getPolicyDetail(id);

            const [addTargets, removeTargets, addExclusions, removeExclusions] = await Promise.all([
                Promise.all((changes.addTargetGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                Promise.all((changes.removeTargetGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                Promise.all((changes.addExclusionGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                Promise.all((changes.removeExclusionGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
            ]);

            const mergeGroups = (existing: any[], toAdd: { id: string; name: string }[], toRemove: { id: string; name: string }[]) => {
                const removeIds = new Set(toRemove.map((g) => g.id));
                const kept = existing.filter((g: any) => !removeIds.has(String(g.id)));
                const existingIds = new Set(kept.map((g: any) => String(g.id)));
                const added = toAdd.filter((g) => !existingIds.has(g.id));
                return [...kept, ...added.map((g) => ({ id: g.id, name: g.name }))];
            };

            const existingTargets: any[] = Array.isArray(current.scope?.computer_groups) ? current.scope.computer_groups : [];
            const existingExclusions: any[] = Array.isArray(current.scope?.exclusions?.computer_groups)
                ? current.scope.exclusions.computer_groups
                : [];

            const mergedTargets = mergeGroups(existingTargets, addTargets, removeTargets);
            const mergedExclusions = mergeGroups(existingExclusions, addExclusions, removeExclusions);

            // Confirmed live: Classic API PUT on policies partial-merges, same as
            // updateComputerRecord — and critically, sending the FULL current policy
            // object back (as originally designed here) is actively unsafe, not just
            // unnecessary: some sections Jamf returns on GET (e.g. `printers`) trigger
            // a 409 Conflict ("Problem with printer") when echoed back verbatim. So
            // this sends only the fields being changed; everything else (scripts,
            // packages, self_service, triggers, etc.) is left untouched by Jamf.
            const partialPolicy: Record<string, any> = {
                scope: {
                    all_computers: false,
                    computer_groups: mergedTargets,
                    exclusions: { computer_groups: mergedExclusions },
                },
            };
            if (changes.enabled !== undefined || changes.frequency !== undefined) {
                partialPolicy.general = {
                    ...(changes.enabled !== undefined ? { enabled: changes.enabled } : {}),
                    ...(changes.frequency !== undefined ? { frequency: changes.frequency } : {}),
                };
            }

            // Confirmed live (Jamf Pro 11.29.1): combining certain top-level sections
            // (e.g. package_configuration + scope) in one PUT returns 201 but silently
            // drops both — send `scope` and `general` as separate sequential PUTs
            // rather than one combined payload, matching upsertPolicy's workaround.
            for (const [key, value] of Object.entries(partialPolicy)) {
                const sectionXml = buildXmlDocument('policy', { [key]: value });
                const apiStart = Date.now();
                const response = await this.client.put(`/JSSResource/policies/id/${id}`, sectionXml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'PUT', `/JSSResource/policies/id/${id} (${key})`, response.status, Date.now() - apiStart);
            }

            // Confirmed live (Jamf Pro 11.29.1, policy ID 1 "Update Inventory") — and
            // confirmed the HARD way: this policy was accidentally left DISABLED in
            // production after a test run, because the first version of this
            // verification loop exited on the first read that happened to match the
            // target value. Reads of a just-written general.enabled/general.frequency
            // are not just delayed, they can be genuinely NON-MONOTONIC for up to a
            // minute or more afterward — a read can show the NEW value, then revert
            // to showing the OLD value on a later read, before finally settling. A
            // single matching read is NOT proof the change stuck. So this requires
            // TWO CONSECUTIVE matching reads (5s apart) before accepting success —
            // still not an absolute guarantee given how long the flip-flopping window
            // can be, which is why frequencyChangeFailed exists at all: always treat
            // a change to `enabled` (safety/operational impact) as unconfirmed until
            // independently re-checked via jamf_get_policy a minute or more later,
            // not just trusted from this call's return value.
            let verifyDetail = await this.getPolicyDetail(id);
            const matchesTarget = (d: any) =>
                (changes.frequency === undefined || d.general?.frequency === changes.frequency) &&
                (changes.enabled === undefined || d.general?.enabled === changes.enabled);
            let consecutiveMatches = matchesTarget(verifyDetail) ? 1 : 0;
            for (let attempt = 0; attempt < 12 && consecutiveMatches < 2; attempt++) {
                await new Promise((resolve) => setTimeout(resolve, 5000));
                verifyDetail = await this.getPolicyDetail(id);
                consecutiveMatches = matchesTarget(verifyDetail) ? consecutiveMatches + 1 : 0;
            }
            const actualFrequency: string = verifyDetail.general?.frequency;
            const actualEnabled: boolean = verifyDetail.general?.enabled;
            const frequencyChangeFailed = changes.frequency !== undefined && actualFrequency !== changes.frequency;
            const enabledChangeFailed = changes.enabled !== undefined && actualEnabled !== changes.enabled;

            this.logger.info('Policy scope updated', { id, name, frequencyChangeFailed, enabledChangeFailed });
            return {
                success: true,
                id,
                name,
                enabled: actualEnabled,
                frequency: actualFrequency,
                frequencyChangeFailed,
                enabledChangeFailed,
                targetGroups: mergedTargets.map((g: any) => g.name),
                exclusionGroups: mergedExclusions.map((g: any) => g.name),
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating policy scope', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/JSSResource/policies/id/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Adds/removes scripts on an EXISTING policy without touching anything else —
    // there was no safe way to do this before: jamf_update_policy deliberately never
    // touches scripts, and upsertPolicy reconstructs the ENTIRE policy from whatever
    // params are passed, silently resetting scope/triggers/frequency/etc. to defaults
    // for any field the caller doesn't re-specify (fine for its own upsert-by-name use
    // case, unsafe for "just add one script to an existing policy"). Mirrors
    // updatePolicyScope exactly: read current, merge only `scripts`, PUT back that one
    // section alone — never the full policy object (same `printers`-409 reasoning).
    // Confirmed live: used to insert a third same-priority script into the middle of
    // an existing two-script policy chain, and the merged array this method builds
    // and sends does match the caller's intended order exactly (verified via a
    // follow-up GET). CAVEAT, also confirmed live: Jamf's actual execution order for
    // multiple scripts sharing the same priority does NOT reliably follow that sent/
    // displayed array order regardless — a real run swapped two same-priority
    // scripts despite the correct order being sent and echoed back on GET. This
    // looks like Jamf-side tie-breaking (e.g. by internal script ID) rather than
    // anything this method controls; no client-side lever to force a specific order
    // among same-priority scripts has been found. If exact ordering matters, verify
    // the real run order via getComputerPolicyLogs after a live execution.
    public async updatePolicyScripts(nameOrId: string, changes: {
        addScripts?: { name: string; priority?: 'Before' | 'After'; parameter4?: string }[];
        removeScriptNames?: string[];
    }) {
        await this.ensureAuthenticated();
        const { id, name } = await this.resolvePolicyId(nameOrId);
        this.logger.info('Updating policy scripts', { id, name, changes });
        try {
            const current = await this.getPolicyDetail(id);
            const existingScripts: any[] = Array.isArray(current.scripts) ? current.scripts : [];

            const toAdd = await Promise.all((changes.addScripts ?? []).map(async (s) => {
                const found = await this.findScriptByName(s.name);
                if (!found) throw new Error(`Script not found: "${s.name}"`);
                return { id: String(found.id), name: found.name, priority: s.priority ?? 'After', parameter4: s.parameter4 };
            }));

            const removeLower = new Set((changes.removeScriptNames ?? []).map((n) => n.toLowerCase()));
            const addIds = new Set(toAdd.map((s) => s.id));
            const kept = existingScripts.filter((s: any) =>
                !removeLower.has(String(s.name).toLowerCase()) && !addIds.has(String(s.id))
            );
            const mergedScripts = [...kept, ...toAdd];

            const sectionXml = buildXmlDocument('policy', { scripts: mergedScripts });
            const apiStart = Date.now();
            const response = await this.client.put(`/JSSResource/policies/id/${id}`, sectionXml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'PUT', `/JSSResource/policies/id/${id} (scripts)`, response.status, Date.now() - apiStart);

            this.logger.info('Policy scripts updated', { id, name, scripts: mergedScripts.map((s: any) => s.name) });
            return { success: true, id, name, scripts: mergedScripts.map((s: any) => ({ name: s.name, priority: s.priority })) };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating policy scripts', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/JSSResource/policies/id/${id} (scripts)`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Uploads a Self Service icon for a policy — confirmed live (2026-07-24,
    // 8 policies): POST /JSSResource/fileuploads/policies/id/{id} with the
    // image as a multipart field named `name` (not `file` — Classic API's
    // fileuploads endpoint uses that field name regardless of what's being
    // uploaded). Native fetch/FormData rather than axios, matching
    // uploadPackageFileBuffer's precedent (axios's Node adapter doesn't
    // cleanly multipart-encode a plain FormData without the extra
    // `form-data` package). One upload during that session hit the exact
    // "201 but silently no-op'd" pattern already known from policy
    // list/scope writes (self_service_icon stayed empty on a follow-up GET
    // despite the 201) — a short OAuth token TTL was a suspected but
    // unconfirmed contributing factor. So this always verifies with a GET
    // after uploading, and retries once (ensureAuthenticated re-runs before
    // the retry, refreshing the token if it's within 60s of expiry) rather
    // than trusting the initial response.
    public async uploadPolicyIcon(policyNameOrId: string, fileContentBase64: string, fileName: string) {
        await this.ensureAuthenticated();
        const { id, name } = await this.resolvePolicyId(policyNameOrId);
        this.logger.info('Uploading Self Service icon', { id, name, fileName });

        const doUpload = async (): Promise<void> => {
            await this.ensureAuthenticated();
            const buffer = Buffer.from(fileContentBase64, 'base64');
            const form = new FormData();
            form.append('name', new Blob([new Uint8Array(buffer)]), fileName);

            const apiStart = Date.now();
            const response = await fetch(`${this.jamfUrl}/JSSResource/fileuploads/policies/id/${id}`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${this.token}` },
                body: form,
            });
            logApiCall(this.logger, 'POST', `/JSSResource/fileuploads/policies/id/${id}`, response.status, Date.now() - apiStart);
            if (response.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing file-upload permissions for Policies in JAMF Pro.`);
            }
            if (!response.ok) {
                const text = await response.text().catch(() => '');
                throw new Error(`Icon upload failed (${response.status}): ${text}`);
            }
        };

        await doUpload();
        await new Promise((resolve) => setTimeout(resolve, 3000));
        let detail = await this.getPolicyDetail(id);
        let icon = detail?.self_service?.self_service_icon;
        let retried = false;

        if (!icon?.id) {
            retried = true;
            this.logger.warn('Icon upload returned success but did not stick — retrying once', { id, name });
            await doUpload();
            await new Promise((resolve) => setTimeout(resolve, 3000));
            detail = await this.getPolicyDetail(id);
            icon = detail?.self_service?.self_service_icon;
        }

        this.logger.info('Icon upload result', { id, name, success: Boolean(icon?.id), retried });
        return {
            success: Boolean(icon?.id),
            policyId: id,
            policyName: name,
            iconId: icon?.id,
            iconFilename: icon?.filename,
            retried,
        };
    }

    private async findConfigurationProfileByName(name: string): Promise<{ id: number; name: string } | null> {
        const data = await this.getComputerConfigurationProfiles(name);
        const lower = name.trim().toLowerCase();
        return (data.results ?? []).find((p: any) => p.name?.toLowerCase() === lower) ?? null;
    }

    // Read a configuration profile's full payload/scope by name or numeric ID —
    // jamf_list_configuration_profiles only ever returns id/name, so there was no way
    // to see an existing profile's actual settings (general.payloads, the raw
    // .mobileconfig plist XML) or scope without the admin console. Confirmed live:
    // the Classic API's os_x_configuration_profile object has general
    // (id/name/description/site/category/distribution_method/user_removable/level/
    // uuid/redeploy_on_update/payloads) + scope (same shape as a policy's scope) +
    // self_service sections.
    public async getConfigurationProfileDetail(nameOrId: string): Promise<any> {
        await this.ensureAuthenticated();
        let id: string;
        if (/^\d+$/.test(nameOrId)) {
            id = nameOrId;
        } else {
            const found = await this.findConfigurationProfileByName(nameOrId);
            if (!found) throw new Error(`Configuration profile not found: "${nameOrId}"`);
            id = String(found.id);
        }
        this.logger.info('Fetching configuration profile detail', { id });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/JSSResource/osxconfigurationprofiles/id/${id}`, {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', `/JSSResource/osxconfigurationprofiles/id/${id}`, response.status, Date.now() - apiStart);
            return response.data.os_x_configuration_profile ?? response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read macOS Configuration Profiles' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Configuration profile with ID ${id} not found.`);
            }
            this.logger.error('Error fetching configuration profile detail', { id, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/osxconfigurationprofiles/id/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Create-or-update a macOS configuration profile by name — the only way to deliver
    // a .mobileconfig-native payload (Dock/Finder prefs, Focus/notification schedules,
    // desktop picture, etc.) via this MCP server before this was a script + policy,
    // which loses the profile-specific benefits (declarative re-assertion, no visible
    // Terminal flash, login-window-stage applicability). `payload` is the raw plist XML
    // (a full .mobileconfig file's contents, starting `<?xml version="1.0"...`) — passed
    // straight into `general.payloads`; `serializeXmlObjectBody`'s existing `escapeXml()`
    // entity-escapes it correctly as XML text content within the outer document (Jamf's
    // Classic API expects the inner plist XML-escaped inline, not wrapped in CDATA —
    // matches how `general.payloads` came back on a live GET, escaped the same way).
    // NOT YET CONFIRMED LIVE for the write path (only the read/GET side of this object
    // type has been exercised against real data) — verify against a real create/update
    // before relying on it, same caveat this codebase already applies elsewhere (e.g.
    // OEMConfig) to write paths built from the documented API shape but not yet exercised.
    public async upsertConfigurationProfile(params: {
        name: string;
        payload: string;
        description?: string;
        categoryName?: string;
        distributionMethod?: 'Install Automatically' | 'Make Available in Self Service';
        targetGroupNames?: string[];
        exclusionGroupNames?: string[];
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting configuration profile', { name: params.name });
        try {
            const existing = await this.findConfigurationProfileByName(params.name);
            const [targetGroups, exclusionGroups, categoryId] = await Promise.all([
                Promise.all((params.targetGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                Promise.all((params.exclusionGroupNames ?? []).map((n) => this.resolveComputerGroupIdByName(n))),
                params.categoryName ? this.resolveCategoryId(params.categoryName) : Promise.resolve(undefined),
            ]);

            const profile: Record<string, any> = {
                general: {
                    name: params.name,
                    description: params.description ?? '',
                    distribution_method: params.distributionMethod ?? 'Install Automatically',
                    payloads: params.payload,
                    category: categoryId ? { id: categoryId } : undefined,
                },
                scope: {
                    all_computers: false,
                    computer_groups: targetGroups.map((g) => ({ id: g.id, name: g.name })),
                    exclusions: exclusionGroups.length
                        ? { computer_groups: exclusionGroups.map((g) => ({ id: g.id, name: g.name })) }
                        : undefined,
                },
            };

            if (!existing) {
                const xml = buildXmlDocument('os_x_configuration_profile', profile);
                const apiStart = Date.now();
                const response = await this.client.post('/JSSResource/osxconfigurationprofiles/id/0', xml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'POST', '/JSSResource/osxconfigurationprofiles/id/0', response.status, Date.now() - apiStart);
                const match = String(response.data).match(/<id>(\d+)<\/id>/);
                if (!match) throw new Error('Configuration profile created but no ID could be determined from the response.');
                this.logger.info('Configuration profile created', { name: params.name, id: match[1] });
                return { action: 'created' as const, id: match[1], name: params.name };
            }

            // Same one-section-per-PUT discipline as upsertPolicy (confirmed live gotcha
            // there: combining sections in a single PUT can silently drop them) — applied
            // here defensively given the precedent on this same Classic API family, though
            // not independently confirmed for configuration profiles specifically.
            const id = String(existing.id);
            const sections = Object.entries(profile).filter(([, v]) => v !== undefined);
            for (const [key, value] of sections) {
                const sectionXml = buildXmlDocument('os_x_configuration_profile', { [key]: value });
                const apiStart = Date.now();
                const response = await this.client.put(`/JSSResource/osxconfigurationprofiles/id/${id}`, sectionXml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'PUT', `/JSSResource/osxconfigurationprofiles/id/${id} (${key})`, response.status, Date.now() - apiStart);
            }
            this.logger.info('Configuration profile updated', { name: params.name, id, sections: sections.map(([k]) => k) });
            return { action: 'updated' as const, id, name: params.name };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create/Update macOS Configuration Profiles' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 415) {
                throw new Error(`Unsupported Media Type (415) — the Classic API rejected the XML body for configuration profiles.`);
            }
            this.logger.error('Error upserting configuration profile', { name: params.name, error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/osxconfigurationprofiles/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getComputerConfigurationProfiles(name?: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computer configuration profiles', { name });
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/JSSResource/osxconfigurationprofiles', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/osxconfigurationprofiles', response.status, Date.now() - apiStart);
            let profiles: any[] = response.data.os_x_configuration_profiles ?? [];
            if (name) {
                const lower = name.toLowerCase();
                profiles = profiles.filter((p: any) => p.name?.toLowerCase().includes(lower));
            }
            this.logger.info('Configuration profiles retrieved', { count: profiles.length });
            return { totalCount: profiles.length, results: profiles };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read macOS Configuration Profiles' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching configuration profiles', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/JSSResource/osxconfigurationprofiles', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getPatchPolicies(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching patch policies', { page, pageSize });
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v3/patch-policies', {
                params: { page: page ?? 0, 'page-size': pageSize ?? 100 }
            });
            logApiCall(this.logger, 'GET', '/api/v3/patch-policies', response.status, Date.now() - apiStart);
            this.logger.info('Patch policies retrieved', { count: response.data.results?.length });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Patch Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching patch policies', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v3/patch-policies', undefined, undefined, error as Error);
            throw error;
        }
    }

    // ── LDAP directory search/import ──────────────────────────────────────────
    // All Classic API — confirmed against developer.jamf.com there is no modern
    // (v1/v2) equivalent for LDAP server search. Response field names for
    // /user and /group searches (e.g. `username`, `realname`, `email_address`)
    // vary by how the LDAP server's attribute mappings are configured in Jamf
    // Pro, so callers should treat the raw match as authoritative over any
    // assumed field name.
    public async getLdapServers() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching LDAP servers');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/JSSResource/ldapservers', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/ldapservers', response.status, Date.now() - apiStart);
            const results: any[] = response.data.ldap_servers ?? [];
            return { totalCount: results.length, results };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read LDAP Servers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching LDAP servers', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/JSSResource/ldapservers', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async searchLdapUsers(serverId: string, username: string) {
        await this.ensureAuthenticated();
        this.logger.info('Searching LDAP users', { serverId, username });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(
                `/JSSResource/ldapservers/id/${serverId}/user/${encodeURIComponent(username)}`,
                { headers: { Accept: 'application/json' } }
            );
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/user/${username}`, response.status, Date.now() - apiStart);
            return { results: response.data.ldap_users ?? [] };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read LDAP Servers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`LDAP server with ID ${serverId} not found.`);
            }
            this.logger.error('Error searching LDAP users', { serverId, username, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/user/${username}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async searchLdapGroups(serverId: string, groupName: string) {
        await this.ensureAuthenticated();
        this.logger.info('Searching LDAP groups', { serverId, groupName });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(
                `/JSSResource/ldapservers/id/${serverId}/group/${encodeURIComponent(groupName)}`,
                { headers: { Accept: 'application/json' } }
            );
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/group/${groupName}`, response.status, Date.now() - apiStart);
            return { results: response.data.ldap_groups ?? [] };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read LDAP Servers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`LDAP server with ID ${serverId} not found.`);
            }
            this.logger.error('Error searching LDAP groups', { serverId, groupName, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/group/${groupName}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async checkLdapGroupMembership(serverId: string, groupName: string, username: string) {
        await this.ensureAuthenticated();
        this.logger.info('Checking LDAP group membership', { serverId, groupName, username });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(
                `/JSSResource/ldapservers/id/${serverId}/group/${encodeURIComponent(groupName)}/user/${encodeURIComponent(username)}`,
                { headers: { Accept: 'application/json' } }
            );
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/group/${groupName}/user/${username}`, response.status, Date.now() - apiStart);
            return { results: response.data.ldap_users ?? [] };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read LDAP Servers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`LDAP server with ID ${serverId} not found.`);
            }
            this.logger.error('Error checking LDAP group membership', { serverId, groupName, username, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/JSSResource/ldapservers/id/${serverId}/group/${groupName}/user/${username}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    private async createUser(fields: Record<string, any>): Promise<string> {
        await this.ensureAuthenticated();
        try {
            const xml = buildXmlDocument('user', fields);
            const apiStart = Date.now();
            const response = await this.client.post('/JSSResource/users/id/0', xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'POST', '/JSSResource/users/id/0', response.status, Date.now() - apiStart);
            const match = String(response.data).match(/<id>(\d+)<\/id>/);
            if (!match) throw new Error('User created but no ID could be determined from the response.');
            return match[1];
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create Users' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating Jamf user', { error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/users/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Searches LDAP server(s) for `username` and, on a match, creates a Jamf Pro
    // User object seeded from the directory record — the actual fix for a
    // "Directory Service Group shows 0 members" issue (a smart user group whose
    // criteria matches against directory-linked Jamf Users, not raw directory
    // accounts). Idempotent: if a Jamf User with this username already exists,
    // returns it rather than erroring or duplicating. `fullName`/`email`/`position`
    // overrides always win over whatever the LDAP match parsed to, since LDAP
    // attribute-to-field mapping is configured per-server and this codebase can't
    // assume the mapping in advance — the raw `ldapMatch` is always returned too
    // so a caller can verify before trusting the imported record.
    public async importDirectoryUser(params: {
        username: string;
        serverId?: string;
        fullName?: string;
        email?: string;
        position?: string;
        siteId?: string;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Importing directory user', { username: params.username, serverId: params.serverId });

        const existingUser = await this.resolveJamfUserIdByUsername(params.username);
        if (existingUser) {
            this.logger.info('Directory user already exists as a Jamf User', { username: params.username, id: existingUser.id });
            return { action: 'exists' as const, id: existingUser.id, name: existingUser.name, matchedServerId: undefined, ldapMatch: null };
        }

        const servers = params.serverId
            ? [{ id: params.serverId }]
            : (await this.getLdapServers()).results;

        let ldapMatch: any = null;
        let matchedServerId: string | undefined;
        for (const server of servers) {
            try {
                const data = await this.searchLdapUsers(String(server.id), params.username);
                if (data.results.length > 0) {
                    ldapMatch = data.results[0];
                    matchedServerId = String(server.id);
                    break;
                }
            } catch (err) {
                this.logger.warn('LDAP user search failed for one server, trying next', { serverId: server.id, error: (err as Error).message });
            }
        }

        if (!ldapMatch && !params.fullName) {
            throw new Error(
                `No directory match found for "${params.username}" in any configured LDAP server, and no fullName override ` +
                `was given to import blind. Use jamf_search_directory_user to check spelling/server first, or pass fullName ` +
                `explicitly to create the Jamf User without a directory match.`
            );
        }

        const fields: Record<string, any> = {
            name: params.username,
            full_name: params.fullName ?? ldapMatch?.realname ?? ldapMatch?.full_name ?? params.username,
            email_address: params.email ?? ldapMatch?.email_address ?? undefined,
            position: params.position ?? ldapMatch?.position ?? undefined,
        };
        if (params.siteId) fields.site = { id: params.siteId };

        const id = await this.createUser(fields);
        this.logger.info('Directory user imported', { username: params.username, id, matchedServerId });
        return { action: 'imported' as const, id, name: params.username, matchedServerId, ldapMatch };
    }

    // ── Cloud Identity Provider test lookups ──────────────────────────────────
    // Modern (v1) API — this is the callable equivalent of the Settings > Global
    // > Cloud Identity Providers > Search test screen in the Jamf Pro UI.
    public async getCloudIdentityProviders() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching Cloud Identity Providers');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/cloud-idp', {
                params: { 'page-size': 200 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/cloud-idp', response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read User' (Cloud Identity Provider) permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching Cloud Identity Providers', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/cloud-idp', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async testCloudIdpLookup(params: { idpId?: string; username?: string; groupName: string }) {
        await this.ensureAuthenticated();
        let idpId = params.idpId;
        if (!idpId) {
            const idps: any[] = (await this.getCloudIdentityProviders()).results ?? [];
            const active = idps.filter((p: any) => p.enabled !== false);
            if (active.length !== 1) {
                throw new Error(
                    active.length === 0
                        ? 'No Cloud Identity Provider is configured/enabled.'
                        : `Multiple Cloud Identity Providers are configured — pass idpId to disambiguate (${active.map((p: any) => `${p.id}: ${p.displayName ?? p.providerName}`).join(', ')}).`
                );
            }
            idpId = String(active[0].id);
        }

        this.logger.info('Testing Cloud Identity Provider lookup', { idpId, username: params.username, groupName: params.groupName });
        try {
            const apiStart = Date.now();
            const path = params.username
                ? `/api/v1/cloud-idp/${idpId}/test-user-membership`
                : `/api/v1/cloud-idp/${idpId}/test-group`;
            const body = params.username
                ? { username: params.username, groupname: params.groupName }
                : { groupname: params.groupName };
            const response = await this.client.post(path, body);
            logApiCall(this.logger, 'POST', path, response.status, Date.now() - apiStart);
            return { idpId, ...response.data };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`Cloud Identity Provider ${idpId} does not exist or is not active.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read User' (Cloud Identity Provider) permissions in JAMF Pro.`);
            }
            this.logger.error('Error testing Cloud Identity Provider lookup', { idpId, error: (error as Error).message });
            logApiCall(this.logger, 'POST', params.username ? `/api/v1/cloud-idp/${idpId}/test-user-membership` : `/api/v1/cloud-idp/${idpId}/test-group`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getDepartments() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching departments');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/departments', {
                params: { 'page-size': 1000 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/departments', response.status, Date.now() - apiStart);
            this.logger.info('Departments retrieved', { count: response.data.results?.length });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Departments' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching departments', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/departments', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getCategories(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching categories');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/categories', {
                params: { page: page ?? 0, 'page-size': pageSize ?? 200 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/categories', response.status, Date.now() - apiStart);
            this.logger.info('Categories retrieved', { count: response.data.results?.length });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Categories' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching categories', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/categories', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Flush a policy's execution history, making it eligible to run again on every computer in its
     * scope — needed for a "once per computer" frequency policy that already ran (successfully or
     * not) and needs to retry, e.g. after fixing a broken package. Flushes ALL computers' history
     * for the policy, not just one — there's no reliable way to scope a flush to a single policy +
     * single computer combination via the Classic API's `/JSSResource/logflush` resource (the
     * alternative XML-body form takes both a `log_id` and a `<computers>` list, but its `log_id`
     * filter is reported to be ignored when a computers list is also given, silently flushing that
     * computer's history for every policy instead of just the one requested — not worth the risk of
     * wiping unrelated policy history to avoid it). This uses the plain per-policy path instead,
     * which only takes an interval.
     *
     * Confirmed live (2026-07-28) against policy 3381 ("BeyondTrust Jump Client - Bernstein (Mac)",
     * scoped to 8 computers via the "Classrooms - Bernstein" smart group): the `interval` value
     * `"Zero Day"` is accepted as-is (no URL-encoding surprises beyond the space), the endpoint
     * returns `201` on success (not `204`), and a before/after check on 5 sampled scoped computers'
     * policy logs (via getComputerPolicyLogs) went from 1 log entry each for this policy to 0 —
     * confirming the flush actually took effect, not just that the call returned success.
     */
    public async flushPolicyLogs(policyNameOrId: string, interval: string = 'Zero Day') {
        await this.ensureAuthenticated();
        this.logger.info('Flushing policy logs', { policyNameOrId, interval });
        try {
            const { id: policyId, name: policyName } = await this.resolvePolicyId(policyNameOrId);
            const apiStart = Date.now();
            const response = await this.client.delete(
                `/JSSResource/logflush/policy/id/${policyId}/interval/${encodeURIComponent(interval)}`
            );
            logApiCall(this.logger, 'DELETE', `/JSSResource/logflush/policy/id/${policyId}/interval/${interval}`, response.status, Date.now() - apiStart);
            this.logger.info('Policy logs flushed', { policyId, policyName, interval });
            return { success: true, policyId, policyName, interval };
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 403) {
                    throw new Error(`Permission denied (403). The API client may be missing 'Flush Policy Logs' permissions in JAMF Pro.`);
                }
                if (error.response?.status === 404) {
                    throw new Error(`Log flush endpoint rejected the request (404) for policy "${policyNameOrId}" — the endpoint path or interval value may be wrong.`);
                }
            }
            this.logger.error('Error flushing policy logs', { policyNameOrId, interval, error: (error as Error).message });
            logApiCall(this.logger, 'DELETE', `/JSSResource/logflush/policy/id/${policyNameOrId}/interval/${interval}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async flushComputerMdmCommands(nameOrSerial: string, status: 'Pending' | 'Failed' | 'Pending+Failed') {
        await this.ensureAuthenticated();
        this.logger.info('Flushing MDM commands', { nameOrSerial, status });
        try {
            const computerId = await this.resolveComputerId(nameOrSerial);
            const apiStart = Date.now();
            const response = await this.client.delete(
                `/JSSResource/commandflush/computers/id/${computerId}/status/${status}`
            );
            logApiCall(this.logger, 'DELETE', `/JSSResource/commandflush/computers/id/${computerId}/status/${status}`, response.status, Date.now() - apiStart);
            this.logger.info('MDM commands flushed', { nameOrSerial, computerId, status });
            return { success: true, computerId, status };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Flush MDM Commands' permissions in JAMF Pro.`);
            }
            this.logger.error('Error flushing MDM commands', { nameOrSerial, status, error: (error as Error).message });
            logApiCall(this.logger, 'DELETE', `/JSSResource/commandflush/computers/id/${nameOrSerial}/status/${status}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getFilevaultStatus(nameOrSerial: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching FileVault status', { nameOrSerial });
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v3/computers-inventory', {
                params: {
                    filter: nameOrSerial.length <= 12 && /^[A-Z0-9]+$/.test(nameOrSerial)
                        ? `hardware.serialNumber=="${escapeRsqlValue(nameOrSerial)}"`
                        : `general.name=="${escapeRsqlValue(nameOrSerial)}"`,
                    'page-size': 1,
                    section: ['GENERAL', 'DISK_ENCRYPTION', 'HARDWARE']
                }
            });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', response.status, Date.now() - apiStart);
            const computer = response.data.results?.[0];
            if (!computer) return null;
            this.logger.info('FileVault status retrieved', { nameOrSerial });
            return {
                id: computer.id,
                name: computer.general?.name,
                serialNumber: computer.hardware?.serialNumber,
                diskEncryption: computer.diskEncryption
            };
        } catch (error) {
            this.logger.error('Error fetching FileVault status', { nameOrSerial, error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Bulk equivalent of getFilevaultStatus, above — one page of FileVault escrow
    // status for the whole fleet per call, rather than one API call per machine.
    // CONFIRMED LIVE 2026-07-29: routed through the Platform API Gateway rather than
    // the tenant's own direct Jamf Pro API — the tenant's own JAMF_CLIENT_ID/SECRET
    // role 403s against this exact endpoint (missing 'View Disk Encryption Recovery
    // Key'), but the Platform Gateway credential's account.jamf.com Integration was
    // granted that privilege (`read:env:filevault`) and returns real data (confirmed
    // against this tenant: 49 computers). Same response shape as the direct v4
    // endpoint, just proxied through a different host/credential.
    public async getFilevaultStatusBulk(page?: number, pageSize?: number) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching bulk FileVault status via Platform API Gateway', { page: page ?? 0, pageSize: pageSize ?? 100 });
        try {
            const apiStart = Date.now();
            const path = `/pro/v4/tenant/${tenantId}/computers-inventory/filevault`;
            const response = await this.platformClient.get(path, {
                params: { page: page ?? 0, 'page-size': pageSize ?? 100 }
            });
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const results = response.data.results ?? [];
            this.logger.info('Bulk FileVault status retrieved', { count: results.length, totalCount: response.data.totalCount });
            return {
                totalCount: response.data.totalCount ?? results.length,
                results
            };
        } catch (error) {
            const status = (error as any)?.response?.status;
            if (status === 403 || status === 401) {
                throw new Error(`Permission denied (${status}). The Platform API Gateway credential (JAMF_PLATFORM_CLIENT_ID) may be missing the 'read:env:filevault' privilege on its account.jamf.com Integration.`);
            }
            this.logger.error('Error fetching bulk FileVault status', { page, pageSize, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/pro/v4/tenant/${tenantId}/computers-inventory/filevault`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // ─── LAPS (Local Admin Password, Platform API Gateway) ──────────────────
    // The tenant's own JAMF_CLIENT_ID/SECRET role 403s (INVALID_PRIVILEGE, missing
    // "View Local Admin Password") on both LAPS endpoints directly — same shape as
    // the bulk FileVault gap above, and the same Gateway credential covers it. No new
    // credential or privilege grant needed beyond the existing JAMF_PLATFORM_* Gateway
    // credential already wired up for FileVault/Compliance Benchmarks/Blueprints.
    // CONFIRMED LIVE 2026-07-30 against a real device (managementId resolved, 2 real
    // LAPS accounts listed with real username/guid fields, and a real current password
    // successfully retrieved for one of them). One real bug caught by this testing:
    // an earlier version of the password path dropped `clientManagementId` (passing it
    // as a query param instead of keeping it in the path like the accounts-list
    // endpoint does) and got a 403 back that looked exactly like a missing-privilege
    // error — it wasn't; the fix was purely the path shape, confirmed by retesting
    // after the fix with no credential/privilege change at all.

    // Resolves a computer's `clientManagementId` — the GUID LAPS keys off, distinct
    // from the plain numeric Jamf computer ID `resolveComputerId` returns. Confirmed
    // live: `GET /api/v1/computers-inventory-detail/{id}?section=GENERAL` ->
    // `general.managementId`.
    private async resolveClientManagementId(nameOrSerial: string): Promise<string> {
        // Uses the direct tenant client (not the Platform Gateway), so it needs the
        // tenant's own auth ensured — getLapsAccounts/getLapsPassword only ensure the
        // Gateway's auth before calling this, since resolving a computer ID/managementId
        // always goes through the tenant's own API regardless of Gateway configuration.
        await this.ensureAuthenticated();
        const computerId = await this.resolveComputerId(nameOrSerial);
        const apiStart = Date.now();
        const response = await this.client.get(`/api/v1/computers-inventory-detail/${computerId}`, {
            params: { section: 'GENERAL' }
        });
        logApiCall(this.logger, 'GET', `/api/v1/computers-inventory-detail/${computerId}`, response.status, Date.now() - apiStart);
        const managementId = response.data.general?.managementId;
        if (!managementId) {
            throw new Error(`No managementId found for computer "${nameOrSerial}" — it may not be enrolled via modern MDM.`);
        }
        return managementId;
    }

    /** List LAPS-managed local admin accounts on a computer, by name or serial. */
    public async getLapsAccounts(nameOrSerial: string) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        const clientManagementId = await this.resolveClientManagementId(nameOrSerial);
        this.logger.info('Fetching LAPS accounts', { nameOrSerial, clientManagementId });
        try {
            const path = `/pro/v2/tenant/${tenantId}/local-admin-password/${clientManagementId}/accounts`;
            const apiStart = Date.now();
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            const status = (error as any)?.response?.status;
            if (status === 403 || status === 401) {
                throw new Error(`Permission denied (${status}). The Platform API Gateway credential may be missing LAPS privileges on its account.jamf.com Integration.`);
            }
            if (status === 404) {
                throw new Error(`No LAPS accounts found for computer "${nameOrSerial}" (managementId ${clientManagementId}) — it may not have LAPS enabled.`);
            }
            this.logger.error('Error fetching LAPS accounts', { nameOrSerial, error: (error as Error).message });
            throw error;
        }
    }

    /**
     * Read a LAPS-managed local admin account's current password, by computer
     * name/serial and account username. Resolves the account's own GUID (a distinct
     * identifier from clientManagementId, needed for the password path) from
     * getLapsAccounts rather than requiring the caller to already know it. Confirmed
     * live 2026-07-30 against a real device/account, including the exact field names
     * parsed here (username/guid).
     */
    public async getLapsPassword(nameOrSerial: string, username: string) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        const clientManagementId = await this.resolveClientManagementId(nameOrSerial);

        const accountsData = await this.getLapsAccounts(nameOrSerial);
        const accounts: any[] = accountsData.results ?? accountsData.accounts ?? (Array.isArray(accountsData) ? accountsData : []);
        const account = accounts.find((a: any) => String(a.username ?? a.userName ?? '').toLowerCase() === username.toLowerCase());
        if (!account) {
            throw new Error(`LAPS account "${username}" not found for computer "${nameOrSerial}". Use jamf_get_laps_accounts to see available accounts.`);
        }
        const guid = account.guid ?? account.id;
        if (!guid) {
            throw new Error(`Could not determine the account GUID for "${username}" from the LAPS accounts response — its shape may differ from what this method expects.`);
        }

        this.logger.info('Fetching LAPS password', { nameOrSerial, clientManagementId, username });
        try {
            // clientManagementId stays in the path here, same as the accounts-list
            // endpoint above — an earlier version of this method dropped it (passing it
            // as a query param instead) and got a 403 back that looked like a privilege
            // gap but was actually just a malformed path; confirmed live once fixed.
            const path = `/pro/v2/tenant/${tenantId}/local-admin-password/${clientManagementId}/account/${encodeURIComponent(username)}/${guid}/password`;
            const apiStart = Date.now();
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            return { username, clientManagementId, ...response.data };
        } catch (error) {
            const status = (error as any)?.response?.status;
            if (status === 403 || status === 401) {
                throw new Error(`Permission denied (${status}). The Platform API Gateway credential may be missing LAPS privileges on its account.jamf.com Integration.`);
            }
            this.logger.error('Error fetching LAPS password', { nameOrSerial, username, error: (error as Error).message });
            throw error;
        }
    }

    // ─── Compliance Benchmarks (Platform API Gateway, Beta) ─────────────────
    // CONFIRMED LIVE 2026-07-29 against a real account.jamf.com Integration
    // credential (see the Platform API Gateway section at the top of this file):
    // getComplianceBaselines returns Jamf's real 14-baseline mSCP catalog (CIS,
    // NIST, CMMC, DISA-STIG, etc.), and getComplianceBenchmarks returns `{benchmarks:
    // []}` — real API access confirmed, this tenant simply hasn't configured any
    // benchmarks yet (resolves the previously-open question of whether Colgate has
    // Compliance Benchmarks enabled at all: the feature/API access works, there's
    // just nothing configured). Read-only: create (POST) and delete are deliberately
    // not implemented — creating/deleting a fleet-wide compliance benchmark is a real
    // security-posture change that needs an explicit human decision in the JAMF Pro
    // console, not something to expose as an MCP tool.
    // GET /v1/tenant/{tenantId}/baselines — Jamf's catalog of available mSCP
    // baselines (CIS Level 1/2, NIST 800-53/800-171, etc.) a tenant can build a
    // benchmark from. Not itself tenant-configuration-dependent, so this should
    // return results even for a tenant with zero benchmarks configured yet.
    // CONFIRMED LIVE 2026-07-29 — returned all 14 real catalog baselines.
    public async getComplianceBaselines() {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Compliance Benchmarks baselines', { tenantId });
        try {
            const apiStart = Date.now();
            const path = `/compliance-benchmarks/v1/tenant/${tenantId}/baselines`;
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const baselines = response.data.baselines ?? [];
            this.logger.info('Compliance Benchmarks baselines retrieved', { count: baselines.length });
            return { totalCount: baselines.length, results: baselines };
        } catch (error) {
            this.logger.error('Error fetching Compliance Benchmarks baselines', { tenantId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/compliance-benchmarks/v1/tenant/${tenantId}/baselines`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // GET /v1/tenant/{tenantId}/benchmarks — this tenant's own configured
    // benchmarks (if any). No pagination in the documented spec — Jamf returns
    // the full list in one response, unlike the mobile-device/computer-scale
    // endpoints elsewhere in this file. CONFIRMED LIVE 2026-07-29 — returns
    // `{benchmarks: []}` for this tenant (no benchmarks configured yet, not an error).
    public async getComplianceBenchmarks() {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Compliance Benchmarks list', { tenantId });
        try {
            const apiStart = Date.now();
            const path = `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks`;
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const benchmarks = response.data.benchmarks ?? [];
            this.logger.info('Compliance Benchmarks list retrieved', { count: benchmarks.length });
            return { totalCount: benchmarks.length, results: benchmarks };
        } catch (error) {
            this.logger.error('Error fetching Compliance Benchmarks list', { tenantId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // GET /v1/tenant/{tenantId}/benchmarks/{id} — a single benchmark's full
    // detail, including its embedded `rules` array (per Jamf's spec, the detail
    // response already contains every rule inline — there's no need for a
    // separate call to the sibling /benchmarks/{id}/rules endpoint just to list
    // them). Also folds in compliance-percentage as a best-effort extra field:
    // a benchmark with no reportable rules yet returns 404 for that specific
    // sub-call ("Benchmark has no applicable rules for reporting calculations"),
    // which is a valid state, not a failure of the whole detail fetch — caught
    // and surfaced as `compliancePercentage: null` rather than thrown. Request
    // construction confirmed live 2026-07-29 (this tenant has zero configured
    // benchmarks to fetch a real detail for, so the 404 branch is exercised
    // rather than the success branch — still a real, confirmed round-trip).
    public async getComplianceBenchmarkDetail(benchmarkId: string) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Compliance Benchmark detail', { tenantId, benchmarkId });
        try {
            const apiStart = Date.now();
            const path = `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks/${benchmarkId}`;
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const benchmark = response.data;

            let compliancePercentage: number | null = null;
            try {
                const pctPath = `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks/${benchmarkId}/compliance-percentage`;
                const pctStart = Date.now();
                const pctResponse = await this.platformClient.get(pctPath);
                logApiCall(this.logger, 'GET', pctPath, pctResponse.status, Date.now() - pctStart);
                compliancePercentage = pctResponse.data?.compliancePercentage ?? null;
            } catch (pctError) {
                if (axios.isAxiosError(pctError) && pctError.response?.status === 404) {
                    this.logger.info('Benchmark has no applicable rules for compliance percentage', { benchmarkId });
                } else {
                    this.logger.warn('Error fetching compliance percentage (non-fatal)', { benchmarkId, error: (pctError as Error).message });
                }
            }

            this.logger.info('Compliance Benchmark detail retrieved', { benchmarkId });
            return { ...benchmark, compliancePercentage };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                return null;
            }
            this.logger.error('Error fetching Compliance Benchmark detail', { tenantId, benchmarkId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks/${benchmarkId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // GET /v1/tenant/{tenantId}/benchmarks/{id}/devices — per-rule device
    // drill-down (which devices passed/failed one specific rule of one specific
    // benchmark report). Kept as its own tool/method rather than folded into
    // getComplianceBenchmarkDetail — it needs an additional required rule ID and
    // is itself paginated, the same shape as jamf_get_smart_group_members being
    // split out from jamf_get_policy rather than embedded in it.
    public async getComplianceBenchmarkDevices(benchmarkId: string, ruleId: string, options?: {
        page?: number;
        pageSize?: number;
        deviceSearch?: string;
        ruleResult?: 'PASSED' | 'FAILED' | 'UNKNOWN';
    }) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Compliance Benchmark rule devices', { tenantId, benchmarkId, ruleId });
        try {
            const params: Record<string, any> = {
                'rule-id': ruleId,
                page: options?.page ?? 0,
                'page-size': options?.pageSize ?? 100,
            };
            if (options?.deviceSearch) params['device-search'] = options.deviceSearch;
            if (options?.ruleResult) params['rule-result'] = options.ruleResult;

            const apiStart = Date.now();
            const path = `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks/${benchmarkId}/devices`;
            const response = await this.platformClient.get(path, { params });
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const results = response.data.results ?? [];
            this.logger.info('Compliance Benchmark rule devices retrieved', { count: results.length, totalCount: response.data.totalCount });
            return { totalCount: response.data.totalCount ?? results.length, results };
        } catch (error) {
            this.logger.error('Error fetching Compliance Benchmark rule devices', { tenantId, benchmarkId, ruleId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/compliance-benchmarks/v1/tenant/${tenantId}/benchmarks/${benchmarkId}/devices`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // ─── Blueprints (Platform API Gateway) ──────────────────────────────────
    // Jamf's declarative-device-management feature — CONFIRMED LIVE 2026-07-29
    // against the same Platform API Gateway credential as Compliance Benchmarks
    // above (real data: 4 blueprints, 16 blueprint components, full detail+report
    // round-trips). Read-only, matching the Compliance Benchmarks convention:
    // create/update/delete/deploy/undeploy are NOT implemented here — deploying or
    // undeploying a blueprint changes real devices' management state fleet-wide,
    // a decision that needs a deliberate human choice in the JAMF Pro console (or a
    // future, explicitly-requested write tool), not something to expose implicitly
    // via a read-tool refactor.

    // GET /v1/tenant/{tenantId}/blueprints — list this tenant's blueprints (name,
    // deployment state, last deployment result). Optional `search` matches against
    // name/description server-side.
    public async getBlueprints(options?: { search?: string; page?: number; pageSize?: number }) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Blueprints list', { tenantId, search: options?.search });
        try {
            const params: Record<string, any> = {
                page: options?.page ?? 0,
                'page-size': options?.pageSize ?? 100,
            };
            if (options?.search) params.search = options.search;

            const apiStart = Date.now();
            const path = `/blueprints/v1/tenant/${tenantId}/blueprints`;
            const response = await this.platformClient.get(path, { params });
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const results = response.data.results ?? [];
            this.logger.info('Blueprints list retrieved', { count: results.length, totalCount: response.data.totalCount });
            return { totalCount: response.data.totalCount ?? results.length, results };
        } catch (error) {
            this.logger.error('Error fetching Blueprints list', { tenantId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/blueprints/v1/tenant/${tenantId}/blueprints`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // GET /v1/tenant/{tenantId}/blueprints/{id} — full detail (scope, steps,
    // component configuration). Also folds in the blueprint's status report
    // (succeeded/failed/pending device counts) as a best-effort extra field, same
    // pattern as getComplianceBenchmarkDetail folding in compliance-percentage —
    // a report fetch failure doesn't fail the whole detail call.
    public async getBlueprintDetail(blueprintId: string) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Blueprint detail', { tenantId, blueprintId });
        try {
            const apiStart = Date.now();
            const path = `/blueprints/v1/tenant/${tenantId}/blueprints/${blueprintId}`;
            const response = await this.platformClient.get(path);
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const blueprint = response.data;

            let report: any = null;
            try {
                const reportPath = `/blueprints/v1/tenant/${tenantId}/blueprints/${blueprintId}/report`;
                const reportStart = Date.now();
                const reportResponse = await this.platformClient.get(reportPath);
                logApiCall(this.logger, 'GET', reportPath, reportResponse.status, Date.now() - reportStart);
                report = reportResponse.data;
            } catch (reportError) {
                this.logger.warn('Error fetching blueprint report (non-fatal)', { blueprintId, error: (reportError as Error).message });
            }

            this.logger.info('Blueprint detail retrieved', { blueprintId });
            return { ...blueprint, report };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                return null;
            }
            this.logger.error('Error fetching Blueprint detail', { tenantId, blueprintId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/blueprints/v1/tenant/${tenantId}/blueprints/${blueprintId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // GET /v1/tenant/{tenantId}/blueprint-components — the catalog of components
    // (payload types) available to build blueprints from (Software Updates,
    // Configuration Profile, Custom Declarations, etc.), not this tenant's own
    // blueprints' chosen components — same "catalog vs. configured" split as
    // getComplianceBaselines vs. getComplianceBenchmarks above.
    public async getBlueprintComponents(options?: { page?: number; pageSize?: number }) {
        await this.ensurePlatformAuthenticated();
        const tenantId = this.getPlatformTenantId();
        this.logger.info('Fetching Blueprint components catalog', { tenantId });
        try {
            const apiStart = Date.now();
            const path = `/blueprints/v1/tenant/${tenantId}/blueprint-components`;
            const response = await this.platformClient.get(path, {
                params: { page: options?.page ?? 0, 'page-size': options?.pageSize ?? 100 }
            });
            logApiCall(this.logger, 'GET', path, response.status, Date.now() - apiStart);
            const results = response.data.results ?? [];
            this.logger.info('Blueprint components retrieved', { count: results.length, totalCount: response.data.totalCount });
            return { totalCount: response.data.totalCount ?? results.length, results };
        } catch (error) {
            this.logger.error('Error fetching Blueprint components', { tenantId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/blueprints/v1/tenant/${tenantId}/blueprint-components`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Wraps GET /api/v1/auth — the same "who am I" check the JAMF Pro UI's own
    // account page uses. Exists because a bare 401/403 from any other endpoint
    // doesn't say *which* privilege is missing; diffing this call's `privileges`
    // list against what an endpoint needs is the fastest way to confirm "client
    // authenticated fine but its role lacks this one privilege" vs. "bad token".
    public async getAuthDetails() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching current API client auth/privilege details');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/auth');
            logApiCall(this.logger, 'GET', '/api/v1/auth', response.status, Date.now() - apiStart);
            this.logger.info('Auth details retrieved');
            return response.data;
        } catch (error) {
            this.logger.error('Error fetching auth details', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/auth', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Disk Encryption Configuration objects (name/key-type/escrow behavior a
    // policy's <disk_encryption> section references by ID) are a distinct object
    // type from a computer's per-machine FileVault status (getFilevaultStatus,
    // above) — this is Classic API only, no v1/v3 equivalent exists.
    public async getDiskEncryptionConfigurations() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching disk encryption configurations');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/JSSResource/diskencryptionconfigurations', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/diskencryptionconfigurations', response.status, Date.now() - apiStart);
            const configs: any[] = response.data.disk_encryption_configurations ?? [];
            this.logger.info('Disk encryption configurations retrieved', { count: configs.length });
            return { totalCount: configs.length, results: configs };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Disk Encryption Configurations' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching disk encryption configurations', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/JSSResource/diskencryptionconfigurations', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Confirmed live (Jamf Pro 11.29.1) against GET .../diskencryptionconfigurations/id/{id}:
    // the writable shape is {name, key_type, file_vault_enabled_users,
    // institutional_recovery_key: {key, certificate_type, password_sha256, data}}.
    // Scoped to key_type=Individual only — Institutional additionally needs an
    // uploaded recovery-key certificate (institutional_recovery_key), comparable
    // in complexity to package file upload, and wasn't asked for here.
    public async upsertDiskEncryptionConfiguration(params: {
        name: string;
        fileVaultEnabledUsers?: 'Management Account' | 'Current or Next User' | 'Management Account And Current or Next User';
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting disk encryption configuration', { name: params.name });
        const fields = {
            name: params.name,
            key_type: 'Individual',
            file_vault_enabled_users: params.fileVaultEnabledUsers ?? 'Current or Next User',
        };
        try {
            const data = await this.getDiskEncryptionConfigurations();
            const lower = params.name.trim().toLowerCase();
            const existing = (data.results ?? []).find((c: any) => c.name?.toLowerCase() === lower);

            if (!existing) {
                const xml = buildXmlDocument('disk_encryption_configuration', fields);
                const apiStart = Date.now();
                const response = await this.client.post('/JSSResource/diskencryptionconfigurations/id/0', xml, {
                    headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
                });
                logApiCall(this.logger, 'POST', '/JSSResource/diskencryptionconfigurations/id/0', response.status, Date.now() - apiStart);
                const match = String(response.data).match(/<id>(\d+)<\/id>/);
                if (!match) throw new Error('Disk Encryption Configuration created but no ID could be determined from the response.');
                this.logger.info('Disk encryption configuration created', { name: params.name, id: match[1] });
                return { action: 'created' as const, id: match[1], name: params.name };
            }

            const id = String(existing.id);
            const xml = buildXmlDocument('disk_encryption_configuration', fields);
            const apiStart = Date.now();
            const response = await this.client.put(`/JSSResource/diskencryptionconfigurations/id/${id}`, xml, {
                headers: { 'Content-Type': 'application/xml', Accept: 'application/json' },
            });
            logApiCall(this.logger, 'PUT', `/JSSResource/diskencryptionconfigurations/id/${id}`, response.status, Date.now() - apiStart);
            this.logger.info('Disk encryption configuration updated', { name: params.name, id });
            return { action: 'updated' as const, id, name: params.name };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create/Update Disk Encryption Configurations' permissions in JAMF Pro.`);
            }
            this.logger.error('Error upserting disk encryption configuration', { name: params.name, error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/JSSResource/diskencryptionconfigurations/id/0', undefined, undefined, error as Error);
            throw error;
        }
    }

    // ── App Installers (Jamf App Catalog) ────────────────────────────────────
    // A distinct feature from packages/policies: Jamf-hosted/curated installer
    // "titles" (e.g. Chrome, Zoom, Slack) deployed via /api/v1/app-installers,
    // not the Classic API package/policy machinery used elsewhere in this file.

    public async getAppInstallerTitles(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching app installer titles');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/app-installers/titles', {
                params: { page: page ?? 0, 'page-size': pageSize ?? 200 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/app-installers/titles', response.status, Date.now() - apiStart);
            this.logger.info('App installer titles retrieved', { count: response.data.results?.length });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read App Installers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching app installer titles', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/app-installers/titles', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Confirmed live (Jamf Pro 11.29.1): the catalog title's display name field
    // is `titleName`, not `title` — e.g. {id: "0BC", titleName: "Google Chrome",
    // bundleId: "com.google.Chrome", publisher: "Google", ...}. `id` is an
    // alphanumeric catalog code (e.g. "0BC"), not a numeric JAMF object ID.
    private async findAppInstallerTitleByName(name: string): Promise<any> {
        const data = await this.getAppInstallerTitles(0, 999);
        const titles: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        const match = titles.find((t) => t.titleName?.toLowerCase() === lower)
            ?? titles.find((t) => t.titleName?.toLowerCase().includes(lower));
        if (!match) throw new Error(`App installer title not found in the Jamf catalog: "${name}"`);
        return match;
    }

    public async listAppInstallerDeployments(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching app installer deployments');
        try {
            const apiStart = Date.now();
            const response = await this.restGet('/api/v1/app-installers/deployments', {
                params: { page: page ?? 0, 'page-size': pageSize ?? 200 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/app-installers/deployments', response.status, Date.now() - apiStart);
            this.logger.info('App installer deployments retrieved', { count: response.data.results?.length });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read App Installers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching app installer deployments', { error: (error as Error).message });
            logApiCall(this.logger, 'GET', '/api/v1/app-installers/deployments', undefined, undefined, error as Error);
            throw error;
        }
    }

    public async getAppInstallerDeploymentDetail(deploymentId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching app installer deployment detail', { deploymentId });
        try {
            const apiStart = Date.now();
            const response = await this.restGet(`/api/v1/app-installers/deployments/${deploymentId}`);
            logApiCall(this.logger, 'GET', `/api/v1/app-installers/deployments/${deploymentId}`, response.status, Date.now() - apiStart);
            this.logger.info('App installer deployment detail retrieved', { deploymentId });
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read App Installers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                throw new Error(`App installer deployment with ID ${deploymentId} not found.`);
            }
            this.logger.error('Error fetching app installer deployment detail', { deploymentId, error: (error as Error).message });
            logApiCall(this.logger, 'GET', `/api/v1/app-installers/deployments/${deploymentId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    private async findAppInstallerDeploymentByName(name: string): Promise<any> {
        const data = await this.listAppInstallerDeployments(0, 999);
        const deployments: any[] = data.results ?? [];
        const lower = name.trim().toLowerCase();
        const match = deployments.find((d) => d.name?.toLowerCase() === lower)
            ?? deployments.find((d) => d.name?.toLowerCase().includes(lower));
        if (!match) throw new Error(`App installer deployment not found: "${name}"`);
        return match;
    }

    // Resolves an id-or-name deployment reference to its numeric ID — mirrors
    // resolvePolicyId's shape for the same reason (callers shouldn't need to
    // separately call a list tool just to get an ID for jamf_update_app_installer_deployment).
    private async resolveAppInstallerDeploymentId(nameOrId: string): Promise<string> {
        if (/^\d+$/.test(nameOrId)) return nameOrId;
        const match = await this.findAppInstallerDeploymentByName(nameOrId);
        return String(match.id);
    }

    // Creates a new App Installer deployment (an ongoing Jamf-managed update
    // subscription for a catalog title, scoped to a smart group). Not an
    // upsert — Jamf's own UI treats deployment name as free text, not a unique
    // key, so re-running with the same name would need to be a deliberate
    // "update the existing one" call via jamf_update_app_installer_deployment
    // instead, mirroring intune_create_win32_app's create-only design (see
    // MCP_TOOL_GAPS.md's Intune section) rather than the upsert-by-name pattern
    // used elsewhere in this file for scripts/packages/smart groups.
    public async createAppInstallerDeployment(params: {
        name: string;
        appTitleName: string;
        smartGroupName: string;
        enabled?: boolean;
        categoryName?: string;
        siteId?: string;
        deploymentType?: 'INSTALL_AUTOMATICALLY' | 'SELF_SERVICE';
        updateBehavior?: 'AUTOMATIC' | 'MANUAL';
        notificationInterval?: number;
        deadline?: number;
        installPredefinedConfigProfiles?: boolean;
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Creating app installer deployment', { name: params.name, appTitleName: params.appTitleName });
        try {
            const [title, smartGroup, categoryId] = await Promise.all([
                this.findAppInstallerTitleByName(params.appTitleName),
                this.resolveComputerGroupIdByName(params.smartGroupName),
                params.categoryName ? this.resolveCategoryId(params.categoryName) : Promise.resolve(undefined),
            ]);

            // Confirmed live (Jamf Pro 11.29.1) end-to-end — created a real
            // deployment (Adobe Photoshop 2026, disabled, scoped to an empty
            // smart group), fetched it back, and diffed every field against
            // this exact body before deleting it: appTitleId/categoryId/siteId/
            // smartGroupId are flat top-level fields, and notificationInterval/
            // deadline are nested under `notificationSettings` on both the
            // request body and the response, exactly as built here.
            const body: Record<string, any> = {
                name: params.name,
                enabled: params.enabled ?? true,
                appTitleId: String(title.id),
                siteId: params.siteId ?? '-1',
                smartGroupId: smartGroup.id,
                deploymentType: params.deploymentType ?? 'INSTALL_AUTOMATICALLY',
                updateBehavior: params.updateBehavior ?? 'AUTOMATIC',
                installPredefinedConfigProfiles: params.installPredefinedConfigProfiles ?? false,
                notificationSettings: {
                    notificationInterval: params.notificationInterval ?? 24,
                    deadline: params.deadline ?? 7,
                },
            };
            if (categoryId) body.categoryId = categoryId;

            const apiStart = Date.now();
            const response = await this.client.post('/api/v1/app-installers/deployments', body);
            logApiCall(this.logger, 'POST', '/api/v1/app-installers/deployments', response.status, Date.now() - apiStart);
            const id = String(response.data.id ?? response.data.deploymentId);
            this.logger.info('App installer deployment created', { name: params.name, id });
            return { action: 'created' as const, id, name: params.name };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Create App Installers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error creating app installer deployment', { name: params.name, error: (error as Error).message });
            logApiCall(this.logger, 'POST', '/api/v1/app-installers/deployments', undefined, undefined, error as Error);
            throw error;
        }
    }

    // Updates an existing deployment by name or numeric ID. Confirmed live
    // (Jamf Pro 11.29.1): unlike the Classic API XML endpoints elsewhere in
    // this file, this v1 JSON PUT applies a full-object echo-back cleanly —
    // enabled/notificationInterval/deadline all landed correctly in one PUT,
    // no section-splitting workaround needed. Still reads the current
    // deployment first and merges only the given fields on top before writing
    // the whole object back (the same defensive read-merge-write approach
    // updateScriptById/updatePackageMetadata use for other v1 JSON resources),
    // so an omitted field can't be silently nulled out even though a naive
    // partial PUT wasn't observed to be a problem here.
    public async updateAppInstallerDeployment(nameOrId: string, changes: {
        enabled?: boolean;
        smartGroupName?: string;
        categoryName?: string;
        deploymentType?: 'INSTALL_AUTOMATICALLY' | 'SELF_SERVICE';
        updateBehavior?: 'AUTOMATIC' | 'MANUAL';
        notificationInterval?: number;
        deadline?: number;
    }) {
        await this.ensureAuthenticated();
        const id = await this.resolveAppInstallerDeploymentId(nameOrId);
        this.logger.info('Updating app installer deployment', { id, changes });
        try {
            // Confirmed live (Jamf Pro 11.29.1): GET .../deployments/{id} nests
            // notificationInterval/deadline under `notificationSettings`, not
            // top-level — merge into that sub-object rather than the top level.
            const existing = await this.getAppInstallerDeploymentDetail(id);
            const [smartGroup, categoryId] = await Promise.all([
                changes.smartGroupName ? this.resolveComputerGroupIdByName(changes.smartGroupName) : Promise.resolve(undefined),
                changes.categoryName ? this.resolveCategoryId(changes.categoryName) : Promise.resolve(undefined),
            ]);

            const body: Record<string, any> = {
                ...existing,
                enabled: changes.enabled ?? existing.enabled,
                smartGroupId: smartGroup?.id ?? existing.smartGroupId,
                categoryId: categoryId ?? existing.categoryId,
                deploymentType: changes.deploymentType ?? existing.deploymentType,
                updateBehavior: changes.updateBehavior ?? existing.updateBehavior,
                notificationSettings: {
                    ...existing.notificationSettings,
                    notificationInterval: changes.notificationInterval ?? existing.notificationSettings?.notificationInterval,
                    deadline: changes.deadline ?? existing.notificationSettings?.deadline,
                },
            };

            const apiStart = Date.now();
            const response = await this.client.put(`/api/v1/app-installers/deployments/${id}`, body);
            logApiCall(this.logger, 'PUT', `/api/v1/app-installers/deployments/${id}`, response.status, Date.now() - apiStart);
            this.logger.info('App installer deployment updated', { id });
            return { success: true, id, name: existing.name ?? nameOrId };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update App Installers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating app installer deployment', { id, error: (error as Error).message });
            logApiCall(this.logger, 'PUT', `/api/v1/app-installers/deployments/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    // Confirmed live (Jamf Pro 11.29.1): DELETE .../app-installers/deployments/{id}
    // returns 204 and the object is gone on a follow-up GET (404) — unlike
    // scripts/policies/smart groups, this API client's role CAN delete these.
    // Test-hygiene only — no corresponding MCP tool, since deleting a live
    // install/update subscription isn't a workflow this project has asked for.
    public async deleteAppInstallerDeployment(id: string): Promise<void> {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.delete(`/api/v1/app-installers/deployments/${id}`);
            logApiCall(this.logger, 'DELETE', `/api/v1/app-installers/deployments/${id}`, response.status, Date.now() - apiStart);
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Delete App Installers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error deleting app installer deployment', { id, error: (error as Error).message });
            logApiCall(this.logger, 'DELETE', `/api/v1/app-installers/deployments/${id}`, undefined, undefined, error as Error);
            throw error;
        }
    }
}
