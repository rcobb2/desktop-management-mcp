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

export class JamfClient {
    private client: AxiosInstance;
    private token: string | null = null;
    private tokenExpiresAt: number = 0;
    private jamfUrl: string;
    private jamfClientId: string;
    private jamfClientSecret: string;
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

    public async getComputerByName(name: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching computer by name', { computerName: name });
        try {
            // First, get the computer's ID using the computers-inventory endpoint
            const apiStart = Date.now();
            const inventoryResponse = await this.client.get('/api/v3/computers-inventory', {
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
            const detailResponse = await this.client.get(`/api/v3/computers-inventory-detail/${computerId}`);
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
                // Adjust error message for detail endpoint if necessary, or keep general
                throw new Error(`Permission denied (403). The API client may be missing necessary 'Read' permissions for 'Computer Inventory' and 'Computer Inventory Details' in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computer ${name}`, { error: (error as Error).message, stack: (error as Error).stack });
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
            const response = await this.client.get('/api/v2/mobile-devices', {
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
            const detailResponse = await this.client.get(`/api/v2/mobile-devices/${foundDevice.id}/detail`);
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Mobile Devices' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching mobile device ${name}`, { error: (error as Error).message, stack: (error as Error).stack });
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
                const response = await this.client.get('/api/v2/mobile-devices', {
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Mobile Devices' permissions in JAMF Pro.`);
            }
            this.logger.error('Error listing mobile devices', { error: (error as Error).message, stack: (error as Error).stack });
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
                const response = await this.client.get('/api/v2/computer-groups/smart-groups', {
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching smart computer groups", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getSmartMobileDeviceGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart mobile device groups');
        try {
            // Using Jamf Pro API v1
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/mobile-device-groups/smart-groups');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/mobile-device-groups/smart-groups', response.status, apiDuration);
            this.logger.info('Smart mobile device groups retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching smart mobile device groups');
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Mobile Device Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching smart mobile device groups", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getSmartComputerGroupMembers(groupId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart computer group members', { groupId });
        try {
            // Using Jamf Pro API v2 to get member IDs
            const apiStart = Date.now();
            const response = await this.client.get(`/api/v2/computer-groups/smart-group-membership/${groupId}`);
            let apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', `/api/v2/computer-groups/smart-group-membership/${groupId}`, response.status, apiDuration);
            
            const memberIds = response.data.members || [];

            // Fetch computer details for each member to get hostname
            const membersWithNames = await Promise.all(
                memberIds.map(async (id: number) => {
                    try {
                        const apiStart2 = Date.now();
                        const computerResponse = await this.client.get(`/api/v3/computers-inventory/${id}`, {
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Smart Computer Groups' and/or 'Read Computers' permissions in JAMF Pro.`);
            }
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                this.logger.warn('Smart computer group not found', { groupId });
                throw new Error(`Smart Computer Group with ID ${groupId} not found.`);
            }
            this.logger.error(`Error fetching smart computer group members for group ${groupId}`, { error: (error as Error).message, stack: (error as Error).stack });
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
            const response = await this.client.get('/api/v3/computers-inventory', { params });
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computers`, { error: (error as Error).message, stack: (error as Error).stack });
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
            const response = await this.client.get('/api/v1/computers-inventory', {
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching computers by user identifier ${identifier}`, { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getSites() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF sites');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/sites');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/sites', response.status, apiDuration);
            this.logger.info('Sites retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching sites');
                throw new Error(`Permission denied (403). The API client may be missing 'Read Sites' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching sites", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getScripts(name?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF scripts', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100 });
        try {
            const params: any = {
                page: page || 0,
                'page-size': pageSize || 100
            };
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/scripts', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/scripts', response.status, apiDuration);

            // Client-side filtering by name if provided (case-insensitive substring match).
            // The real v1 response's array is under `results`, not `scripts` — reading the
            // latter silently produced an always-empty filtered list (confirmed live).
            let scripts = response.data.results || [];
            if (name) {
                const nameLower = name.toLowerCase();
                scripts = scripts.filter((script: any) =>
                    script.name && script.name.toLowerCase().includes(nameLower)
                );
            }

            this.logger.info('Scripts retrieved successfully', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100, filteredCount: scripts.length, totalInPage: response.data.results?.length || 0 });
            return {
                ...response.data,
                results: scripts
            };
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 403) {
                    this.logger.error('Permission denied fetching scripts');
                    throw new Error(`Permission denied (403). The API client may be missing 'Read Scripts' permissions in JAMF Pro.`);
                }
                if (error.response?.status === 400) {
                    this.logger.error('Bad request fetching scripts', { status: error.response.status, data: error.response.data, config: { url: error.config?.url, params: error.config?.params } });
                    throw new Error(`Bad request (400). ${error.response.data?.message || 'Invalid filter or parameter format'}`);
                }
            }
            this.logger.error("Error fetching scripts", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getPackages(name?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching JAMF packages', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100 });
        try {
            const params: any = {
                page: page || 0,
                'page-size': pageSize || 100
            };
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/packages', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/packages', response.status, apiDuration);

            // Client-side filtering by name if provided (case-insensitive substring match).
            // The real v1 response's array is under `results`, not `packages` — reading the
            // latter silently produced an always-empty filtered list (confirmed live).
            let packages = response.data.results || [];
            if (name) {
                const nameLower = name.toLowerCase();
                packages = packages.filter((pkg: any) =>
                    pkg.packageName && pkg.packageName.toLowerCase().includes(nameLower)
                );
            }

            this.logger.info('Packages retrieved successfully', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100, filteredCount: packages.length, totalInPage: response.data.results?.length || 0 });
            return {
                ...response.data,
                results: packages
            };
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 403) {
                    this.logger.error('Permission denied fetching packages');
                    throw new Error(`Permission denied (403). The API client may be missing 'Read Packages' permissions in JAMF Pro.`);
                }
                if (error.response?.status === 400) {
                    this.logger.error('Bad request fetching packages', { status: error.response.status, data: error.response.data, config: { url: error.config?.url, params: error.config?.params } });
                    throw new Error(`Bad request (400). ${error.response.data?.message || 'Invalid filter or parameter format'}`);
                }
            }
            this.logger.error("Error fetching packages", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getScriptById(id: string) {
        await this.ensureAuthenticated();
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/api/v1/scripts/${id}`);
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
            throw error;
        }
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
            const response = await this.client.get('/api/v1/inventory-preload', { params });
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v1/inventory-preload', response.status, apiDuration);
            this.logger.info('Inventory preload records retrieved successfully');
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching inventory preload records');
                throw new Error(`Permission denied (403). The API client may be missing 'Read Inventory Preload Records' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching inventory preload records", { error: (error as Error).message, stack: (error as Error).stack });
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
                const response = await this.client.get('/api/v3/computer-prestages', {
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Prestage Assignments' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching prestage assignments", { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getPrestageScope(prestageId: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching prestage scope', { prestageId });
        try {
            const apiStart = Date.now();
            const response = await this.client.get(`/api/v2/computer-prestages/${prestageId}/scope`);
            logApiCall(this.logger, 'GET', `/api/v2/computer-prestages/${prestageId}/scope`, response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Prestage Assignments' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching prestage scope', { prestageId, error: (error as Error).message });
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
    // assignments. Jamf's scope endpoint replaces the entire scope on write, so
    // this reads the current scope, merges in only the new serials, and writes
    // the full list back with the versionLock Jamf requires for optimistic
    // concurrency. Does NOT remove a serial from any other prestage it may
    // already be scoped to.
    public async assignSerialsToPrestage(prestageNameOrId: string, serialNumbers: string[]) {
        await this.ensureAuthenticated();
        const { id: prestageId, displayName } = await this.resolvePrestage(prestageNameOrId);
        this.logger.info('Assigning serials to prestage', { prestageId, displayName, count: serialNumbers.length });
        try {
            const scope = await this.getPrestageScope(prestageId);
            const existing: string[] = (scope.assignments ?? []).map((a: any) => a.serialNumber);
            const versionLock = scope.versionLock;

            const normalized = serialNumbers.map((s) => s.trim().toUpperCase()).filter(Boolean);
            const alreadyScoped = normalized.filter((s) => existing.includes(s));
            const toAdd = normalized.filter((s) => !existing.includes(s));

            if (toAdd.length === 0) {
                this.logger.info('No new serials to add', { prestageId });
                return { success: true, prestageId, prestageName: displayName, added: [], alreadyScoped, totalScoped: existing.length };
            }

            const merged = [...existing, ...toAdd];
            const apiStart = Date.now();
            const response = await this.client.put(`/api/v2/computer-prestages/${prestageId}/scope`, {
                serialNumbers: merged,
                versionLock,
            });
            logApiCall(this.logger, 'PUT', `/api/v2/computer-prestages/${prestageId}/scope`, response.status, Date.now() - apiStart);

            this.logger.info('Serials assigned to prestage', { prestageId, added: toAdd.length });
            return { success: true, prestageId, prestageName: displayName, added: toAdd, alreadyScoped, totalScoped: merged.length };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Prestage Assignments' permissions in JAMF Pro.`);
            }
            this.logger.error('Error assigning serials to prestage', { prestageId, error: (error as Error).message });
            throw error;
        }
    }

    public async getStaticComputerGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching static computer groups');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/computer-groups');
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
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computer Groups' permissions in JAMF Pro.`);
            }
            this.logger.error("Error fetching static computer groups", { error: (error as Error).message, stack: (error as Error).stack });
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
            const response = await this.client.get('/api/v3/computers-inventory', {
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
            const inventoryResponse = await this.client.get('/api/v3/computers-inventory', {
                params: { filter: `hardware.serialNumber=="${escapeRsqlValue(serial)}"`, 'page-size': 1 }
            });
            logApiCall(this.logger, 'GET', '/api/v3/computers-inventory', inventoryResponse.status, Date.now() - apiStart);
            const computerId = inventoryResponse.data.results?.[0]?.id;
            if (!computerId) return { totalCount: 0, results: [] };

            const apiStart2 = Date.now();
            const detailResponse = await this.client.get(`/api/v3/computers-inventory-detail/${computerId}`);
            logApiCall(this.logger, 'GET', `/api/v3/computers-inventory-detail/${computerId}`, detailResponse.status, Date.now() - apiStart2);
            this.logger.info('Computer by serial retrieved', { serial, computerId });
            return { totalCount: 1, results: [detailResponse.data] };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Computers' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching computer by serial', { serial, error: (error as Error).message });
            throw error;
        }
    }

    public async sendComputerMdmCommand(
        nameOrSerial: string,
        command: string,
        options?: { unlockUsername?: string; erasurePasscode?: string }
    ) {
        await this.ensureAuthenticated();
        this.logger.info('Sending MDM command', { nameOrSerial, command });
        try {
            const computerId = await this.resolveComputerId(nameOrSerial);
            let url = `/JSSResource/computercommands/command/${command}`;
            if (command === 'UnlockUserAccount' && options?.unlockUsername) {
                url += `/username/${encodeURIComponent(options.unlockUsername)}`;
            }
            url += `/id/${computerId}`;

            const body = command === 'EraseDevice' && options?.erasurePasscode
                ? { computer_command: { command: { passcode: options.erasurePasscode } } }
                : null;

            const apiStart = Date.now();
            const response = await this.client.post(url, body);
            logApiCall(this.logger, 'POST', url, response.status, Date.now() - apiStart);
            this.logger.info('MDM command sent successfully', { nameOrSerial, command, computerId });
            return { success: true, command, computerId };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Send Computer Remote Commands' permissions in JAMF Pro.`);
            }
            this.logger.error('Error sending MDM command', { nameOrSerial, command, error: (error as Error).message });
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
            throw error;
        }
    }

    public async getPolicies(name?: string, page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching policies', { name, page, pageSize });
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/JSSResource/policies', {
                headers: { Accept: 'application/json' }
            });
            logApiCall(this.logger, 'GET', '/JSSResource/policies', response.status, Date.now() - apiStart);
            let policies: any[] = response.data.policies ?? [];
            if (name) {
                const lower = name.toLowerCase();
                policies = policies.filter((p: any) => p.name?.toLowerCase().includes(lower));
            }
            const start = (page ?? 0) * (pageSize ?? 100);
            const paged = policies.slice(start, start + (pageSize ?? 100));
            this.logger.info('Policies retrieved', { total: policies.length, returned: paged.length });
            return { totalCount: policies.length, results: paged };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching policies', { error: (error as Error).message });
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
            throw error;
        }
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
    }) {
        await this.ensureAuthenticated();
        this.logger.info('Upserting policy', { name: params.name });
        try {
            const existing = await this.findPolicyByName(params.name);
            const [targetGroups, exclusionGroups, categoryId, scripts, packages] = await Promise.all([
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
            if (changes.enabled !== undefined) {
                partialPolicy.general = { enabled: changes.enabled };
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

            this.logger.info('Policy scope updated', { id, name });
            return {
                success: true,
                id,
                name,
                enabled: changes.enabled !== undefined ? changes.enabled : current.general.enabled,
                targetGroups: mergedTargets.map((g: any) => g.name),
                exclusionGroups: mergedExclusions.map((g: any) => g.name),
            };
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Update Policies' permissions in JAMF Pro.`);
            }
            this.logger.error('Error updating policy scope', { id, error: (error as Error).message });
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
            const response = await this.client.get('/api/v1/cloud-idp', {
                params: { 'page-size': 200 }
            });
            logApiCall(this.logger, 'GET', '/api/v1/cloud-idp', response.status, Date.now() - apiStart);
            return response.data;
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                throw new Error(`Permission denied (403). The API client may be missing 'Read User' (Cloud Identity Provider) permissions in JAMF Pro.`);
            }
            this.logger.error('Error fetching Cloud Identity Providers', { error: (error as Error).message });
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
            throw error;
        }
    }

    public async getDepartments() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching departments');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/departments', {
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
            throw error;
        }
    }

    public async getCategories(page?: number, pageSize?: number) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching categories');
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v1/categories', {
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
            throw error;
        }
    }

    public async getFilevaultStatus(nameOrSerial: string) {
        await this.ensureAuthenticated();
        this.logger.info('Fetching FileVault status', { nameOrSerial });
        try {
            const apiStart = Date.now();
            const response = await this.client.get('/api/v3/computers-inventory', {
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
            throw error;
        }
    }
}
