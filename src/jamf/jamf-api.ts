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
            // Using Jamf Pro API v2 (fetching all and filtering locally as v2 doesn't support filter param yet)
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

            if (foundDevice) {
                this.logger.info('Mobile device found', { deviceName: name });
                return {
                    totalCount: 1,
                    results: [foundDevice]
                };
            } else {
                this.logger.warn('Mobile device not found', { deviceName: name });
                return {
                    totalCount: 0,
                    results: []
                };
            }
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.status === 403) {
                this.logger.error('Permission denied fetching mobile device', { deviceName: name });
                throw new Error(`Permission denied (403). The API client may be missing 'Read Mobile Devices' permissions in JAMF Pro.`);
            }
            this.logger.error(`Error fetching mobile device ${name}`, { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    public async getSmartComputerGroups() {
        await this.ensureAuthenticated();
        this.logger.info('Fetching smart computer groups');
        try {
            // Using Jamf Pro API v2
            const apiStart = Date.now();
            const response = await this.client.get('/api/v2/computer-groups/smart-groups');
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/api/v2/computer-groups/smart-groups', response.status, apiDuration);
            this.logger.info('Smart computer groups retrieved successfully');
            return response.data;
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
            
            // Client-side filtering by name if provided (case-insensitive substring match)
            let scripts = response.data.scripts || [];
            if (name) {
                const nameLower = name.toLowerCase();
                scripts = scripts.filter((script: any) => 
                    script.name && script.name.toLowerCase().includes(nameLower)
                );
            }
            
            this.logger.info('Scripts retrieved successfully', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100, filteredCount: scripts.length, totalInPage: response.data.scripts?.length || 0 });
            return {
                ...response.data,
                scripts: scripts
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
            
            // Client-side filtering by name if provided (case-insensitive substring match)
            let packages = response.data.packages || [];
            if (name) {
                const nameLower = name.toLowerCase();
                packages = packages.filter((pkg: any) => 
                    pkg.name && pkg.name.toLowerCase().includes(nameLower)
                );
            }
            
            this.logger.info('Packages retrieved successfully', { name: name || '(all)', page: page || 0, pageSize: pageSize || 100, filteredCount: packages.length, totalInPage: response.data.packages?.length || 0 });
            return {
                ...response.data,
                packages: packages
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
