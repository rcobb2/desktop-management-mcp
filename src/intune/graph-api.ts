import { Client } from "@microsoft/microsoft-graph-client";
import { TokenCredentialAuthenticationProvider } from "@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials";
import { ClientSecretCredential } from "@azure/identity";
import { createLogger, logApiCall } from '../utils/logger.js';
import yauzl from 'yauzl';

// ─── .intunewin package parsing ─────────────────────────────────────────────
// A .intunewin file (produced by Microsoft's Win32 Content Prep Tool) is a ZIP
// containing Metadata/Detection.xml (encryption parameters + the unencrypted
// setup file's metadata, as simple flat XML elements — confirmed against
// several independent writeups of the format) and a Contents/ directory with
// exactly one file: the actual installer payload, AES-256-CBC encrypted with
// an HMAC-SHA256 MAC, using the key material recorded in Detection.xml.

interface IntunewinEncryptionInfo {
    encryptionKey: string;
    macKey: string;
    initializationVector: string;
    mac: string;
    profileIdentifier: string;
    fileDigest: string;
    fileDigestAlgorithm: string;
}

interface ParsedIntunewinPackage {
    setupFileName: string;
    unencryptedContentSize: number;
    encryptionInfo: IntunewinEncryptionInfo;
    encryptedContent: Buffer;
}

function extractDetectionXmlTag(xml: string, tag: string): string {
    const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
    if (!match) throw new Error(`.intunewin package's Detection.xml is missing required element <${tag}> — is this a valid Win32 Content Prep Tool package?`);
    return match[1].trim();
}

function readIntunewinZipEntries(buffer: Buffer): Promise<{ detectionXml?: Buffer; content?: Buffer }> {
    return new Promise((resolve, reject) => {
        yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
            if (err || !zipfile) return reject(err ?? new Error('Failed to open .intunewin as a zip archive'));
            const result: { detectionXml?: Buffer; content?: Buffer } = {};
            zipfile.on('error', reject);
            zipfile.readEntry();
            zipfile.on('entry', (entry) => {
                const isDir = /\/$/.test(entry.fileName);
                const isDetection = /Metadata\/Detection\.xml$/i.test(entry.fileName);
                const isContent = /^Contents\//i.test(entry.fileName) && !isDir;
                if (isDir || (!isDetection && !isContent)) {
                    zipfile.readEntry();
                    return;
                }
                zipfile.openReadStream(entry, (err2, stream) => {
                    if (err2 || !stream) return reject(err2 ?? new Error(`Failed to read zip entry ${entry.fileName}`));
                    const chunks: Buffer[] = [];
                    stream.on('data', (c) => chunks.push(c));
                    stream.on('end', () => {
                        const data = Buffer.concat(chunks);
                        if (isDetection) result.detectionXml = data;
                        if (isContent) result.content = data;
                        zipfile.readEntry();
                    });
                    stream.on('error', reject);
                });
            });
            zipfile.on('end', () => resolve(result));
        });
    });
}

async function parseIntunewinPackage(buffer: Buffer): Promise<ParsedIntunewinPackage> {
    const entries = await readIntunewinZipEntries(buffer);
    if (!entries.detectionXml) {
        throw new Error('.intunewin package is missing Metadata/Detection.xml — is this a valid Win32 Content Prep Tool package?');
    }
    if (!entries.content) {
        throw new Error('.intunewin package is missing its Contents/ payload.');
    }
    const xml = entries.detectionXml.toString('utf8');
    return {
        setupFileName: extractDetectionXmlTag(xml, 'SetupFile'),
        unencryptedContentSize: parseInt(extractDetectionXmlTag(xml, 'UnencryptedContentSize'), 10),
        encryptionInfo: {
            encryptionKey: extractDetectionXmlTag(xml, 'EncryptionKey'),
            macKey: extractDetectionXmlTag(xml, 'MacKey'),
            initializationVector: extractDetectionXmlTag(xml, 'InitializationVector'),
            mac: extractDetectionXmlTag(xml, 'Mac'),
            profileIdentifier: extractDetectionXmlTag(xml, 'ProfileIdentifier'),
            fileDigest: extractDetectionXmlTag(xml, 'FileDigest'),
            fileDigestAlgorithm: extractDetectionXmlTag(xml, 'FileDigestAlgorithm'),
        },
        encryptedContent: entries.content,
    };
}

export class IntuneClient {
    private client: Client;
    private credential: ClientSecretCredential;
    private readonly authScopes = ["https://graph.microsoft.com/.default"];
    private logger = createLogger('intune-api');

    constructor() {
        const tenantId = process.env.AZURE_TENANT_ID ?? '';
        const clientId = process.env.AZURE_CLIENT_ID ?? '';
        const clientSecret = process.env.AZURE_CLIENT_SECRET ?? '';

        if (!tenantId || !clientId || !clientSecret) {
            throw new Error('AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set as environment variables or App Settings.');
        }

        this.credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
        const authProvider = new TokenCredentialAuthenticationProvider(this.credential, {
            scopes: this.authScopes,
        });

        this.client = Client.initWithMiddleware({
            debugLogging: false, // Turn off unless debugging
            authProvider,
        });
    }

    private async trackAuthAttempt(): Promise<void> {
        try {
            await this.credential.getToken(this.authScopes);
        } catch (error) {
            this.logger.error('Failed to authenticate with Intune', { error: (error as Error).message });
            throw error;
        }
    }

    private escapeODataString(value: string): string {
        return value.replace(/'/g, "''");
    }

    /**
     * ROBUST STRATEGY:
     * 1. Search v1.0 (Stable filter) to get the ID.
     * 2. Fetch Beta (Rich data) using that ID to get the profile.
     */
    public async getAutopilotProfileStatus(serialNumber: string) {
        this.logger.info('Fetching Autopilot profile status', { serialNumber });
        await this.trackAuthAttempt();
        let deviceId: string | null = null;

        try {
            // STEP 1: Find the ID using v1.0 (Try server-side filter first)
            const apiStart = Date.now();
            const lookupResponse = await this.client
                .api('/deviceManagement/windowsAutopilotDeviceIdentities')
                .version('v1.0') // Explicitly use v1.0 for stability
                .filter(`serialNumber eq '${this.escapeODataString(serialNumber)}'`)
                .select('id,serialNumber') // Fetch only what we need
                .get();
            
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/windowsAutopilotDeviceIdentities', 200, apiDuration);

            if (lookupResponse.value && lookupResponse.value.length > 0) {
                deviceId = lookupResponse.value[0].id;
            }
        } catch (error) {
            this.logger.warn(`Server-side filter failed for serial number ${serialNumber}. Attempting client-side filtering...`, { error: (error as Error).message });
            // Fallback: Fetch a batch and filter client-side
            try {
                // We use Beta here because v1.0 was throwing 500 errors even for basic listing in some cases.
                // We also avoid .select() to minimize potential parsing issues on the backend.
                const apiStart = Date.now();
                const fallbackResponse = await this.client
                    .api('/deviceManagement/windowsAutopilotDeviceIdentities')
                    .version('beta')
                    .top(500) // Beta seems responsive, fetch a reasonable batch
                    .get();
                
                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', '/deviceManagement/windowsAutopilotDeviceIdentities (fallback)', 200, apiDuration);

                // Case-insensitive comparison
                const found = fallbackResponse.value?.find((d: any) => d.serialNumber && d.serialNumber.toLowerCase() === serialNumber.toLowerCase());
                if (found) {
                    deviceId = found.id;
                }
            } catch (fallbackError) {
                this.logger.error("Fallback search also failed", { error: (fallbackError as Error).message, stack: (fallbackError as Error).stack });
                logApiCall(this.logger, 'GET', '/deviceManagement/windowsAutopilotDeviceIdentities (fallback)', undefined, undefined, fallbackError as Error);
                throw error;
            }
        }

        if (!deviceId) {
            this.logger.warn(`Device with serial ${serialNumber} not found in Autopilot`, { serialNumber });
            return null;
        }

        try {
            // STEP 2: Use the ID to get the full object from Beta
            // The profile details are available via the 'deploymentProfile' navigation property
            const apiStart = Date.now();
            const fullDeviceProfile = await this.client
                .api(`/deviceManagement/windowsAutopilotDeviceIdentities/${deviceId}`)
                .version('beta') // Switch to Beta for the rich profile data
                .expand('deploymentProfile')
                .get();
            
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', `/deviceManagement/windowsAutopilotDeviceIdentities/${deviceId}`, 200, apiDuration);

            // Return a clean object with just the info we care about
            const result = {
                serialNumber: fullDeviceProfile.serialNumber,
                profileName: fullDeviceProfile.deploymentProfile?.displayName || "Not Assigned",
                profileStatus: fullDeviceProfile.deploymentProfileAssignmentStatus,
                userPrincipalName: fullDeviceProfile.userPrincipalName || "No User Assigned"
            };
            
            this.logger.info('Autopilot profile status retrieved successfully', { serialNumber, profileName: result.profileName });
            return result;

        } catch (error) {
            this.logger.error(`Error fetching Autopilot profile for ${serialNumber}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', `/deviceManagement/windowsAutopilotDeviceIdentities/${deviceId}`, undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Get managed device by device name
     */
    public async getManagedDeviceByName(deviceName: string) {
        const normalizedDeviceName = deviceName.trim();
        this.logger.info('Fetching managed device by name', { deviceName: normalizedDeviceName });
        await this.trackAuthAttempt();

        try {
            const escapedName = this.escapeODataString(normalizedDeviceName);

            // Try exact match first (fast path)
            const apiStart = Date.now();
            const response = await this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .filter(`deviceName eq '${escapedName}'`)
                .select('id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName')
                .get();
            
            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', 200, apiDuration);

            if (response.value && response.value.length > 0) {
                const device = response.value[0];
                this.logger.info('Device found by exact name', { deviceName: normalizedDeviceName, deviceId: device.id });
                return device;
            }

            // Fallback: prefix search on deviceName
            try {
                const prefixStart = Date.now();
                const prefixResponse = await this.client
                    .api('/deviceManagement/managedDevices')
                    .version('v1.0')
                    .filter(`startswith(deviceName,'${escapedName}')`)
                    .select('id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName')
                    .top(25)
                    .get();

                const prefixDuration = Date.now() - prefixStart;
                logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices (prefix)', 200, prefixDuration);

                const prefixMatches = prefixResponse.value || [];
                if (prefixMatches.length > 0) {
                    const exactCaseInsensitive = prefixMatches.find((d: any) => String(d.deviceName || '').toLowerCase() === normalizedDeviceName.toLowerCase());
                    const best = exactCaseInsensitive || prefixMatches[0];
                    this.logger.info('Device found by prefix name search', {
                        deviceName: normalizedDeviceName,
                        matchedDeviceName: best.deviceName,
                        deviceId: best.id
                    });
                    return best;
                }
            } catch (prefixError) {
                this.logger.warn('Prefix device search failed; continuing with client-side fallback', {
                    deviceName: normalizedDeviceName,
                    error: (prefixError as Error).message
                });
            }

            // Final fallback: fetch a larger page and perform client-side contains/exact matching
            const fallbackStart = Date.now();
            const fallbackResponse = await this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .select('id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName')
                .top(999)
                .get();

            const fallbackDuration = Date.now() - fallbackStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices (client-fallback)', 200, fallbackDuration);

            const devices = fallbackResponse.value || [];
            const lowerName = normalizedDeviceName.toLowerCase();
            const exactClient = devices.find((device: any) => String(device.deviceName || '').toLowerCase() === lowerName);
            if (exactClient) {
                this.logger.info('Device found by client-side exact fallback', {
                    deviceName: normalizedDeviceName,
                    deviceId: exactClient.id
                });
                return exactClient;
            }

            const containsClient = devices.find((device: any) => String(device.deviceName || '').toLowerCase().includes(lowerName));
            if (containsClient) {
                this.logger.info('Device found by client-side contains fallback', {
                    deviceName: normalizedDeviceName,
                    matchedDeviceName: containsClient.deviceName,
                    deviceId: containsClient.id
                });
                return containsClient;
            }

            this.logger.warn('Device not found by name', { deviceName: normalizedDeviceName });
            return null;

        } catch (error) {
            this.logger.error(`Error fetching device by name ${normalizedDeviceName}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Get managed device by serial number.
     */
    public async getManagedDeviceBySerialNumber(serialNumber: string) {
        const normalizedSerial = serialNumber.trim();
        this.logger.info('Fetching managed device by serial number', { serialNumber: normalizedSerial });
        await this.trackAuthAttempt();

        try {
            const escapedSerial = this.escapeODataString(normalizedSerial);

            const apiStart = Date.now();
            const response = await this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .filter(`serialNumber eq '${escapedSerial}'`)
                .select('id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName')
                .get();

            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', 200, apiDuration);

            if (response.value && response.value.length > 0) {
                const device = response.value[0];
                this.logger.info('Device found by exact serial number', { serialNumber: normalizedSerial, deviceId: device.id });
                return device;
            }

            const fallbackStart = Date.now();
            const fallbackResponse = await this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .select('id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName')
                .top(999)
                .get();

            const fallbackDuration = Date.now() - fallbackStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices (serial-fallback)', 200, fallbackDuration);

            const lowerSerial = normalizedSerial.toLowerCase();
            const matches = (fallbackResponse.value || []).find((device: any) => String(device.serialNumber || '').toLowerCase() === lowerSerial);
            if (matches) {
                this.logger.info('Device found by serial fallback', { serialNumber: normalizedSerial, deviceId: matches.id });
                return matches;
            }

            this.logger.warn('Device not found by serial number', { serialNumber: normalizedSerial });
            return null;
        } catch (error) {
            this.logger.error(`Error fetching device by serial number ${normalizedSerial}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Get managed devices by primary user (UPN, email, or display name)
     */
    public async getManagedDevicesByUser(userIdentifier: string) {
        const normalizedUserIdentifier = userIdentifier.trim();
        this.logger.info('Fetching managed devices by user', { userIdentifier: normalizedUserIdentifier });
        await this.trackAuthAttempt();

        try {
            const escapedIdentifier = this.escapeODataString(normalizedUserIdentifier);

            const candidateUpns: string[] = [];
            if (normalizedUserIdentifier.includes('@')) {
                candidateUpns.push(normalizedUserIdentifier);
            }

            // Resolve identifier against Entra users for robust short-name/full-name/email handling.
            try {
                const userLookupStart = Date.now();
                const userResponse = await this.client
                    .api('/users')
                    .version('v1.0')
                    .filter(
                        `userPrincipalName eq '${escapedIdentifier}' or mail eq '${escapedIdentifier}' or mailNickname eq '${escapedIdentifier}' or displayName eq '${escapedIdentifier}'`
                    )
                    .select('userPrincipalName,displayName,mail,mailNickname')
                    .top(25)
                    .get();

                const userLookupDuration = Date.now() - userLookupStart;
                logApiCall(this.logger, 'GET', '/users', 200, userLookupDuration);

                const users = userResponse.value || [];
                for (const user of users) {
                    if (user.userPrincipalName) {
                        candidateUpns.push(user.userPrincipalName);
                    }
                }

                // If short username was provided, try startswith on UPN/mail for alias-style matches.
                if (!normalizedUserIdentifier.includes('@')) {
                    try {
                        const prefixStart = Date.now();
                        const prefixResponse = await this.client
                            .api('/users')
                            .version('v1.0')
                            .filter(`startswith(userPrincipalName,'${escapedIdentifier}@') or startswith(mail,'${escapedIdentifier}@')`)
                            .select('userPrincipalName')
                            .top(25)
                            .get();

                        const prefixDuration = Date.now() - prefixStart;
                        logApiCall(this.logger, 'GET', '/users (prefix)', 200, prefixDuration);

                        for (const user of prefixResponse.value || []) {
                            if (user.userPrincipalName) {
                                candidateUpns.push(user.userPrincipalName);
                            }
                        }
                    } catch (prefixUserError) {
                        this.logger.warn('Prefix-based user resolution failed', {
                            userIdentifier: normalizedUserIdentifier,
                            error: (prefixUserError as Error).message
                        });
                    }
                }
            } catch (userError) {
                this.logger.warn('User directory lookup failed; continuing with managed-device fallback', {
                    userIdentifier: normalizedUserIdentifier,
                    error: (userError as Error).message
                });
            }

            const dedupedCandidateUpns = Array.from(new Set(candidateUpns.filter(Boolean).map((upn) => String(upn).toLowerCase())));
            const deviceFields = 'id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName';

            for (const upnLower of dedupedCandidateUpns) {
                const escapedUpn = this.escapeODataString(upnLower);
                const apiStart = Date.now();
                const deviceResponse = await this.client
                    .api('/deviceManagement/managedDevices')
                    .version('v1.0')
                    .filter(`userPrincipalName eq '${escapedUpn}'`)
                    .select(deviceFields)
                    .top(999)
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', 200, apiDuration);

                const devices = deviceResponse.value || [];
                if (devices.length > 0) {
                    this.logger.info('Devices retrieved for resolved user identifier', {
                        userIdentifier: normalizedUserIdentifier,
                        resolvedUserPrincipalName: upnLower,
                        deviceCount: devices.length
                    });
                    return devices;
                }
            }

            // Final fallback: client-side match against managed device userPrincipalName for short usernames.
            const fallbackStart = Date.now();
            const allDevicesResponse = await this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .select(deviceFields)
                .top(999)
                .get();

            const fallbackDuration = Date.now() - fallbackStart;
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices (user-fallback)', 200, fallbackDuration);

            const allDevices = allDevicesResponse.value || [];
            const lowerIdentifier = normalizedUserIdentifier.toLowerCase();
            const clientSideMatches = allDevices.filter((device: any) => {
                const upn = String(device.userPrincipalName || '').toLowerCase();
                if (!upn) {
                    return false;
                }
                if (upn === lowerIdentifier) {
                    return true;
                }
                if (!normalizedUserIdentifier.includes('@') && upn.startsWith(`${lowerIdentifier}@`)) {
                    return true;
                }
                return false;
            });

            this.logger.info('Devices retrieved using user fallback matching', {
                userIdentifier: normalizedUserIdentifier,
                deviceCount: clientSideMatches.length
            });

            return clientSideMatches;

        } catch (error) {
            this.logger.error(`Error fetching devices by user ${normalizedUserIdentifier}`, { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * managementAgent values (confirmed against a live tenant) that mean the device is actually
     * enrolled/managed via Intune MDM, as opposed to merely appearing in Intune's device inventory
     * because of e.g. Defender for Endpoint sensor reporting (`msSense`) or ConfigMgr-only management
     * (`configurationManagerClient` with no MDM component) — those show up in /managedDevices too but
     * aren't Intune-managed, so a raw device count without this distinction overstates the Intune fleet.
     */
    private static readonly INTUNE_MANAGED_AGENTS = new Set([
        'mdm',
        'easmdm',
        'intuneclient',
        'easintuneclient',
        'configurationmanagerclientmdm',
        'configurationmanagerclientmdmeas',
        'microsoft365managedmdm',
        'intuneaosp'
    ]);

    /**
     * List managed devices tenant-wide, optionally filtered by OS, compliance state, management
     * state, or management agent. Follows @odata.nextLink to page through the full result set (up
     * to a safety cap) so counts reflect the whole fleet rather than a single page of up to 999.
     */
    public async listManagedDevices(options?: {
        operatingSystem?: string;
        complianceState?: string;
        managementState?: string;
        managementAgent?: string;
        intuneManagedOnly?: boolean;
    }) {
        this.logger.info('Listing managed devices', options ?? {});
        await this.trackAuthAttempt();

        const MAX_PAGES = 20; // 20 * 999 ≈ 20k devices — far above any real fleet size here
        const deviceFields = 'id,deviceName,serialNumber,userPrincipalName,azureADDeviceId,managementState,managementAgent,complianceState,lastSyncDateTime,model,manufacturer,operatingSystem,osVersion,enrolledDateTime,userDisplayName';

        const filters: string[] = [];
        if (options?.operatingSystem) {
            filters.push(`operatingSystem eq '${this.escapeODataString(options.operatingSystem)}'`);
        }
        if (options?.complianceState) {
            filters.push(`complianceState eq '${this.escapeODataString(options.complianceState)}'`);
        }
        if (options?.managementState) {
            filters.push(`managementState eq '${this.escapeODataString(options.managementState)}'`);
        }
        if (options?.managementAgent) {
            filters.push(`managementAgent eq '${this.escapeODataString(options.managementAgent)}'`);
        }

        try {
            let request = this.client
                .api('/deviceManagement/managedDevices')
                .version('v1.0')
                .select(deviceFields)
                .top(999);

            if (filters.length > 0) {
                request = request.filter(filters.join(' and '));
            }

            const devices: any[] = [];
            let apiStart = Date.now();
            let response = await request.get();
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', 200, Date.now() - apiStart);
            devices.push(...(response.value || []));

            let page = 1;
            while (response['@odata.nextLink'] && page < MAX_PAGES) {
                apiStart = Date.now();
                response = await this.client.api(response['@odata.nextLink']).get();
                logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices (nextLink)', 200, Date.now() - apiStart);
                devices.push(...(response.value || []));
                page++;
            }

            const truncated = Boolean(response['@odata.nextLink']);
            if (truncated) {
                this.logger.warn('listManagedDevices hit the pagination safety cap; results are truncated', {
                    pagesFetched: page,
                    deviceCount: devices.length
                });
            }

            const filteredDevices = options?.intuneManagedOnly
                ? devices.filter((d: any) => IntuneClient.INTUNE_MANAGED_AGENTS.has(String(d.managementAgent ?? '').toLowerCase()))
                : devices;

            this.logger.info('Managed devices listed', {
                count: filteredDevices.length,
                rawCount: devices.length,
                intuneManagedOnly: Boolean(options?.intuneManagedOnly),
                truncated
            });
            return { devices: filteredDevices, totalCount: filteredDevices.length, truncated };
        } catch (error) {
            this.logger.error('Error listing managed devices', { error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', '/deviceManagement/managedDevices', undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Resolve a group name to its Entra ID GUID via a displayName filter (exact match
     * preferred, first partial match as fallback) — mirrors resolveAppByName/
     * resolvePolicyByName's name-resolution convention in intune-server.ts. A value
     * that already looks like a GUID is returned as-is without a lookup.
     */
    private async resolveGroupId(groupNameOrId: string): Promise<{ id: string; displayName: string } | null> {
        const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (GUID_RE.test(groupNameOrId)) {
            const apiStart = Date.now();
            const group = await this.client
                .api(`/groups/${groupNameOrId}`)
                .version('v1.0')
                .select('id,displayName')
                .get();
            logApiCall(this.logger, 'GET', `/groups/${groupNameOrId}`, 200, Date.now() - apiStart);
            return { id: group.id, displayName: group.displayName };
        }

        const apiStart = Date.now();
        const response = await this.client
            .api('/groups')
            .version('v1.0')
            .filter(`displayName eq '${this.escapeODataString(groupNameOrId)}'`)
            .select('id,displayName')
            .get();
        logApiCall(this.logger, 'GET', '/groups', 200, Date.now() - apiStart);

        let matches: any[] = response.value || [];
        if (matches.length === 0) {
            const searchStart = Date.now();
            const searchResponse = await this.client
                .api('/groups')
                .version('v1.0')
                .filter(`startswith(displayName,'${this.escapeODataString(groupNameOrId)}')`)
                .select('id,displayName')
                .get();
            logApiCall(this.logger, 'GET', '/groups (startswith)', 200, Date.now() - searchStart);
            matches = searchResponse.value || [];
        }
        if (matches.length === 0) return null;

        const lower = groupNameOrId.toLowerCase();
        const exact = matches.find((g: any) => String(g.displayName ?? '').toLowerCase() === lower);
        const match = exact ?? matches[0];
        return { id: match.id, displayName: match.displayName };
    }

    /**
     * List the members of an Entra ID group by name or GUID — the Intune-side
     * analogue of confirming whether an assignment group actually resolves to real
     * members before/after assigning an app or policy to it. Follows @odata.nextLink
     * the same way listManagedDevices does, up to a safety cap.
     */
    public async getGroupMembers(groupNameOrId: string) {
        this.logger.info('Fetching group members', { groupNameOrId });
        await this.trackAuthAttempt();

        const group = await this.resolveGroupId(groupNameOrId);
        if (!group) {
            return { group: null, members: [], totalCount: 0, truncated: false };
        }

        const MAX_PAGES = 20; // 20 * 999 ≈ 20k members — far above any real group size here
        const memberFields = 'id,displayName,userPrincipalName,mail,deviceId,operatingSystem';

        try {
            let apiStart = Date.now();
            let response = await this.client
                .api(`/groups/${group.id}/members`)
                .version('v1.0')
                .select(memberFields)
                .top(999)
                .get();
            logApiCall(this.logger, 'GET', `/groups/${group.id}/members`, 200, Date.now() - apiStart);

            const members: any[] = [...(response.value || [])];
            let page = 1;
            while (response['@odata.nextLink'] && page < MAX_PAGES) {
                apiStart = Date.now();
                response = await this.client.api(response['@odata.nextLink']).get();
                logApiCall(this.logger, 'GET', `/groups/${group.id}/members (nextLink)`, 200, Date.now() - apiStart);
                members.push(...(response.value || []));
                page++;
            }

            const truncated = Boolean(response['@odata.nextLink']);
            if (truncated) {
                this.logger.warn('getGroupMembers hit the pagination safety cap; results are truncated', {
                    groupId: group.id,
                    pagesFetched: page,
                    memberCount: members.length
                });
            }

            const typedMembers = members.map((m: any) => ({
                id: m.id,
                displayName: m.displayName,
                type: String(m['@odata.type'] || '').split('.').pop() || 'unknown',
                userPrincipalName: m.userPrincipalName,
                mail: m.mail,
                deviceId: m.deviceId,
                operatingSystem: m.operatingSystem,
            }));

            this.logger.info('Group members listed', { groupId: group.id, count: typedMembers.length, truncated });
            return { group, members: typedMembers, totalCount: typedMembers.length, truncated };
        } catch (error) {
            this.logger.error('Error listing group members', { groupId: group.id, error: (error as Error).message, stack: (error as Error).stack });
            logApiCall(this.logger, 'GET', `/groups/${group.id}/members`, undefined, undefined, error as Error);
            throw error;
        }
    }

    /**
     * Get group memberships for a device (both Azure AD groups and Intune device categories)
     */
    public async getDeviceGroupMemberships(deviceId: string, azureADDeviceId?: string) {
        this.logger.info('Fetching device group memberships', { deviceId, azureADDeviceId });
        await this.trackAuthAttempt();
        const result: any = {
            intuneCategories: [],
            azureADGroups: []
        };

        try {
            // Get Intune device categories
            try {
                const apiStart = Date.now();
                const categoriesResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}`)
                    .version('v1.0')
                    .select('id,deviceName,deviceCategory')
                    .expand('deviceCategory')
                    .get();
                
                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}`, 200, apiDuration);

                if (categoriesResponse.deviceCategory) {
                    result.intuneCategories = Array.isArray(categoriesResponse.deviceCategory) 
                        ? categoriesResponse.deviceCategory 
                        : [categoriesResponse.deviceCategory];
                }
                this.logger.info('Intune device categories retrieved', { deviceId, categoryCount: result.intuneCategories.length });
            } catch (error) {
                this.logger.warn('Failed to fetch Intune device categories', { deviceId, error: (error as Error).message });
            }

            // Get Azure AD group memberships if azureADDeviceId is provided
            if (azureADDeviceId) {
                try {
                    const apiStart = Date.now();
                    const groupsResponse = await this.client
                        .api(`/devices/${azureADDeviceId}/memberOf`)
                        .version('v1.0')
                        .select('id,displayName,mail,description,mailEnabled,securityEnabled')
                        .get();
                    
                    const apiDuration = Date.now() - apiStart;
                    logApiCall(this.logger, 'GET', `/devices/${azureADDeviceId}/memberOf`, 200, apiDuration);

                    result.azureADGroups = groupsResponse.value || [];
                    this.logger.info('Azure AD group memberships retrieved', { azureADDeviceId, groupCount: result.azureADGroups.length });
                } catch (error) {
                    this.logger.warn('Failed to fetch Azure AD group memberships', { azureADDeviceId, error: (error as Error).message });
                }
            }

            return result;

        } catch (error) {
            this.logger.error(`Error fetching group memberships for device ${deviceId}`, { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    /**
     * Get applications assigned to and detected on a device
     */
    public async getDeviceApplications(deviceId: string) {
        this.logger.info('Fetching device applications', { deviceId });
        await this.trackAuthAttempt();
        const result: any = {
            detectedApps: [],
            assignedApps: []
        };

        try {
            // Get detected/installed apps on device
            try {
                const apiStart = Date.now();
                const detectedAppsResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}/detectedApps`)
                    .version('v1.0')
                    .select('id,displayName,version,publisher,installState')
                    .top(999)
                    .get();
                
                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}/detectedApps`, 200, apiDuration);

                result.detectedApps = detectedAppsResponse.value || [];
                this.logger.info('Detected apps retrieved', { deviceId, appCount: result.detectedApps.length });
            } catch (error) {
                this.logger.warn('Failed to fetch detected apps', { deviceId, error: (error as Error).message });
            }

            // Get assigned mobile apps and their status for this device
            try {
                const apiStart = Date.now();
                const devicesResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}`)
                    .version('v1.0')
                    .select('id,deviceName')
                    .expand('mobileAppIntentAndStates')
                    .get();
                
                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}`, 200, apiDuration);

                if (devicesResponse.mobileAppIntentAndStates) {
                    result.assignedApps = devicesResponse.mobileAppIntentAndStates;
                    this.logger.info('Assigned apps retrieved', { deviceId, appCount: result.assignedApps.length });
                }
            } catch (error) {
                this.logger.warn('Failed to fetch assigned apps with status', { deviceId, error: (error as Error).message });
                
                // Fallback: Get all apps (without device-specific status)
                try {
                    const apiStart = Date.now();
                    const appsResponse = await this.client
                        .api('/deviceAppManagement/mobileApps')
                        .version('v1.0')
                        .select('id,displayName,publisher,description')
                        .top(999)
                        .get();
                    
                    const apiDuration = Date.now() - apiStart;
                    logApiCall(this.logger, 'GET', '/deviceAppManagement/mobileApps', 200, apiDuration);

                    result.assignedApps = appsResponse.value || [];
                    this.logger.info('All available apps retrieved (fallback)', { appCount: result.assignedApps.length });
                } catch (fallbackError) {
                    this.logger.warn('Failed to fetch any apps information', { deviceId, error: (fallbackError as Error).message });
                }
            }

            return result;

        } catch (error) {
            this.logger.error(`Error fetching applications for device ${deviceId}`, { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    /**
     * Get Intune configuration policies from both classic device configurations and settings catalog policies.
     */
    public async getConfigurationPolicies(options?: { policyName?: string; platform?: string }) {
        const policyName = options?.policyName?.trim().toLowerCase();
        const platform = options?.platform?.trim().toLowerCase();

        this.logger.info('Fetching configuration policies', { policyName: options?.policyName, platform: options?.platform });
        await this.trackAuthAttempt();

        const result: any = {
            classicDeviceConfigurations: [],
            settingsCatalogPolicies: [],
            combined: []
        };

        try {
            try {
                const apiStart = Date.now();
                const classicResponse = await this.client
                    .api('/deviceManagement/deviceConfigurations')
                    .version('v1.0')
                    .select('id,displayName,description,lastModifiedDateTime,createdDateTime')
                    .top(999)
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', '/deviceManagement/deviceConfigurations', 200, apiDuration);

                result.classicDeviceConfigurations = classicResponse.value || [];
            } catch (error) {
                this.logger.warn('Failed to fetch classic device configurations', { error: (error as Error).message });
            }

            try {
                const apiStart = Date.now();
                const settingsCatalogResponse = await this.client
                    .api('/deviceManagement/configurationPolicies')
                    .version('beta')
                    .select('id,name,description,platforms,technologies,lastModifiedDateTime,createdDateTime')
                    .top(999)
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', '/deviceManagement/configurationPolicies', 200, apiDuration);

                result.settingsCatalogPolicies = settingsCatalogResponse.value || [];
            } catch (error) {
                this.logger.warn('Failed to fetch settings catalog policies', { error: (error as Error).message });
            }

            const normalizedClassic = result.classicDeviceConfigurations.map((policy: any) => ({
                source: 'classic',
                id: policy.id,
                name: policy.displayName,
                description: policy.description,
                platforms: [],
                technologies: [],
                createdDateTime: policy.createdDateTime,
                lastModifiedDateTime: policy.lastModifiedDateTime
            }));

            const normalizedSettingsCatalog = result.settingsCatalogPolicies.map((policy: any) => ({
                source: 'settingsCatalog',
                id: policy.id,
                name: policy.name,
                description: policy.description,
                platforms: Array.isArray(policy.platforms) ? policy.platforms : [],
                technologies: Array.isArray(policy.technologies) ? policy.technologies : [],
                createdDateTime: policy.createdDateTime,
                lastModifiedDateTime: policy.lastModifiedDateTime
            }));

            let combined = [...normalizedClassic, ...normalizedSettingsCatalog];

            if (policyName) {
                combined = combined.filter((policy: any) => (policy.name || '').toLowerCase().includes(policyName));
            }

            if (platform) {
                combined = combined.filter((policy: any) => {
                    const platforms = Array.isArray(policy.platforms) ? policy.platforms : [];
                    return platforms.some((value: string) => value.toLowerCase().includes(platform));
                });
            }

            result.combined = combined;
            this.logger.info('Configuration policies retrieved', {
                totalClassic: normalizedClassic.length,
                totalSettingsCatalog: normalizedSettingsCatalog.length,
                filteredTotal: combined.length
            });

            return result;
        } catch (error) {
            this.logger.error('Error fetching configuration policies', { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    /**
     * Get deployment states for configuration and compliance policies on a managed device,
     * including conflict/error troubleshooting summaries.
     */
    public async getDevicePolicyDeploymentTroubleshooting(deviceId: string) {
        this.logger.info('Fetching policy deployment troubleshooting details', { deviceId });
        await this.trackAuthAttempt();

        const result: any = {
            device: null,
            configurationPolicyStates: [],
            compliancePolicyStates: [],
            issues: {
                configurationPolicies: [],
                compliancePolicies: []
            },
            summary: {
                totalConfigurationPolicies: 0,
                totalCompliancePolicies: 0,
                configurationIssues: 0,
                complianceIssues: 0,
                overallIssueCount: 0
            }
        };

        try {
            try {
                const apiStart = Date.now();
                const deviceResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}`)
                    .version('v1.0')
                    .select('id,deviceName,serialNumber,userPrincipalName,operatingSystem,osVersion,lastSyncDateTime,complianceState,managementState')
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}`, 200, apiDuration);

                result.device = deviceResponse;
            } catch (error) {
                this.logger.warn('Failed to fetch base device details for troubleshooting', { deviceId, error: (error as Error).message });
            }

            try {
                const apiStart = Date.now();
                const configStatesResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}/deviceConfigurationStates`)
                    .version('v1.0')
                    .top(999)
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}/deviceConfigurationStates`, 200, apiDuration);

                result.configurationPolicyStates = configStatesResponse.value || [];
            } catch (error) {
                this.logger.warn('Failed to fetch device configuration policy states', { deviceId, error: (error as Error).message });
            }

            try {
                const apiStart = Date.now();
                const complianceStatesResponse = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}/deviceCompliancePolicyStates`)
                    .version('v1.0')
                    .top(999)
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}/deviceCompliancePolicyStates`, 200, apiDuration);

                result.compliancePolicyStates = complianceStatesResponse.value || [];
            } catch (error) {
                this.logger.warn('Failed to fetch compliance policy states', { deviceId, error: (error as Error).message });
            }

            const issueKeywords = ['error', 'conflict'];
            const hasIssue = (value: string | undefined): boolean => {
                const normalized = (value || '').toLowerCase();
                return issueKeywords.some((keyword) => normalized.includes(keyword));
            };

            result.issues.configurationPolicies = result.configurationPolicyStates
                .filter((policyState: any) => hasIssue(policyState.state))
                .map((policyState: any) => ({
                    id: policyState.id,
                    displayName: policyState.displayName,
                    state: policyState.state,
                    errorCode: policyState.errorCode,
                    version: policyState.version,
                    userId: policyState.userId,
                    settingCount: Array.isArray(policyState.settingStates) ? policyState.settingStates.length : 0,
                    settingIssues: Array.isArray(policyState.settingStates)
                        ? policyState.settingStates.filter((setting: any) => hasIssue(setting.state)).map((setting: any) => ({
                            setting: setting.setting,
                            state: setting.state,
                            errorCode: setting.errorCode,
                            sources: setting.sources
                        }))
                        : []
                }));

            result.issues.compliancePolicies = result.compliancePolicyStates
                .filter((policyState: any) => hasIssue(policyState.state))
                .map((policyState: any) => ({
                    id: policyState.id,
                    displayName: policyState.displayName,
                    state: policyState.state,
                    userId: policyState.userId,
                    settingIssues: Array.isArray(policyState.settingStates)
                        ? policyState.settingStates.filter((setting: any) => hasIssue(setting.state)).map((setting: any) => ({
                            setting: setting.setting,
                            state: setting.state,
                            errorCode: setting.errorCode,
                            sources: setting.sources
                        }))
                        : []
                }));

            result.summary.totalConfigurationPolicies = result.configurationPolicyStates.length;
            result.summary.totalCompliancePolicies = result.compliancePolicyStates.length;
            result.summary.configurationIssues = result.issues.configurationPolicies.length;
            result.summary.complianceIssues = result.issues.compliancePolicies.length;
            result.summary.overallIssueCount = result.summary.configurationIssues + result.summary.complianceIssues;

            this.logger.info('Policy deployment troubleshooting completed', {
                deviceId,
                totalConfigurationPolicies: result.summary.totalConfigurationPolicies,
                totalCompliancePolicies: result.summary.totalCompliancePolicies,
                issueCount: result.summary.overallIssueCount
            });

            return result;
        } catch (error) {
            this.logger.error(`Error troubleshooting policy deployment for device ${deviceId}`, { error: (error as Error).message, stack: (error as Error).stack });
            throw error;
        }
    }

    /**
     * Get assignment targets for an Intune configuration policy.
     * Supports both classic device configurations and settings catalog policies.
     */
    public async getConfigurationPolicyAssignments(policyId: string, source?: 'classic' | 'settingsCatalog' | 'auto') {
        const effectiveSource = source || 'auto';
        this.logger.info('Fetching configuration policy assignments', { policyId, source: effectiveSource });
        await this.trackAuthAttempt();

        const result: any = {
            policy: null,
            source: null,
            assignments: [],
            resolvedTargets: [],
            summary: {
                totalAssignments: 0,
                includeAssignments: 0,
                excludeAssignments: 0,
                groupTargets: 0,
                allDevicesTargets: 0,
                allLicensedUsersTargets: 0
            }
        };

        const mapAssignment = (assignment: any) => {
            const target = assignment?.target || {};
            const targetType = String(target['@odata.type'] || '').toLowerCase();
            return {
                id: assignment.id,
                intent: assignment.intent,
                source: assignment.source,
                sourceId: assignment.sourceId,
                targetType: target['@odata.type'] || 'unknown',
                groupId: target.groupId,
                collectionId: target.collectionId,
                deviceAndAppManagementAssignmentFilterId: target.deviceAndAppManagementAssignmentFilterId,
                deviceAndAppManagementAssignmentFilterType: target.deviceAndAppManagementAssignmentFilterType,
                isExclude: targetType.includes('exclusion')
            };
        };

        const resolveTargetName = async (assignment: any) => {
            if (assignment.groupId) {
                try {
                    const apiStart = Date.now();
                    const group = await this.client
                        .api(`/groups/${assignment.groupId}`)
                        .version('v1.0')
                        .select('id,displayName,mailEnabled,securityEnabled,description')
                        .get();

                    const apiDuration = Date.now() - apiStart;
                    logApiCall(this.logger, 'GET', `/groups/${assignment.groupId}`, 200, apiDuration);

                    return {
                        assignmentId: assignment.id,
                        type: assignment.isExclude ? 'excludeGroup' : 'includeGroup',
                        id: group.id,
                        displayName: group.displayName,
                        description: group.description,
                        mailEnabled: group.mailEnabled,
                        securityEnabled: group.securityEnabled,
                        filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                        filterType: assignment.deviceAndAppManagementAssignmentFilterType
                    };
                } catch (error) {
                    this.logger.warn('Failed to resolve assignment group target', {
                        groupId: assignment.groupId,
                        error: (error as Error).message
                    });
                    return {
                        assignmentId: assignment.id,
                        type: assignment.isExclude ? 'excludeGroup' : 'includeGroup',
                        id: assignment.groupId,
                        displayName: null,
                        error: (error as Error).message,
                        filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                        filterType: assignment.deviceAndAppManagementAssignmentFilterType
                    };
                }
            }

            const targetType = String(assignment.targetType || '').toLowerCase();
            if (targetType.includes('alldevicesassignmenttarget')) {
                return {
                    assignmentId: assignment.id,
                    type: 'allDevices',
                    displayName: 'All Devices',
                    filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                    filterType: assignment.deviceAndAppManagementAssignmentFilterType
                };
            }

            if (targetType.includes('alllicensedusersassignmenttarget')) {
                return {
                    assignmentId: assignment.id,
                    type: 'allLicensedUsers',
                    displayName: 'All Licensed Users',
                    filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                    filterType: assignment.deviceAndAppManagementAssignmentFilterType
                };
            }

            return {
                assignmentId: assignment.id,
                type: 'other',
                displayName: assignment.targetType
            };
        };

        try {
            const tryClassic = effectiveSource === 'classic' || effectiveSource === 'auto';
            const trySettingsCatalog = effectiveSource === 'settingsCatalog' || effectiveSource === 'auto';

            if (tryClassic) {
                try {
                    const apiStart = Date.now();
                    const policy = await this.client
                        .api(`/deviceManagement/deviceConfigurations/${policyId}`)
                        .version('v1.0')
                        .select('id,displayName,description,lastModifiedDateTime,createdDateTime')
                        .get();

                    const apiDuration = Date.now() - apiStart;
                    logApiCall(this.logger, 'GET', `/deviceManagement/deviceConfigurations/${policyId}`, 200, apiDuration);

                    const assignmentsStart = Date.now();
                    const assignmentsResponse = await this.client
                        .api(`/deviceManagement/deviceConfigurations/${policyId}/assignments`)
                        .version('v1.0')
                        .top(999)
                        .get();

                    const assignmentsDuration = Date.now() - assignmentsStart;
                    logApiCall(this.logger, 'GET', `/deviceManagement/deviceConfigurations/${policyId}/assignments`, 200, assignmentsDuration);

                    result.policy = {
                        id: policy.id,
                        name: policy.displayName,
                        description: policy.description,
                        createdDateTime: policy.createdDateTime,
                        lastModifiedDateTime: policy.lastModifiedDateTime
                    };
                    result.source = 'classic';
                    result.assignments = (assignmentsResponse.value || []).map(mapAssignment);
                } catch (error) {
                    if (effectiveSource === 'classic') {
                        throw error;
                    }
                    this.logger.info('Classic policy lookup failed, trying settings catalog policy endpoint', {
                        policyId,
                        error: (error as Error).message
                    });
                }
            }

            if (!result.policy && trySettingsCatalog) {
                const apiStart = Date.now();
                const policy = await this.client
                    .api(`/deviceManagement/configurationPolicies/${policyId}`)
                    .version('beta')
                    .select('id,name,description,platforms,technologies,lastModifiedDateTime,createdDateTime')
                    .get();

                const apiDuration = Date.now() - apiStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/configurationPolicies/${policyId}`, 200, apiDuration);

                const assignmentsStart = Date.now();
                const assignmentsResponse = await this.client
                    .api(`/deviceManagement/configurationPolicies/${policyId}/assignments`)
                    .version('beta')
                    .top(999)
                    .get();

                const assignmentsDuration = Date.now() - assignmentsStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/configurationPolicies/${policyId}/assignments`, 200, assignmentsDuration);

                result.policy = {
                    id: policy.id,
                    name: policy.name,
                    description: policy.description,
                    platforms: policy.platforms,
                    technologies: policy.technologies,
                    createdDateTime: policy.createdDateTime,
                    lastModifiedDateTime: policy.lastModifiedDateTime
                };
                result.source = 'settingsCatalog';
                result.assignments = (assignmentsResponse.value || []).map(mapAssignment);
            }

            if (!result.policy) {
                throw new Error(`Policy '${policyId}' was not found in classic device configurations or settings catalog policies.`);
            }

            const resolvedTargets = [];
            for (const assignment of result.assignments) {
                resolvedTargets.push(await resolveTargetName(assignment));
            }
            result.resolvedTargets = resolvedTargets;

            result.summary.totalAssignments = result.assignments.length;
            result.summary.includeAssignments = result.assignments.filter((assignment: any) => !assignment.isExclude).length;
            result.summary.excludeAssignments = result.assignments.filter((assignment: any) => assignment.isExclude).length;
            result.summary.groupTargets = result.assignments.filter((assignment: any) => !!assignment.groupId).length;
            result.summary.allDevicesTargets = result.assignments.filter((assignment: any) => String(assignment.targetType || '').toLowerCase().includes('alldevicesassignmenttarget')).length;
            result.summary.allLicensedUsersTargets = result.assignments.filter((assignment: any) => String(assignment.targetType || '').toLowerCase().includes('alllicensedusersassignmenttarget')).length;

            this.logger.info('Configuration policy assignments retrieved', {
                policyId,
                source: result.source,
                assignmentCount: result.summary.totalAssignments
            });

            return result;
        } catch (error) {
            this.logger.error('Error fetching configuration policy assignments', {
                policyId,
                source: effectiveSource,
                error: (error as Error).message,
                stack: (error as Error).stack
            });
            throw error;
        }
    }

    /**
     * Correlate policy assignments and device deployment state to provide likely root causes
     * and targeted remediation suggestions.
     */
    public async getGuidedPolicyTroubleshooting(deviceId: string, policyId: string, source?: 'classic' | 'settingsCatalog' | 'auto') {
        this.logger.info('Running guided policy troubleshooting', { deviceId, policyId, source: source || 'auto' });
        await this.trackAuthAttempt();

        try {
            const deployment = await this.getDevicePolicyDeploymentTroubleshooting(deviceId);
            const assignments = await this.getConfigurationPolicyAssignments(policyId, source || 'auto');

            const allPolicyStates = [
                ...(deployment.configurationPolicyStates || []),
                ...(deployment.compliancePolicyStates || [])
            ];

            const matchingPolicyState = allPolicyStates.find((policyState: any) => {
                return policyState?.id === policyId || String(policyState?.displayName || '').toLowerCase() === String(assignments?.policy?.name || '').toLowerCase();
            }) || null;

            const findings: any[] = [];
            const recommendations: any[] = [];

            const hasAssignments = (assignments.summary?.totalAssignments || 0) > 0;
            if (!hasAssignments) {
                findings.push({
                    severity: 'high',
                    code: 'NO_ASSIGNMENTS',
                    message: 'The target policy currently has no assignments.'
                });
                recommendations.push({
                    priority: 'high',
                    action: 'Assign policy to a target',
                    details: 'Add at least one include assignment (group/all devices/all licensed users) so the policy can be evaluated on devices.'
                });
            }

            const hasIncludeTargets = (assignments.summary?.includeAssignments || 0) > 0;
            const hasExcludeTargets = (assignments.summary?.excludeAssignments || 0) > 0;
            if (!hasIncludeTargets && hasExcludeTargets) {
                findings.push({
                    severity: 'high',
                    code: 'ONLY_EXCLUDE_TARGETS',
                    message: 'The policy has exclude targets but no include targets.'
                });
                recommendations.push({
                    priority: 'high',
                    action: 'Add include targets',
                    details: 'Policies require include targets to apply; excludes only remove scope from existing includes.'
                });
            }

            const hasFilters = (assignments.assignments || []).some((assignment: any) => !!assignment.deviceAndAppManagementAssignmentFilterId);
            if (hasFilters) {
                findings.push({
                    severity: 'medium',
                    code: 'ASSIGNMENT_FILTERS_PRESENT',
                    message: 'Assignment filters are configured and can narrow or block policy scope on this device.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Validate assignment filters',
                    details: 'Confirm device properties satisfy include filters and do not match exclude filters for this policy.'
                });
            }

            if (!matchingPolicyState) {
                findings.push({
                    severity: 'medium',
                    code: 'NO_DEVICE_POLICY_STATE',
                    message: 'No matching policy state was found for this policy on the target device.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Force sync and re-check state',
                    details: 'Trigger an Intune sync on the device and verify membership in assigned include groups and absence from exclusion groups.'
                });
            } else {
                const state = String(matchingPolicyState.state || '').toLowerCase();
                const hasError = state.includes('error');
                const hasConflict = state.includes('conflict');
                const hasPending = state.includes('pending') || state.includes('notapplicable');

                if (hasError) {
                    findings.push({
                        severity: 'high',
                        code: 'DEVICE_POLICY_ERROR',
                        message: `Device reports policy state '${matchingPolicyState.state}'.`
                    });
                    recommendations.push({
                        priority: 'high',
                        action: 'Investigate policy error details',
                        details: 'Review setting-level errors and device-side MDM event logs to identify failing CSP/OMA-URI or unsupported configuration.'
                    });
                }

                if (hasConflict) {
                    findings.push({
                        severity: 'high',
                        code: 'DEVICE_POLICY_CONFLICT',
                        message: `Device reports policy state '${matchingPolicyState.state}', indicating conflicting settings.`
                    });
                    recommendations.push({
                        priority: 'high',
                        action: 'Resolve conflicting settings',
                        details: 'Identify overlapping policies configuring the same setting to different values and consolidate to a single authoritative policy.'
                    });
                }

                if (hasPending) {
                    findings.push({
                        severity: 'low',
                        code: 'POLICY_STATE_PENDING_OR_NOT_APPLICABLE',
                        message: `Device reports policy state '${matchingPolicyState.state}'.`
                    });
                    recommendations.push({
                        priority: 'low',
                        action: 'Validate applicability and sync timing',
                        details: 'Check OS edition/version prerequisites and allow additional check-in cycles before escalating.'
                    });
                }
            }

            const lastSync = deployment.device?.lastSyncDateTime;
            if (lastSync) {
                const lastSyncDate = new Date(lastSync);
                const hoursSinceSync = (Date.now() - lastSyncDate.getTime()) / (1000 * 60 * 60);
                if (hoursSinceSync > 24) {
                    findings.push({
                        severity: 'medium',
                        code: 'STALE_DEVICE_SYNC',
                        message: `Device last synced ${Math.floor(hoursSinceSync)} hours ago.`
                    });
                    recommendations.push({
                        priority: 'medium',
                        action: 'Trigger fresh device sync',
                        details: 'Old sync state can hide recent assignment or policy changes; trigger sync and retry deployment evaluation.'
                    });
                }
            }

            const severityRank: Record<string, number> = { high: 3, medium: 2, low: 1 };
            const topSeverity = findings.reduce((current: string, finding: any) => {
                if (!current) {
                    return finding.severity;
                }
                return severityRank[finding.severity] > severityRank[current] ? finding.severity : current;
            }, 'none');

            return {
                device: deployment.device,
                policy: assignments.policy,
                policySource: assignments.source,
                assignmentSummary: assignments.summary,
                assignments: assignments.resolvedTargets,
                policyState: matchingPolicyState,
                findings,
                recommendations,
                summary: {
                    findingCount: findings.length,
                    recommendationCount: recommendations.length,
                    topSeverity
                }
            };
        } catch (error) {
            this.logger.error('Error running guided policy troubleshooting', {
                deviceId,
                policyId,
                source: source || 'auto',
                error: (error as Error).message,
                stack: (error as Error).stack
            });
            throw error;
        }
    }

    /**
     * Read Intune app deployment definitions from mobile apps.
     */
    public async getAppDeployments(options?: { appName?: string; publisher?: string; platform?: string }) {
        const appName = options?.appName?.trim().toLowerCase();
        const publisher = options?.publisher?.trim().toLowerCase();
        const platform = options?.platform?.trim().toLowerCase();

        this.logger.info('Fetching app deployments', {
            appName: options?.appName,
            publisher: options?.publisher,
            platform: options?.platform
        });
        await this.trackAuthAttempt();

        try {
            const apiStart = Date.now();
            const appsResponse = await this.client
                .api('/deviceAppManagement/mobileApps')
                .version('v1.0')
                .select('id,displayName,publisher,description,isFeatured,createdDateTime,lastModifiedDateTime')
                .top(999)
                .get();

            const apiDuration = Date.now() - apiStart;
            logApiCall(this.logger, 'GET', '/deviceAppManagement/mobileApps', 200, apiDuration);

            const normalized = (appsResponse.value || []).map((app: any) => {
                const odataType = String(app['@odata.type'] || '').toLowerCase();
                return {
                    id: app.id,
                    name: app.displayName,
                    publisher: app.publisher,
                    description: app.description,
                    isFeatured: app.isFeatured,
                    createdDateTime: app.createdDateTime,
                    lastModifiedDateTime: app.lastModifiedDateTime,
                    appType: app['@odata.type'],
                    platformHint: odataType.includes('windows')
                        ? 'windows'
                        : odataType.includes('ios')
                            ? 'ios'
                            : odataType.includes('android')
                                ? 'android'
                                : odataType.includes('macos')
                                    ? 'macos'
                                    : 'unknown'
                };
            });

            let filtered = normalized;
            if (appName) {
                filtered = filtered.filter((app: any) => String(app.name || '').toLowerCase().includes(appName));
            }
            if (publisher) {
                filtered = filtered.filter((app: any) => String(app.publisher || '').toLowerCase().includes(publisher));
            }
            if (platform) {
                filtered = filtered.filter((app: any) => String(app.platformHint || '').toLowerCase().includes(platform));
            }

            const result = {
                apps: filtered,
                summary: {
                    totalApps: normalized.length,
                    filteredApps: filtered.length
                }
            };

            this.logger.info('App deployments retrieved', {
                totalApps: result.summary.totalApps,
                filteredApps: result.summary.filteredApps
            });

            return result;
        } catch (error) {
            this.logger.error('Error fetching app deployments', {
                error: (error as Error).message,
                stack: (error as Error).stack
            });
            throw error;
        }
    }

    /**
     * Get assignment targets for an Intune mobile app deployment.
     */
    public async getAppDeploymentAssignments(appId: string) {
        this.logger.info('Fetching app deployment assignments', { appId });
        await this.trackAuthAttempt();

        const result: any = {
            app: null,
            assignments: [],
            resolvedTargets: [],
            summary: {
                totalAssignments: 0,
                includeAssignments: 0,
                excludeAssignments: 0,
                requiredAssignments: 0,
                availableAssignments: 0,
                uninstallAssignments: 0
            }
        };

        const mapAssignment = (assignment: any) => {
            const target = assignment?.target || {};
            const targetType = String(target['@odata.type'] || '').toLowerCase();
            return {
                id: assignment.id,
                intent: assignment.intent,
                settings: assignment.settings,
                targetType: target['@odata.type'] || 'unknown',
                groupId: target.groupId,
                collectionId: target.collectionId,
                deviceAndAppManagementAssignmentFilterId: target.deviceAndAppManagementAssignmentFilterId,
                deviceAndAppManagementAssignmentFilterType: target.deviceAndAppManagementAssignmentFilterType,
                isExclude: targetType.includes('exclusion')
            };
        };

        const resolveTargetName = async (assignment: any) => {
            if (assignment.groupId) {
                try {
                    const apiStart = Date.now();
                    const group = await this.client
                        .api(`/groups/${assignment.groupId}`)
                        .version('v1.0')
                        .select('id,displayName,mailEnabled,securityEnabled,description')
                        .get();

                    const apiDuration = Date.now() - apiStart;
                    logApiCall(this.logger, 'GET', `/groups/${assignment.groupId}`, 200, apiDuration);

                    return {
                        assignmentId: assignment.id,
                        type: assignment.isExclude ? 'excludeGroup' : 'includeGroup',
                        id: group.id,
                        displayName: group.displayName,
                        description: group.description,
                        intent: assignment.intent,
                        filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                        filterType: assignment.deviceAndAppManagementAssignmentFilterType
                    };
                } catch (error) {
                    this.logger.warn('Failed to resolve app assignment group target', {
                        groupId: assignment.groupId,
                        error: (error as Error).message
                    });
                    return {
                        assignmentId: assignment.id,
                        type: assignment.isExclude ? 'excludeGroup' : 'includeGroup',
                        id: assignment.groupId,
                        displayName: null,
                        intent: assignment.intent,
                        error: (error as Error).message,
                        filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                        filterType: assignment.deviceAndAppManagementAssignmentFilterType
                    };
                }
            }

            const targetType = String(assignment.targetType || '').toLowerCase();
            if (targetType.includes('alldevicesassignmenttarget')) {
                return {
                    assignmentId: assignment.id,
                    type: 'allDevices',
                    displayName: 'All Devices',
                    intent: assignment.intent,
                    filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                    filterType: assignment.deviceAndAppManagementAssignmentFilterType
                };
            }

            if (targetType.includes('alllicensedusersassignmenttarget')) {
                return {
                    assignmentId: assignment.id,
                    type: 'allLicensedUsers',
                    displayName: 'All Licensed Users',
                    intent: assignment.intent,
                    filterId: assignment.deviceAndAppManagementAssignmentFilterId,
                    filterType: assignment.deviceAndAppManagementAssignmentFilterType
                };
            }

            return {
                assignmentId: assignment.id,
                type: 'other',
                displayName: assignment.targetType,
                intent: assignment.intent
            };
        };

        try {
            const appStart = Date.now();
            const app = await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}`)
                .version('v1.0')
                .select('id,displayName,publisher,description,isFeatured,createdDateTime,lastModifiedDateTime')
                .get();

            const appDuration = Date.now() - appStart;
            logApiCall(this.logger, 'GET', `/deviceAppManagement/mobileApps/${appId}`, 200, appDuration);

            result.app = {
                id: app.id,
                name: app.displayName,
                publisher: app.publisher,
                description: app.description,
                isFeatured: app.isFeatured,
                createdDateTime: app.createdDateTime,
                lastModifiedDateTime: app.lastModifiedDateTime,
                appType: app['@odata.type']
            };

            const assignmentsStart = Date.now();
            const assignmentsResponse = await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}/assignments`)
                .version('v1.0')
                .top(999)
                .get();

            const assignmentsDuration = Date.now() - assignmentsStart;
            logApiCall(this.logger, 'GET', `/deviceAppManagement/mobileApps/${appId}/assignments`, 200, assignmentsDuration);

            result.assignments = (assignmentsResponse.value || []).map(mapAssignment);

            const resolvedTargets = [];
            for (const assignment of result.assignments) {
                resolvedTargets.push(await resolveTargetName(assignment));
            }
            result.resolvedTargets = resolvedTargets;

            result.summary.totalAssignments = result.assignments.length;
            result.summary.includeAssignments = result.assignments.filter((assignment: any) => !assignment.isExclude).length;
            result.summary.excludeAssignments = result.assignments.filter((assignment: any) => assignment.isExclude).length;
            result.summary.requiredAssignments = result.assignments.filter((assignment: any) => String(assignment.intent || '').toLowerCase() === 'required').length;
            result.summary.availableAssignments = result.assignments.filter((assignment: any) => String(assignment.intent || '').toLowerCase() === 'available').length;
            result.summary.uninstallAssignments = result.assignments.filter((assignment: any) => String(assignment.intent || '').toLowerCase() === 'uninstall').length;

            this.logger.info('App deployment assignments retrieved', {
                appId,
                assignmentCount: result.summary.totalAssignments
            });

            return result;
        } catch (error) {
            this.logger.error('Error fetching app deployment assignments', {
                appId,
                error: (error as Error).message,
                stack: (error as Error).stack
            });
            throw error;
        }
    }

    /**
     * Correlate app assignment targets and device app status to provide likely root causes
     * and targeted remediation suggestions.
     */
    public async getGuidedAppDeploymentTroubleshooting(deviceId: string, appId: string) {
        this.logger.info('Running guided app deployment troubleshooting', { deviceId, appId });
        await this.trackAuthAttempt();

        try {
            const assignments = await this.getAppDeploymentAssignments(appId);
            const deviceApps = await this.getDeviceApplications(deviceId);

            let device: any = null;
            try {
                const deviceStart = Date.now();
                device = await this.client
                    .api(`/deviceManagement/managedDevices/${deviceId}`)
                    .version('v1.0')
                    .select('id,deviceName,serialNumber,userPrincipalName,operatingSystem,osVersion,lastSyncDateTime,complianceState,managementState')
                    .get();

                const deviceDuration = Date.now() - deviceStart;
                logApiCall(this.logger, 'GET', `/deviceManagement/managedDevices/${deviceId}`, 200, deviceDuration);
            } catch (error) {
                this.logger.warn('Failed to fetch managed device for app troubleshooting', { deviceId, error: (error as Error).message });
            }

            let deviceStatus: any = null;
            try {
                const statusStart = Date.now();
                const statusResponse = await this.client
                    .api(`/deviceAppManagement/mobileApps/${appId}/deviceStatuses`)
                    .version('v1.0')
                    .top(999)
                    .get();

                const statusDuration = Date.now() - statusStart;
                logApiCall(this.logger, 'GET', `/deviceAppManagement/mobileApps/${appId}/deviceStatuses`, 200, statusDuration);

                deviceStatus = (statusResponse.value || []).find((status: any) => status.deviceId === deviceId) || null;
            } catch (error) {
                this.logger.warn('Failed to fetch app device statuses', { appId, error: (error as Error).message });
            }

            const assignedAppState = (deviceApps.assignedApps || []).find((appState: any) => {
                return appState.mobileAppId === appId || appState.id === appId;
            }) || null;

            const detectedMatch = (deviceApps.detectedApps || []).find((detected: any) => {
                return String(detected.displayName || '').toLowerCase() === String(assignments.app?.name || '').toLowerCase();
            }) || null;

            const findings: any[] = [];
            const recommendations: any[] = [];

            const hasAssignments = (assignments.summary?.totalAssignments || 0) > 0;
            if (!hasAssignments) {
                findings.push({
                    severity: 'high',
                    code: 'NO_APP_ASSIGNMENTS',
                    message: 'The target app has no assignments and will not deploy.'
                });
                recommendations.push({
                    priority: 'high',
                    action: 'Assign app to target scope',
                    details: 'Add include assignment targets (group/all devices/all users) with required/available intent as appropriate.'
                });
            }

            const hasRequired = (assignments.summary?.requiredAssignments || 0) > 0;
            if (!hasRequired) {
                findings.push({
                    severity: 'medium',
                    code: 'NO_REQUIRED_ASSIGNMENT',
                    message: 'No required assignment exists; deployment may rely on user-initiated install.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Use required intent for mandatory deployment',
                    details: 'Set assignment intent to required for automatic installation.'
                });
            }

            const hasFilters = (assignments.assignments || []).some((assignment: any) => !!assignment.deviceAndAppManagementAssignmentFilterId);
            if (hasFilters) {
                findings.push({
                    severity: 'medium',
                    code: 'APP_ASSIGNMENT_FILTERS_PRESENT',
                    message: 'Assignment filters are configured and can impact whether this device is in scope.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Validate app assignment filters',
                    details: 'Confirm device attributes satisfy include filters and do not match exclusion filters.'
                });
            }

            if (!deviceStatus && !assignedAppState) {
                findings.push({
                    severity: 'medium',
                    code: 'NO_DEVICE_APP_STATE',
                    message: 'No app deployment status was found for this device.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Force sync and verify scope',
                    details: 'Trigger device sync and validate that the device/user belongs to include targets and not exclusion targets.'
                });
            }

            const normalizedInstallState = String(deviceStatus?.installState || assignedAppState?.installState || '').toLowerCase();
            if (normalizedInstallState.includes('failed') || normalizedInstallState.includes('error')) {
                findings.push({
                    severity: 'high',
                    code: 'APP_INSTALL_FAILED',
                    message: `Install state indicates failure ('${deviceStatus?.installState || assignedAppState?.installState}').`
                });
                recommendations.push({
                    priority: 'high',
                    action: 'Review install and detection requirements',
                    details: 'Check app package type, requirement rules, dependencies, supersedence, and detection logic for this device platform/version.'
                });
            }

            if (detectedMatch && (normalizedInstallState.includes('failed') || normalizedInstallState.includes('notinstalled'))) {
                findings.push({
                    severity: 'medium',
                    code: 'DETECTION_MISMATCH_POSSIBLE',
                    message: 'App appears detected on the device, but deployment state is failed/not installed.'
                });
                recommendations.push({
                    priority: 'medium',
                    action: 'Validate detection rule accuracy',
                    details: 'Adjust detection rules to correctly identify installed app state and version conditions.'
                });
            }

            const lastSync = device?.lastSyncDateTime;
            if (lastSync) {
                const lastSyncDate = new Date(lastSync);
                const hoursSinceSync = (Date.now() - lastSyncDate.getTime()) / (1000 * 60 * 60);
                if (hoursSinceSync > 24) {
                    findings.push({
                        severity: 'medium',
                        code: 'STALE_DEVICE_SYNC',
                        message: `Device last synced ${Math.floor(hoursSinceSync)} hours ago.`
                    });
                    recommendations.push({
                        priority: 'medium',
                        action: 'Trigger fresh sync and retry',
                        details: 'Stale sync can delay app assignment evaluation and status reporting.'
                    });
                }
            }

            const severityRank: Record<string, number> = { high: 3, medium: 2, low: 1 };
            const topSeverity = findings.reduce((current: string, finding: any) => {
                if (!current || current === 'none') {
                    return finding.severity;
                }
                return severityRank[finding.severity] > severityRank[current] ? finding.severity : current;
            }, 'none');

            return {
                device,
                app: assignments.app,
                assignmentSummary: assignments.summary,
                assignments: assignments.resolvedTargets,
                appDeviceStatus: deviceStatus,
                appIntentState: assignedAppState,
                detectedApp: detectedMatch,
                findings,
                recommendations,
                summary: {
                    findingCount: findings.length,
                    recommendationCount: recommendations.length,
                    topSeverity
                }
            };
        } catch (error) {
            this.logger.error('Error running guided app deployment troubleshooting', {
                deviceId,
                appId,
                error: (error as Error).message,
                stack: (error as Error).stack
            });
            throw error;
        }
    }

    // ── Win32 app publishing ──────────────────────────────────────────────────
    // Confirmed against Microsoft Learn's win32LobApp resource docs (v1.0) for the
    // app object schema, and against multiple independent community writeups
    // (rozemuller.com in particular) for the content-upload sequence, which isn't
    // fully documented as a single Microsoft Learn walkthrough. `rules` mixes
    // detection and requirement rules in one array (each tagged with its own
    // `ruleType`/`@odata.type`) — there is no separate detectionRules/
    // requirementRules property, despite that being a common assumption from
    // older blog posts.

    // Chunk size matches the Win32 Content Prep Tool's own default — not a Graph
    // API requirement, just the value every reference implementation uses.
    private static readonly AZURE_BLOCK_CHUNK_SIZE = 6 * 1024 * 1024;

    private async uploadEncryptedContentToAzure(azureStorageUri: string, content: Buffer): Promise<void> {
        const blockIds: string[] = [];
        let offset = 0;
        let blockNumber = 0;
        while (offset < content.length) {
            const chunk = content.subarray(offset, Math.min(offset + IntuneClient.AZURE_BLOCK_CHUNK_SIZE, content.length));
            const blockId = Buffer.from(String(blockNumber).padStart(6, '0')).toString('base64');
            blockIds.push(blockId);
            const apiStart = Date.now();
            const response = await fetch(`${azureStorageUri}&comp=block&blockid=${encodeURIComponent(blockId)}`, {
                method: 'PUT',
                headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Type': 'application/octet-stream' },
                body: new Uint8Array(chunk),
            });
            logApiCall(this.logger, 'PUT', 'azureStorageUri (block)', response.status, Date.now() - apiStart);
            if (!response.ok) {
                const text = await response.text().catch(() => '');
                throw new Error(`Azure block upload failed at offset ${offset} (${response.status}): ${text}`);
            }
            offset += IntuneClient.AZURE_BLOCK_CHUNK_SIZE;
            blockNumber++;
        }

        const blockListXml = `<?xml version="1.0" encoding="utf-8"?><BlockList>${blockIds.map((id) => `<Latest>${id}</Latest>`).join('')}</BlockList>`;
        const apiStart = Date.now();
        const commitResponse = await fetch(`${azureStorageUri}&comp=blocklist`, {
            method: 'PUT',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: blockListXml,
        });
        logApiCall(this.logger, 'PUT', 'azureStorageUri (blocklist)', commitResponse.status, Date.now() - apiStart);
        if (!commitResponse.ok) {
            const text = await commitResponse.text().catch(() => '');
            throw new Error(`Azure block list commit failed (${commitResponse.status}): ${text}`);
        }
    }

    private async pollContentFile(appId: string, versionId: string, fileId: string, until: (file: any) => boolean, timeoutMs = 120_000): Promise<any> {
        const start = Date.now();
        while (true) {
            const apiStart = Date.now();
            const file = await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}/microsoft.graph.win32LobApp/contentVersions/${versionId}/files/${fileId}`)
                .version('beta')
                .get();
            logApiCall(this.logger, 'GET', `contentVersions/${versionId}/files/${fileId}`, 200, Date.now() - apiStart);
            if (until(file)) return file;
            if (file.uploadState && String(file.uploadState).toLowerCase().includes('fail')) {
                throw new Error(`Content file upload failed with state "${file.uploadState}".`);
            }
            if (Date.now() - start > timeoutMs) {
                throw new Error(`Timed out waiting on content file state (last uploadState: "${file.uploadState}").`);
            }
            await new Promise((r) => setTimeout(r, 2000));
        }
    }

    // Creates a new Win32 app object, uploads and commits its .intunewin content,
    // and marks the resulting content version as committed on the app — the full
    // publish pipeline that otherwise means dropping out of MCP entirely and
    // hand-rolling Graph calls + Azure Storage chunked upload + SAS URI polling.
    // Always creates a NEW app object (no upsert-by-displayName — updating an
    // existing app's content means adding a new content version, a materially
    // different operation from creating one, so it isn't folded in here).
    // `intunewinFileBase64` is the raw .intunewin file's bytes, base64-encoded —
    // the same file the Win32 Content Prep Tool produces, unmodified.
    public async createWin32App(params: {
        displayName: string;
        description?: string;
        publisher: string;
        installCommandLine: string;
        uninstallCommandLine: string;
        applicableArchitectures?: 'x86' | 'x64' | 'none';
        minimumSupportedWindowsRelease?: string;
        runAsAccount?: 'system' | 'user';
        deviceRestartBehavior?: 'basedOnReturnCode' | 'allow' | 'suppress' | 'force';
        returnCodes?: { returnCode: number; type: string }[];
        rules: any[];
        intunewinFileBase64: string;
    }) {
        this.logger.info('Creating Win32 app', { displayName: params.displayName });
        await this.trackAuthAttempt();

        const packageBuffer = Buffer.from(params.intunewinFileBase64, 'base64');
        const pkg = await parseIntunewinPackage(packageBuffer);

        const appBody: Record<string, any> = {
            '@odata.type': '#microsoft.graph.win32LobApp',
            displayName: params.displayName,
            description: params.description ?? params.displayName,
            publisher: params.publisher,
            fileName: `${params.displayName}.intunewin`,
            setupFilePath: pkg.setupFileName,
            installCommandLine: params.installCommandLine,
            uninstallCommandLine: params.uninstallCommandLine,
            applicableArchitectures: params.applicableArchitectures ?? 'x64',
            minimumSupportedWindowsRelease: params.minimumSupportedWindowsRelease ?? 'Windows10_1607',
            installExperience: {
                '@odata.type': '#microsoft.graph.win32LobAppInstallExperience',
                runAsAccount: params.runAsAccount ?? 'system',
                deviceRestartBehavior: params.deviceRestartBehavior ?? 'basedOnReturnCode',
            },
            returnCodes: params.returnCodes ?? [
                { '@odata.type': '#microsoft.graph.win32LobAppReturnCode', returnCode: 0, type: 'success' },
                { '@odata.type': '#microsoft.graph.win32LobAppReturnCode', returnCode: 1707, type: 'success' },
                { '@odata.type': '#microsoft.graph.win32LobAppReturnCode', returnCode: 3010, type: 'softReboot' },
                { '@odata.type': '#microsoft.graph.win32LobAppReturnCode', returnCode: 1641, type: 'hardReboot' },
                { '@odata.type': '#microsoft.graph.win32LobAppReturnCode', returnCode: 1618, type: 'retry' },
            ],
            rules: params.rules,
        };

        let apiStart = Date.now();
        const app = await this.client.api('/deviceAppManagement/mobileApps').version('beta').post(appBody);
        logApiCall(this.logger, 'POST', '/deviceAppManagement/mobileApps', 201, Date.now() - apiStart);
        const appId = app.id;

        try {
            apiStart = Date.now();
            const contentVersion = await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}/microsoft.graph.win32LobApp/contentVersions`)
                .version('beta')
                .post({});
            logApiCall(this.logger, 'POST', `mobileApps/${appId}/.../contentVersions`, 201, Date.now() - apiStart);
            const versionId = contentVersion.id;

            apiStart = Date.now();
            const contentFile = await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}/microsoft.graph.win32LobApp/contentVersions/${versionId}/files`)
                .version('beta')
                .post({
                    '@odata.type': '#microsoft.graph.mobileAppContentFile',
                    name: pkg.setupFileName,
                    size: pkg.unencryptedContentSize,
                    sizeEncrypted: pkg.encryptedContent.length,
                    isDependency: false,
                });
            logApiCall(this.logger, 'POST', `contentVersions/${versionId}/files`, 201, Date.now() - apiStart);
            const fileId = contentFile.id;

            const fileWithUri = await this.pollContentFile(appId, versionId, fileId, (f) => Boolean(f.azureStorageUri));
            await this.uploadEncryptedContentToAzure(fileWithUri.azureStorageUri, pkg.encryptedContent);

            apiStart = Date.now();
            await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}/microsoft.graph.win32LobApp/contentVersions/${versionId}/files/${fileId}/commit`)
                .version('beta')
                .post({ fileEncryptionInfo: pkg.encryptionInfo });
            logApiCall(this.logger, 'POST', `contentVersions/${versionId}/files/${fileId}/commit`, 200, Date.now() - apiStart);

            await this.pollContentFile(appId, versionId, fileId, (f) => f.isCommitted === true);

            apiStart = Date.now();
            await this.client
                .api(`/deviceAppManagement/mobileApps/${appId}`)
                .version('beta')
                .patch({ '@odata.type': '#microsoft.graph.win32LobApp', committedContentVersion: versionId });
            logApiCall(this.logger, 'PATCH', `mobileApps/${appId}`, 204, Date.now() - apiStart);

            this.logger.info('Win32 app created and content committed', { appId, displayName: params.displayName, versionId });
            return { appId, displayName: params.displayName, contentVersionId: versionId, setupFileName: pkg.setupFileName };
        } catch (error) {
            this.logger.error('Win32 app content upload failed after app object was created — app exists but content is not committed', {
                appId, displayName: params.displayName, error: (error as Error).message,
            });
            throw error;
        }
    }

    // Assigns an existing app (Win32 or otherwise) to one or more Entra ID groups.
    // This replaces the app's ENTIRE assignment set with the groups given here —
    // matching Graph's own /assign semantics (it is not additive) — so callers
    // widening/narrowing an existing app's rollout must pass the full desired set,
    // not just the group(s) being added.
    public async assignAppToGroups(appId: string, assignments: { groupId: string; intent: 'required' | 'available' | 'uninstall' }[]) {
        this.logger.info('Assigning app to groups', { appId, assignments });
        await this.trackAuthAttempt();
        try {
            const body = {
                mobileAppAssignments: assignments.map((a) => ({
                    '@odata.type': '#microsoft.graph.mobileAppAssignment',
                    intent: a.intent,
                    target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: a.groupId },
                })),
            };
            const apiStart = Date.now();
            await this.client.api(`/deviceAppManagement/mobileApps/${appId}/assign`).version('v1.0').post(body);
            logApiCall(this.logger, 'POST', `mobileApps/${appId}/assign`, 204, Date.now() - apiStart);
            return { appId, assignments };
        } catch (error) {
            this.logger.error('Error assigning app to groups', { appId, error: (error as Error).message });
            throw error;
        }
    }
}