/**
 * Microsoft Intune MCP Server
 *
 * Standalone Streamable HTTP MCP server exposing Microsoft Intune device management,
 * configuration policies, app deployments, and troubleshooting via the Model Context Protocol.
 *
 * Transport: Streamable HTTP — deploy behind Azure APIM or any reverse proxy.
 *
 * Environment variables:
 *   AZURE_TENANT_ID            Azure AD tenant ID (Graph app-only client credentials — unrelated to
 *                              the Entra auth vars below, deliberately kept as a separate app)
 *   AZURE_CLIENT_ID            App registration client ID
 *   AZURE_CLIENT_SECRET        App registration client secret
 *   INTUNE_MCP_AUTH_TOKEN      Bearer token(s) required on /mcp requests (comma-separated to allow
 *                              rotation). Callers authenticated this way get full Intune.Read + Intune.Write
 *                              access, matching this token's behavior before Entra auth existed.
 *   ENTRA_OAUTH_ENABLED        "true" to additionally accept Entra-issued bearer tokens on /mcp, with
 *                              tool visibility driven by the token's `roles` claim (Intune.Read/Intune.Write).
 *   ENTRA_TENANT_ID            Entra tenant GUID (required when ENTRA_OAUTH_ENABLED=true)
 *   ENTRA_RESOURCE_APP_ID_URI  Application ID URI of the "Desktop Management MCP" resource app,
 *                              e.g. api://desktop-mgmt-mcp (required when ENTRA_OAUTH_ENABLED=true)
 *   ENTRA_RESOURCE_APP_ID      GUID app ID of the same resource app. Accepted as an alternate `aud`
 *                              value alongside ENTRA_RESOURCE_APP_ID_URI — a client that sends the
 *                              RFC 8707 `resource` parameter (as MCP-spec clients like OpenCode do)
 *                              gets back a token audienced to this GUID, not the URI, even on the
 *                              v2 endpoint. Optional but recommended once any such client is in use.
 *   INTUNE_MCP_PUBLIC_URL      This server's externally-visible origin, e.g. https://intune-mcp.colgate.edu
 *                              (required when ENTRA_OAUTH_ENABLED=true, used for RFC 9728 resource metadata)
 *   PORT                       HTTP port to listen on (default: 3002)
 */

import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthMetadataRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { z } from "zod";
import { IntuneClient } from "../intune/graph-api.js";
import { requireMcpAuth } from "../utils/auth.js";
import { createEntraVerifier, buildEntraOAuthMetadata } from "../utils/entra-jwt.js";
import { hasRole, assertRole, INTUNE_READ, INTUNE_WRITE, INTUNE_ALL_ROLES } from "../utils/roles.js";
import { metricsMiddleware, metricsHandler, instrumentToolCalls } from "../utils/metrics.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const ResponseFormatSchema = z
    .enum(["json", "markdown"])
    .default("markdown")
    .describe('Output format: "markdown" (default, human-readable) or "json" (structured data)');

function toText(data: unknown, format: "json" | "markdown", markdownFn: () => string): string {
    if (format === "json") return JSON.stringify(data, null, 2);
    return markdownFn();
}

function notFound(label: string): { content: [{ type: "text"; text: string }]; isError: true } {
    return {
        isError: true,
        content: [{ type: "text", text: `Not found: ${label}` }],
    };
}

function errorResult(err: unknown): { content: [{ type: "text"; text: string }]; isError: true } {
    const msg = err instanceof Error ? err.message : String(err);
    return {
        isError: true,
        content: [{ type: "text", text: `Error: ${msg}` }],
    };
}

// ─── Device resolution helpers ───────────────────────────────────────────────

async function resolveDevice(
    client: IntuneClient,
    opts: { deviceName?: string; deviceId?: string; serialNumber?: string }
): Promise<{ deviceId: string; azureADDeviceId?: string } | null> {
    if (opts.deviceId) return { deviceId: opts.deviceId };

    if (opts.deviceName) {
        const device = await client.getManagedDeviceByName(opts.deviceName);
        if (device) return { deviceId: device.id, azureADDeviceId: device.azureADDeviceId };
        return null;
    }

    if (opts.serialNumber) {
        const device = await client.getManagedDeviceBySerialNumber(opts.serialNumber);
        if (device) return { deviceId: device.id, azureADDeviceId: device.azureADDeviceId };
        return null;
    }

    return null;
}

async function resolveAppByName(
    client: IntuneClient,
    appName: string
): Promise<{ appId: string; appName: string } | null> {
    const deployments = await client.getAppDeployments({ appName });
    const apps: any[] = Array.isArray(deployments.apps) ? deployments.apps : [];
    if (apps.length === 0) return null;

    const lower = appName.toLowerCase();
    const exact = apps.find((a: any) => String(a.name ?? "").toLowerCase() === lower);
    const match = exact ?? apps[0];
    return { appId: match.id, appName: match.name };
}

async function resolvePolicyByName(
    client: IntuneClient,
    policyName: string,
    source?: "classic" | "settingsCatalog" | "auto"
): Promise<{ policyId: string; policyName: string; source: "classic" | "settingsCatalog" } | null> {
    const result = await client.getConfigurationPolicies({ policyName });
    let all: any[] = Array.isArray(result.combined) ? result.combined : [];

    if (source && source !== "auto") all = all.filter((p: any) => p.source === source);
    if (all.length === 0) return null;

    const lower = policyName.toLowerCase();
    const exact = all.find((p: any) => String(p.name ?? "").toLowerCase() === lower);
    const match = exact ?? all[0];
    return { policyId: match.id, policyName: match.name, source: match.source };
}

async function resolveCompliancePolicyByName(
    client: IntuneClient,
    policyName: string
): Promise<{ policyId: string; policyName: string } | null> {
    const result = await client.getCompliancePolicies({ policyName });
    const policies: any[] = Array.isArray(result.policies) ? result.policies : [];
    if (policies.length === 0) return null;

    const lower = policyName.toLowerCase();
    const exact = policies.find((p: any) => String(p.name ?? "").toLowerCase() === lower);
    const match = exact ?? policies[0];
    return { policyId: match.id, policyName: match.name };
}

async function resolveAppConfigurationPolicyByName(
    client: IntuneClient,
    name: string
): Promise<{ id: string; name: string } | null> {
    const result = await client.getAppConfigurationPolicies({ name });
    const policies: any[] = Array.isArray(result.policies) ? result.policies : [];
    if (policies.length === 0) return null;

    const lower = name.toLowerCase();
    const exact = policies.find((p: any) => String(p.name ?? "").toLowerCase() === lower);
    const match = exact ?? policies[0];
    return { id: match.id, name: match.name };
}

const DeviceIdentifierSchema = {
    deviceName: z.string().optional().describe("Device display name in Intune"),
    deviceId: z.string().optional().describe("Intune managed device ID (GUID)"),
    serialNumber: z.string().optional().describe("Device serial number"),
};

// ─── Server factory ───────────────────────────────────────────────────────────

function createIntuneMcpServer(roles: string[], caller: string): McpServer {
    const client = new IntuneClient();

    const server = new McpServer({
        name: "intune-mcp-server",
        version: "1.0.0",
    });
    instrumentToolCalls(server, "intune", caller);

    // ── 1. intune_get_device_by_name ─────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_device_by_name",
            {
                description:
                    "Get full details for a single managed device in Microsoft Intune by display name. " +
                    "Returns OS, compliance state, last sync, serial, model, Entra ID device ID, assigned user, and management state.",
                inputSchema: {
                    deviceName: z.string().describe("The display name of the device in Intune"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, response_format = "markdown" }) => {
                try {
                    const device = await client.getManagedDeviceByName(deviceName);
                    if (!device) return notFound(`device "${deviceName}"`);

                    const text = toText(device, response_format, () => {
                        const d = device as any;
                        return [
                            `## ${d.deviceName ?? deviceName}`,
                            `- **Serial:** ${d.serialNumber ?? "—"}`,
                            `- **Model:** ${d.model ?? "—"} (${d.manufacturer ?? "—"})`,
                            `- **OS:** ${d.operatingSystem ?? "—"} ${d.osVersion ?? ""}`,
                            `- **Compliance:** ${d.complianceState ?? "—"}`,
                            `- **Management State:** ${d.managementState ?? "—"}`,
                            `- **Ownership:** ${d.ownerType ?? "—"}`,
                            `- **Last Sync:** ${d.lastSyncDateTime ?? "—"}`,
                            `- **Enrolled:** ${d.enrolledDateTime ?? "—"}`,
                            `- **Assigned User:** ${d.userDisplayName ?? "—"} (${d.userPrincipalName ?? "—"})`,
                            `- **Intune Device ID:** ${d.id ?? "—"}`,
                            `- **Azure AD Device ID:** ${d.azureADDeviceId ?? "—"}`,
                        ].join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 2. intune_get_device_by_serial ───────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_device_by_serial",
            {
                description:
                    "Get full details for a managed device in Microsoft Intune by serial number. " +
                    "Returns OS, compliance state, last sync, model, Entra ID device ID, and assigned user.",
                inputSchema: {
                    serialNumber: z.string().describe("The device serial number"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ serialNumber, response_format = "markdown" }) => {
                try {
                    const device = await client.getManagedDeviceBySerialNumber(serialNumber);
                    if (!device) return notFound(`device with serial "${serialNumber}"`);

                    const text = toText(device, response_format, () => {
                        const d = device as any;
                        return [
                            `## ${d.deviceName ?? serialNumber}`,
                            `- **Serial:** ${d.serialNumber ?? serialNumber}`,
                            `- **Model:** ${d.model ?? "—"} (${d.manufacturer ?? "—"})`,
                            `- **OS:** ${d.operatingSystem ?? "—"} ${d.osVersion ?? ""}`,
                            `- **Compliance:** ${d.complianceState ?? "—"}`,
                            `- **Management State:** ${d.managementState ?? "—"}`,
                            `- **Ownership:** ${d.ownerType ?? "—"}`,
                            `- **Last Sync:** ${d.lastSyncDateTime ?? "—"}`,
                            `- **Assigned User:** ${d.userDisplayName ?? "—"} (${d.userPrincipalName ?? "—"})`,
                            `- **Intune Device ID:** ${d.id ?? "—"}`,
                            `- **Azure AD Device ID:** ${d.azureADDeviceId ?? "—"}`,
                        ].join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 3. intune_get_autopilot_status ───────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_autopilot_status",
            {
                description:
                    "Get the Windows Autopilot deployment profile assigned to a device, looked up by serial number or device name. " +
                    "Returns the profile name, group tag, deployment mode, enrollment status, and profile assignment state.",
                inputSchema: {
                    serialNumber: z.string().optional().describe("Device serial number (preferred for Autopilot lookups)"),
                    deviceName: z.string().optional().describe("Intune device display name (resolved to serial automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ serialNumber, deviceName, response_format = "markdown" }) => {
                try {
                    let targetSerial = serialNumber;

                    if (deviceName && !targetSerial) {
                        const device = await client.getManagedDeviceByName(deviceName);
                        if (!device) return notFound(`device "${deviceName}"`);
                        targetSerial = (device as any).serialNumber;
                    }

                    if (!targetSerial) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide serialNumber or deviceName." }],
                        };
                    }

                    const data = await client.getAutopilotProfileStatus(targetSerial);
                    if (!data) return notFound(`Autopilot record for serial "${targetSerial}"`);

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        return [
                            `## Autopilot Profile — ${d.serialNumber ?? targetSerial}`,
                            `- **Profile:** ${d.deploymentProfileAssignmentStatus ?? "—"} — ${d.deploymentProfile?.displayName ?? "No profile assigned"}`,
                            `- **Group Tag:** ${d.groupTag ?? "—"}`,
                            `- **Deployment Mode:** ${d.deploymentProfile?.outOfBoxExperienceSettings?.deviceUsageType ?? "—"}`,
                            `- **Profile Assigned:** ${d.deploymentProfileAssignedDateTime ?? "—"}`,
                            `- **Last Contacted:** ${d.lastContactedDateTime ?? "—"}`,
                            `- **Purchase Order:** ${d.purchaseOrderIdentifier ?? "—"}`,
                            `- **Address:** ${d.addressableUserName ?? "—"}`,
                        ].join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── intune_list_autopilot_devices ────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_autopilot_devices",
            {
                description:
                    "Bulk-list Windows Autopilot device identities (distinct from Intune's managed-device inventory — " +
                    "a device can have an Autopilot record with no Intune enrollment yet, or vice versa). Use this for " +
                    "fleet-wide Autopilot counts/breakdowns (e.g. by manufacturer, whether devices came in pre-registered " +
                    "via purchaseOrderIdentifier) instead of sending many concurrent intune_get_autopilot_status calls, " +
                    "which can overload this server — see that tool's description.",
                inputSchema: {
                    manufacturer: z.string().optional().describe("Filter by manufacturer, substring match (e.g. \"Dell\")"),
                    model: z.string().optional().describe("Filter by model, substring match"),
                    groupTag: z.string().optional().describe("Filter by Autopilot group tag, substring match"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ manufacturer, model, groupTag, response_format = "markdown" }) => {
                try {
                    const data = await client.listAutopilotDevices({ manufacturer, model, groupTag });

                    const text = toText(data, response_format, () => {
                        const devices: any[] = data.devices ?? [];
                        const filterNote = [
                            manufacturer && `manufacturer="${manufacturer}"`,
                            model && `model="${model}"`,
                            groupTag && `groupTag="${groupTag}"`,
                        ]
                            .filter(Boolean)
                            .join(", ");

                        if (devices.length === 0) {
                            return `No Autopilot devices found${filterNote ? ` matching ${filterNote}` : ""}.`;
                        }

                        const byManufacturer = new Map<string, number>();
                        const byPurchaseOrder = new Map<string, number>();
                        for (const d of devices) {
                            const mfr = d.manufacturer ?? "Unknown";
                            const po = d.purchaseOrderIdentifier || "(none)";
                            byManufacturer.set(mfr, (byManufacturer.get(mfr) ?? 0) + 1);
                            byPurchaseOrder.set(po, (byPurchaseOrder.get(po) ?? 0) + 1);
                        }

                        const sortedEntries = (m: Map<string, number>) =>
                            [...m.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `- **${k}:** ${v}`).join("\n");

                        const rows = devices
                            .slice(0, 50)
                            .map(
                                (d: any) =>
                                    `- **${d.serialNumber ?? "Unknown"}** | ${d.manufacturer ?? "—"} ${d.model ?? "—"} | Group Tag: ${d.groupTag || "—"} | Profile: ${d.deploymentProfileAssignmentStatus ?? "—"} | PO: ${d.purchaseOrderIdentifier || "—"}`
                            )
                            .join("\n");

                        const truncationNote = data.truncated
                            ? `\n\n_⚠️ Hit the pagination safety cap — counts above reflect only the first ${devices.length} devices fetched, not necessarily the entire tenant._`
                            : "";

                        return (
                            [
                                `## Autopilot Devices${filterNote ? ` (${filterNote})` : ""} — ${devices.length} total`,
                                `### By Manufacturer\n${sortedEntries(byManufacturer)}`,
                                `### By Purchase Order Identifier\n${sortedEntries(byPurchaseOrder)}`,
                                `### Devices (showing ${Math.min(50, devices.length)} of ${devices.length})\n${rows}${devices.length > 50 ? `\n_…and ${devices.length - 50} more_` : ""}`,
                            ].join("\n\n") + truncationNote
                        );
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 4. intune_get_devices_by_user ────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_devices_by_user",
            {
                description:
                    "Find all managed devices in Intune assigned to a user. " +
                    "Accepts an Entra ID UPN (email), display name, or username. " +
                    "Returns device name, OS, compliance state, last sync, and model for each device.",
                inputSchema: {
                    userIdentifier: z
                        .string()
                        .describe("User UPN (email), Entra ID display name, or username"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ userIdentifier, response_format = "markdown" }) => {
                try {
                    const devices = await client.getManagedDevicesByUser(userIdentifier);
                    const list: any[] = Array.isArray(devices) ? devices : [];

                    const text = toText(devices, response_format, () => {
                        if (list.length === 0) return `No managed devices found for user "${userIdentifier}".`;
                        const rows = list
                            .map(
                                (d: any) =>
                                    `- **${d.deviceName ?? "Unknown"}** | OS: ${d.operatingSystem ?? "—"} ${d.osVersion ?? ""} | Compliance: ${d.complianceState ?? "—"} | Ownership: ${d.ownerType ?? "—"} | Last sync: ${d.lastSyncDateTime ?? "—"}`
                            )
                            .join("\n");
                        return `## Devices for "${userIdentifier}" (${list.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 5. intune_get_device_groups ──────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_device_groups",
            {
                description:
                    "Get the Intune categories and Azure AD group memberships for a managed device. " +
                    "Accepts device name, Intune device ID, or serial number. " +
                    "Returns Intune device categories and all Azure AD security/dynamic groups the device belongs to.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, response_format = "markdown" }) => {
                try {
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    const data = await client.getDeviceGroupMemberships(resolved.deviceId, resolved.azureADDeviceId);

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        const label = deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId;
                        const categories: any[] = d.intuneCategories ?? [];
                        const groups: any[] = d.azureADGroups ?? [];

                        const catSection =
                            categories.length > 0
                                ? `### Intune Categories\n${categories.map((c: any) => `- ${c.displayName ?? c.name}`).join("\n")}`
                                : "### Intune Categories\n_None assigned_";

                        const grpSection =
                            groups.length > 0
                                ? `### Azure AD Group Memberships (${groups.length})\n${groups.map((g: any) => `- **${g.displayName}** (${g.groupTypes?.join(", ") ?? "Security"})`).join("\n")}`
                                : "### Azure AD Group Memberships\n_None found_";

                        return `## Group Memberships — ${label}\n\n${catSection}\n\n${grpSection}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 6. intune_get_device_apps ────────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_device_apps",
            {
                description:
                    "Get the applications installed on a managed device in Intune. " +
                    "Accepts device name, Intune device ID, or serial number. " +
                    "Returns detected apps (name, version, publisher) and Intune app intent states.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, response_format = "markdown" }) => {
                try {
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    const data = await client.getDeviceApplications(resolved.deviceId);

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        const label = deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId;
                        const detected: any[] = d.detectedApps ?? [];
                        const intune: any[] = d.intuneApps ?? [];

                        const detectedSection =
                            detected.length > 0
                                ? `### Detected Apps (${detected.length})\n${detected
                                      .slice(0, 50)
                                      .map((a: any) => `- **${a.displayName}** v${a.version ?? "—"} | Publisher: ${a.publisher ?? "—"}`)
                                      .join("\n")}${detected.length > 50 ? `\n_…and ${detected.length - 50} more_` : ""}`
                                : "### Detected Apps\n_None_";

                        const intuneSection =
                            intune.length > 0
                                ? `### Intune App Deployments (${intune.length})\n${intune
                                      .map((a: any) => `- **${a.displayName}** | Intent: ${a.intent ?? "—"} | State: ${a.installState ?? a.installSummary?.installedDeviceCount ?? "—"}`)
                                      .join("\n")}`
                                : "### Intune App Deployments\n_None_";

                        return `## Applications — ${label}\n\n${detectedSection}\n\n${intuneSection}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 7. intune_list_configuration_policies ────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_configuration_policies",
            {
                description:
                    "List configuration policies in Microsoft Intune, including both classic device configuration profiles " +
                    "and modern Settings Catalog policies. Optionally filter by name or platform. " +
                    "Returns policy ID, name, platform, last modified date, and assignment count.",
                inputSchema: {
                    policyName: z
                        .string()
                        .optional()
                        .describe("Optional name filter (case-insensitive substring match)"),
                    platform: z
                        .string()
                        .optional()
                        .describe(
                            'Optional platform filter (e.g. "windows10", "macOS", "iOS", "android")'
                        ),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyName, platform, response_format = "markdown" }) => {
                try {
                    const data = await client.getConfigurationPolicies({ policyName, platform });

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        const combined: any[] = d.combined ?? [];

                        if (combined.length === 0) {
                            const filters = [policyName && `name: "${policyName}"`, platform && `platform: "${platform}"`]
                                .filter(Boolean)
                                .join(", ");
                            return `No configuration policies found${filters ? ` matching ${filters}` : ""}.`;
                        }

                        const classic = combined.filter((p: any) => p.source === "classic");
                        const catalog = combined.filter((p: any) => p.source === "settingsCatalog");

                        const formatSection = (label: string, policies: any[]) => {
                            if (policies.length === 0) return "";
                            const rows = policies
                                .map(
                                    (p: any) =>
                                        `- **${p.name}** (ID: ${p.id}) | Platform: ${p.platforms || "—"} | Modified: ${p.lastModifiedDateTime ?? "—"}`
                                )
                                .join("\n");
                            return `### ${label} (${policies.length})\n${rows}`;
                        };

                        const sections = [
                            formatSection("Settings Catalog Policies", catalog),
                            formatSection("Classic Device Configuration Profiles", classic),
                        ]
                            .filter(Boolean)
                            .join("\n\n");

                        const filterNote =
                            policyName || platform
                                ? ` (filtered: ${[policyName && `name="${policyName}"`, platform && `platform="${platform}"`].filter(Boolean).join(", ")})`
                                : "";

                        return `## Configuration Policies${filterNote} — ${combined.length} total\n\n${sections}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 8. intune_get_policy_assignments ─────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_policy_assignments",
            {
                description:
                    "Get the group assignments for a specific Intune configuration policy, looked up by policy ID or name. " +
                    "Returns included and excluded groups with resolved display names and assignment filters.",
                inputSchema: {
                    policyId: z.string().optional().describe("Intune policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    source: z
                        .enum(["classic", "settingsCatalog", "auto"])
                        .default("auto")
                        .describe(
                            'Policy type: "classic" for device configuration profiles, "settingsCatalog" for Settings Catalog, "auto" to detect (default)'
                        ),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyId, policyName, source = "auto", response_format = "markdown" }) => {
                try {
                    let resolvedPolicyId = policyId;
                    let resolvedSource: "classic" | "settingsCatalog" | "auto" = source;
                    let resolvedName = policyName;

                    if (!resolvedPolicyId && policyName) {
                        const resolved = await resolvePolicyByName(client, policyName, source);
                        if (!resolved) return notFound(`policy "${policyName}"`);
                        resolvedPolicyId = resolved.policyId;
                        resolvedSource = resolved.source;
                        resolvedName = resolved.policyName;
                    }

                    if (!resolvedPolicyId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide policyId or policyName." }],
                        };
                    }

                    const data = await client.getConfigurationPolicyAssignments(resolvedPolicyId, resolvedSource);

                    const text = toText(
                        { resolvedPolicy: { id: resolvedPolicyId, name: resolvedName, source: resolvedSource }, assignments: data },
                        response_format,
                        () => {
                            const d = data as any;
                            const assignments: any[] = d.assignments ?? [];
                            const label = resolvedName ?? resolvedPolicyId;

                            if (assignments.length === 0) return `## Assignments for "${label}"\n\n_No assignments found._`;

                            const included = assignments.filter((a: any) => !a.target?.targetType?.includes("Excluded"));
                            const excluded = assignments.filter((a: any) => a.target?.targetType?.includes("Excluded"));

                            const formatGroup = (a: any) => {
                                const name = a.target?.groupDisplayName ?? a.target?.groupId ?? a.target?.targetType ?? "Unknown";
                                const filter = a.target?.deviceAndAppManagementAssignmentFilterDisplayName;
                                return `- **${name}**${filter ? ` (filter: ${filter})` : ""}`;
                            };

                            const incSection =
                                included.length > 0
                                    ? `### Included (${included.length})\n${included.map(formatGroup).join("\n")}`
                                    : "### Included\n_None_";

                            const exclSection =
                                excluded.length > 0
                                    ? `### Excluded (${excluded.length})\n${excluded.map(formatGroup).join("\n")}`
                                    : "";

                            return `## Assignments — "${label}"\n\n${incSection}${exclSection ? `\n\n${exclSection}` : ""}`;
                        }
                    );

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 9. intune_troubleshoot_device_policies ───────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_troubleshoot_device_policies",
            {
                description:
                    "Get a full policy deployment and compliance troubleshooting report for a managed device. " +
                    "Returns all configuration policy states, compliance policy states, and identified issues with recommendations. " +
                    "Accepts device name, Intune device ID, or serial number.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, response_format = "markdown" }) => {
                try {
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    const data = await client.getDevicePolicyDeploymentTroubleshooting(resolved.deviceId);

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        const label = deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId;
                        const configPolicies: any[] = d.configurationPolicyStates ?? [];
                        const compliancePolicies: any[] = d.compliancePolicyStates ?? [];
                        const issues: any[] = d.issues ?? [];

                        const configSection =
                            configPolicies.length > 0
                                ? `### Configuration Policies (${configPolicies.length})\n${configPolicies
                                      .map(
                                          (p: any) =>
                                              `- **${p.displayName ?? p.id}** | State: ${p.state ?? "—"} | Conflicts: ${p.conflictCount ?? 0} | Errors: ${p.errorCount ?? 0}`
                                      )
                                      .join("\n")}`
                                : "### Configuration Policies\n_None reported_";

                        const complianceSection =
                            compliancePolicies.length > 0
                                ? `### Compliance Policies (${compliancePolicies.length})\n${compliancePolicies
                                      .map(
                                          (p: any) =>
                                              `- **${p.displayName ?? p.id}** | State: ${p.state ?? "—"}`
                                      )
                                      .join("\n")}`
                                : "### Compliance Policies\n_None reported_";

                        const issuesSection =
                            issues.length > 0
                                ? `### ⚠️ Issues Found (${issues.length})\n${issues
                                      .map(
                                          (i: any) =>
                                              `- **${i.title ?? "Issue"}**: ${i.description ?? "—"}\n  _Recommendation: ${i.recommendation ?? "See Intune portal for details"}_`
                                      )
                                      .join("\n")}`
                                : "### Issues\n_No issues detected_";

                        return `## Policy Troubleshooting — ${label}\n\n${configSection}\n\n${complianceSection}\n\n${issuesSection}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 10. intune_troubleshoot_policy ───────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_troubleshoot_policy",
            {
                description:
                    "Run guided troubleshooting for a specific configuration policy on a specific device. " +
                    "Correlates the policy's deployment state on the device with its group assignments, " +
                    "identifies errors or conflicts, and provides actionable findings and recommendations. " +
                    "Accepts policy by ID or name, and device by name, device ID, or serial number.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    policyId: z.string().optional().describe("Intune policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    source: z
                        .enum(["classic", "settingsCatalog", "auto"])
                        .default("auto")
                        .describe('Policy type hint — "classic", "settingsCatalog", or "auto" to detect'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, policyId, policyName, source = "auto", response_format = "markdown" }) => {
                try {
                    const resolvedDevice = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolvedDevice) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    let resolvedPolicyId = policyId;
                    let resolvedSource: "classic" | "settingsCatalog" | "auto" = source;
                    let resolvedPolicyName = policyName;

                    if (!resolvedPolicyId && policyName) {
                        const rp = await resolvePolicyByName(client, policyName, source);
                        if (!rp) return notFound(`policy "${policyName}"`);
                        resolvedPolicyId = rp.policyId;
                        resolvedSource = rp.source;
                        resolvedPolicyName = rp.policyName;
                    }

                    if (!resolvedPolicyId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide policyId or policyName." }],
                        };
                    }

                    const data = await client.getGuidedPolicyTroubleshooting(
                        resolvedDevice.deviceId,
                        resolvedPolicyId,
                        resolvedSource
                    );

                    const text = toText(
                        { resolvedPolicy: { id: resolvedPolicyId, name: resolvedPolicyName }, device: { id: resolvedDevice.deviceId }, analysis: data },
                        response_format,
                        () => {
                            const d = data as any;
                            const devLabel = deviceName ?? deviceId ?? serialNumber ?? resolvedDevice.deviceId;
                            const polLabel = resolvedPolicyName ?? resolvedPolicyId;

                            const findings: any[] = d.findings ?? [];
                            const recommendations: any[] = d.recommendations ?? [];
                            const state = d.deploymentState ?? d.policyState;

                            const stateSection = state ? `**Deployment State:** ${state}` : "";
                            const findingsSection =
                                findings.length > 0
                                    ? `### Findings\n${findings
                                          .map((f: any) => `- **[${f.severity ?? "—"}] ${f.code ?? "Finding"}**: ${f.message ?? f}`)
                                          .join("\n")}`
                                    : "### Findings\n_No issues detected_";
                            const recoSection =
                                recommendations.length > 0
                                    ? `### Recommendations\n${recommendations
                                          .map((r: any) => `- **[${r.priority ?? "—"}] ${r.action ?? "Recommendation"}**: ${r.details ?? r}`)
                                          .join("\n")}`
                                    : "";

                            return `## Guided Policy Troubleshooting\n**Device:** ${devLabel} | **Policy:** ${polLabel}\n\n${stateSection}\n\n${findingsSection}${recoSection ? `\n\n${recoSection}` : ""}`;
                        }
                    );

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 11. intune_list_app_deployments ──────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_app_deployments",
            {
                description:
                    "List app deployments configured in Microsoft Intune. " +
                    "Optionally filter by app name, publisher, or platform. " +
                    "Returns app ID, name, publisher, platform, app type, and deployment counts.",
                inputSchema: {
                    appName: z
                        .string()
                        .optional()
                        .describe("Optional app name filter (case-insensitive substring match)"),
                    publisher: z
                        .string()
                        .optional()
                        .describe("Optional publisher name filter"),
                    platform: z
                        .string()
                        .optional()
                        .describe('Optional platform filter (e.g. "windows", "macOS", "iOS", "android")'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ appName, publisher, platform, response_format = "markdown" }) => {
                try {
                    const data = await client.getAppDeployments({ appName, publisher, platform });

                    const text = toText(data, response_format, () => {
                        const d = data as any;
                        const apps: any[] = d.apps ?? [];

                        if (apps.length === 0) {
                            const filters = [
                                appName && `name: "${appName}"`,
                                publisher && `publisher: "${publisher}"`,
                                platform && `platform: "${platform}"`,
                            ]
                                .filter(Boolean)
                                .join(", ");
                            return `No app deployments found${filters ? ` matching ${filters}` : ""}.`;
                        }

                        const rows = apps
                            .map(
                                (a: any) =>
                                    `- **${a.name ?? a.displayName}** (ID: ${a.id}) | Platform: ${a.platform ?? "—"} | Publisher: ${a.publisher ?? "—"} | Type: ${a.appType ?? "—"}`
                            )
                            .join("\n");

                        const filterNote = [
                            appName && `name="${appName}"`,
                            publisher && `publisher="${publisher}"`,
                            platform && `platform="${platform}"`,
                        ]
                            .filter(Boolean)
                            .join(", ");

                        return `## App Deployments${filterNote ? ` (${filterNote})` : ""} — ${apps.length} found\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 12. intune_get_app_assignments ───────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_app_assignments",
            {
                description:
                    "Get the group assignments for a specific app deployment in Intune, by app ID or app name. " +
                    "Returns included and excluded groups, assignment intent (required/available/uninstall), " +
                    "and resolved group display names.",
                inputSchema: {
                    appId: z.string().optional().describe("Intune mobile app ID (GUID). Use if you already have it."),
                    appName: z.string().optional().describe("App display name (resolved to ID automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ appId, appName, response_format = "markdown" }) => {
                try {
                    let resolvedAppId = appId;
                    let resolvedAppName = appName;

                    if (!resolvedAppId && appName) {
                        const resolved = await resolveAppByName(client, appName);
                        if (!resolved) return notFound(`app "${appName}"`);
                        resolvedAppId = resolved.appId;
                        resolvedAppName = resolved.appName;
                    }

                    if (!resolvedAppId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide appId or appName." }],
                        };
                    }

                    const data = await client.getAppDeploymentAssignments(resolvedAppId);

                    const text = toText(
                        { resolvedApp: { id: resolvedAppId, name: resolvedAppName }, assignments: data },
                        response_format,
                        () => {
                            const d = data as any;
                            const assignments: any[] = d.assignments ?? [];
                            const label = resolvedAppName ?? resolvedAppId;

                            if (assignments.length === 0) return `## Assignments for "${label}"\n\n_No assignments configured._`;

                            const rows = assignments
                                .map((a: any) => {
                                    const group = a.target?.groupDisplayName ?? a.target?.groupId ?? a.target?.targetType ?? "Unknown";
                                    const intent = a.intent ?? "—";
                                    const filter = a.target?.deviceAndAppManagementAssignmentFilterDisplayName;
                                    return `- **${group}** | Intent: ${intent}${filter ? ` | Filter: ${filter}` : ""}`;
                                })
                                .join("\n");

                            return `## App Assignments — "${label}"\n\n${rows}`;
                        }
                    );

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 13. intune_troubleshoot_app ──────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_troubleshoot_app",
            {
                description:
                    "Run guided troubleshooting for a specific app deployment on a specific device. " +
                    "Identifies why an app is not installed, in error, or not targeted to the device. " +
                    "Checks app assignments, device group memberships, and install state, then provides findings and recommendations. " +
                    "Accepts app by ID or name, and device by name, device ID, or serial number.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    appId: z.string().optional().describe("Intune mobile app ID (GUID). Use if you already have it."),
                    appName: z.string().optional().describe("App display name (resolved to ID automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, appId, appName, response_format = "markdown" }) => {
                try {
                    const resolvedDevice = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolvedDevice) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    let resolvedAppId = appId;
                    let resolvedAppName = appName;

                    if (!resolvedAppId && appName) {
                        const resolved = await resolveAppByName(client, appName);
                        if (!resolved) return notFound(`app "${appName}"`);
                        resolvedAppId = resolved.appId;
                        resolvedAppName = resolved.appName;
                    }

                    if (!resolvedAppId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide appId or appName." }],
                        };
                    }

                    const data = await client.getGuidedAppDeploymentTroubleshooting(resolvedDevice.deviceId, resolvedAppId);

                    const text = toText(
                        { resolvedApp: { id: resolvedAppId, name: resolvedAppName }, device: { id: resolvedDevice.deviceId }, analysis: data },
                        response_format,
                        () => {
                            const d = data as any;
                            const devLabel = deviceName ?? deviceId ?? serialNumber ?? resolvedDevice.deviceId;
                            const appLabel = resolvedAppName ?? resolvedAppId;

                            const installState = d.installState ?? d.deviceInstallState?.installState;
                            const findings: any[] = d.findings ?? [];
                            const recommendations: any[] = d.recommendations ?? [];

                            const stateSection = installState ? `**Install State:** ${installState}` : "";
                            const findingsSection =
                                findings.length > 0
                                    ? `### Findings\n${findings
                                          .map((f: any) => `- **[${f.severity ?? "—"}] ${f.code ?? "Finding"}**: ${f.message ?? f}`)
                                          .join("\n")}`
                                    : "### Findings\n_No issues detected_";
                            const recoSection =
                                recommendations.length > 0
                                    ? `### Recommendations\n${recommendations
                                          .map((r: any) => `- **[${r.priority ?? "—"}] ${r.action ?? "Recommendation"}**: ${r.details ?? r}`)
                                          .join("\n")}`
                                    : "";

                            return `## Guided App Troubleshooting\n**Device:** ${devLabel} | **App:** ${appLabel}\n\n${stateSection}\n\n${findingsSection}${recoSection ? `\n\n${recoSection}` : ""}`;
                        }
                    );

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 13b. intune_get_group_members ────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_group_members",
            {
                description:
                    "List the members of an Entra ID group by name or GUID. Use this to confirm whether an app " +
                    "or configuration policy assignment group actually resolves to real members before or after " +
                    "assigning it — the Intune-side analogue of jamf_get_smart_group_members. Returns each " +
                    "member's display name, type (user/device/group), and (for devices) OS.",
                inputSchema: {
                    groupNameOrId: z.string().describe("Entra ID group display name or GUID"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupNameOrId, response_format = "markdown" }) => {
                try {
                    const data = await client.getGroupMembers(groupNameOrId);
                    if (!data.group) return notFound(`group "${groupNameOrId}"`);

                    const text = toText(data, response_format, () => {
                        if (data.members.length === 0) return `Group **${data.group!.displayName}** has no members.`;
                        const rows = data.members
                            .map((m: any) => `- **${m.displayName ?? "Unknown"}** (${m.type})${m.userPrincipalName ? ` — ${m.userPrincipalName}` : ""}${m.operatingSystem ? ` — ${m.operatingSystem}` : ""}`)
                            .join("\n");
                        const truncNote = data.truncated ? "\n\n_Results truncated at the pagination safety cap._" : "";
                        return `## Group **${data.group!.displayName}** Members (${data.members.length})\n\n${rows}${truncNote}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 14. intune_list_devices ──────────────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_devices",
            {
                description:
                    "List managed devices across the whole Intune fleet, optionally filtered by operating system, " +
                    "compliance state, management state, or management agent. Pages through the full result set " +
                    "(not just the first 999) so counts are accurate fleet-wide. Use this for fleet counts and " +
                    "breakdowns rather than sending repeated single-device lookups. " +
                    "IMPORTANT: /managedDevices includes devices that merely appear in Intune's device inventory " +
                    "without being Intune-MDM-managed — e.g. devices reporting in only via Defender for Endpoint " +
                    "(managementAgent \"msSense\") or pure ConfigMgr/SCCM management with no MDM component " +
                    "(\"configurationManagerClient\"). Set intuneManagedOnly=true to restrict to devices actually " +
                    "enrolled/managed via Intune MDM (including ConfigMgr co-management) for an accurate Intune fleet count.",
                inputSchema: {
                    operatingSystem: z
                        .string()
                        .optional()
                        .describe('Filter by OS, e.g. "Windows", "macOS", "iOS", "Android"'),
                    complianceState: z
                        .string()
                        .optional()
                        .describe('Filter by compliance state, e.g. "compliant", "noncompliant", "inGracePeriod", "error"'),
                    managementState: z
                        .string()
                        .optional()
                        .describe('Filter by management state, e.g. "managed", "retirePending", "wipePending"'),
                    managementAgent: z
                        .string()
                        .optional()
                        .describe(
                            'Filter by exact management agent, e.g. "mdm", "configurationManagerClientMdm", "msSense", "configurationManagerClient"'
                        ),
                    ownerType: z
                        .string()
                        .optional()
                        .describe('Filter by device ownership, e.g. "company", "personal", "unknown"'),
                    intuneManagedOnly: z
                        .boolean()
                        .optional()
                        .describe(
                            "If true, exclude devices that appear in Intune's device inventory but aren't actually " +
                                "Intune-MDM-managed (e.g. Defender-sensor-only or ConfigMgr-only devices). Recommended " +
                                "for accurate Intune fleet counts."
                        ),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({
                operatingSystem,
                complianceState,
                managementState,
                managementAgent,
                ownerType,
                intuneManagedOnly,
                response_format = "markdown",
            }) => {
                try {
                    const data = await client.listManagedDevices({
                        operatingSystem,
                        complianceState,
                        managementState,
                        managementAgent,
                        ownerType,
                        intuneManagedOnly,
                    });

                    const text = toText(data, response_format, () => {
                        const devices: any[] = data.devices ?? [];
                        const filterNote = [
                            operatingSystem && `OS="${operatingSystem}"`,
                            complianceState && `compliance="${complianceState}"`,
                            managementState && `managementState="${managementState}"`,
                            managementAgent && `managementAgent="${managementAgent}"`,
                            ownerType && `ownerType="${ownerType}"`,
                            intuneManagedOnly && "intuneManagedOnly=true",
                        ]
                            .filter(Boolean)
                            .join(", ");

                        if (devices.length === 0) {
                            return `No managed devices found${filterNote ? ` matching ${filterNote}` : ""}.`;
                        }

                        const byOs = new Map<string, number>();
                        const byCompliance = new Map<string, number>();
                        const byAgent = new Map<string, number>();
                        const byOwnership = new Map<string, number>();
                        for (const d of devices) {
                            const os = d.operatingSystem ?? "Unknown";
                            const comp = d.complianceState ?? "unknown";
                            const agent = d.managementAgent ?? "unknown";
                            const ownership = d.ownerType ?? "unknown";
                            byOs.set(os, (byOs.get(os) ?? 0) + 1);
                            byCompliance.set(comp, (byCompliance.get(comp) ?? 0) + 1);
                            byAgent.set(agent, (byAgent.get(agent) ?? 0) + 1);
                            byOwnership.set(ownership, (byOwnership.get(ownership) ?? 0) + 1);
                        }

                        const sortedEntries = (m: Map<string, number>) =>
                            [...m.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `- **${k}:** ${v}`).join("\n");

                        const rows = devices
                            .slice(0, 50)
                            .map(
                                (d: any) =>
                                    `- **${d.deviceName ?? "Unknown"}** | ${d.operatingSystem ?? "—"} ${d.osVersion ?? ""} | Compliance: ${d.complianceState ?? "—"} | Serial: ${d.serialNumber ?? "—"}`
                            )
                            .join("\n");

                        const truncationNote = data.truncated
                            ? `\n\n_⚠️ Hit the pagination safety cap — counts above reflect only the first ${devices.length} devices fetched, not necessarily the entire tenant._`
                            : "";

                        return (
                            [
                                `## Managed Devices${filterNote ? ` (${filterNote})` : ""} — ${devices.length} total`,
                                `### By OS\n${sortedEntries(byOs)}`,
                                `### By Compliance State\n${sortedEntries(byCompliance)}`,
                                `### By Management Agent\n${sortedEntries(byAgent)}`,
                                `### By Ownership\n${sortedEntries(byOwnership)}`,
                                `### Devices (showing ${Math.min(50, devices.length)} of ${devices.length})\n${rows}${devices.length > 50 ? `\n_…and ${devices.length - 50} more_` : ""}`,
                            ].join("\n\n") + truncationNote
                        );
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 15. intune_create_win32_app ──────────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_create_win32_app",
            {
                description:
                    "Publish a Win32 app to Intune: creates a new app object, uploads and commits the .intunewin " +
                    "content (handling the Azure Storage chunked block upload and SAS URI polling internally), " +
                    "and marks it ready to assign. Always creates a NEW app object — this does not upsert by " +
                    "displayName; updating an existing app's installer means adding a new content version, a " +
                    "materially different operation. Use intune_assign_app_to_groups afterward to actually deploy " +
                    "it. `intunewinFileBase64` must be the raw .intunewin file produced by the Win32 Content Prep " +
                    "Tool, base64-encoded — practical for typical app sizes, but the whole decoded package is " +
                    "held in memory (no streaming), so very large installers may need a different path. `rules` " +
                    "must be Microsoft Graph win32LobAppRule objects (detection AND requirement rules in one " +
                    "array, each tagged with its own `ruleType` and `@odata.type`) — e.g. a file-existence " +
                    "detection rule: " +
                    '`{"@odata.type": "#microsoft.graph.win32LobAppFileSystemRule", "ruleType": "detection", ' +
                    '"operationType": "exists", "path": "C:\\\\Program Files\\\\App", "fileOrFolderName": "app.exe"}`. ' +
                    "At least one detection rule (ruleType: \"detection\") is required by Intune.",
                inputSchema: {
                    displayName: z.string().describe("App display name shown in Intune/Company Portal"),
                    description: z.string().optional(),
                    publisher: z.string().describe("Publisher name shown in Intune/Company Portal"),
                    installCommandLine: z.string().describe('e.g. "msiexec /i \\"App.msi\\" /qn"'),
                    uninstallCommandLine: z.string().describe('e.g. "msiexec /x \\"{GUID}\\" /qn"'),
                    applicableArchitectures: z.enum(["x86", "x64", "none"]).optional().describe("Default: x64"),
                    minimumSupportedWindowsRelease: z.string().optional().describe('e.g. "Windows10_1607", "Windows11_23H2" — default: "Windows10_1607"'),
                    runAsAccount: z.enum(["system", "user"]).optional().describe("Default: system"),
                    deviceRestartBehavior: z.enum(["basedOnReturnCode", "allow", "suppress", "force"]).optional().describe("Default: basedOnReturnCode"),
                    returnCodes: z
                        .array(z.object({ returnCode: z.number(), type: z.string() }))
                        .optional()
                        .describe("Defaults to the standard MSI success/reboot/retry code set if omitted"),
                    rules: z
                        .array(z.record(z.any()))
                        .min(1)
                        .describe("Microsoft Graph win32LobAppRule objects — see tool description for the required shape"),
                    intunewinFileBase64: z.string().describe("Base64-encoded .intunewin file contents"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                displayName, description, publisher, installCommandLine, uninstallCommandLine,
                applicableArchitectures, minimumSupportedWindowsRelease, runAsAccount, deviceRestartBehavior,
                returnCodes, rules, intunewinFileBase64, response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const result = await client.createWin32App({
                        displayName, description, publisher, installCommandLine, uninstallCommandLine,
                        applicableArchitectures, minimumSupportedWindowsRelease, runAsAccount, deviceRestartBehavior,
                        returnCodes, rules, intunewinFileBase64,
                    });
                    const text = toText(result, response_format, () =>
                        `Created and published Win32 app **${result.displayName}** (ID ${result.appId}, content version ${result.contentVersionId}). ` +
                        `Use intune_assign_app_to_groups to deploy it to a group.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 16. intune_assign_app_to_groups ──────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_assign_app_to_groups",
            {
                description:
                    "Assign an Intune app (Win32 or otherwise) to one or more Entra ID groups. IMPORTANT: this " +
                    "REPLACES the app's entire assignment set — it is not additive, matching Microsoft Graph's " +
                    "own /assign semantics. To widen or narrow an existing rollout, pass the full desired set of " +
                    "groups/intents each time, not just the ones being added. Use intune_get_group_members first " +
                    "to confirm a target group actually resolves to real members.",
                inputSchema: {
                    appId: z.string().describe("Intune app ID (GUID)"),
                    assignments: z
                        .array(z.object({
                            groupId: z.string().describe("Entra ID group GUID — use intune_get_group_members to resolve a name first"),
                            intent: z.enum(["required", "available", "uninstall"]),
                        }))
                        .min(1)
                        .describe("The full desired assignment set — replaces whatever is currently assigned"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ appId, assignments, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const result = await client.assignAppToGroups(appId, assignments);
                    const text = toText(result, response_format, () =>
                        `Assigned app ${result.appId} to ${result.assignments.length} group(s):\n` +
                        result.assignments.map((a: any) => `- ${a.groupId} (${a.intent})`).join("\n")
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 17. intune_send_device_action ────────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_send_device_action",
            {
                description:
                    "Send a remote action to a managed device in Intune. Accepts device name, Intune device ID, " +
                    "or serial number. Supported actions: Sync (trigger an immediate check-in), Reboot, RemoteLock " +
                    "(Android only), Retire (IRREVERSIBLE — removes company data and unenrolls the device from " +
                    "Intune), Wipe (IRREVERSIBLE — factory-resets the device). " +
                    "For Wipe, keepEnrollmentData/keepUserData let you do a 'reset but stay enrolled' style wipe; " +
                    "macOsUnlockCode is required to wipe a Mac with a firmware password/Activation Lock set.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    action: z.enum(["Sync", "Reboot", "RemoteLock", "Retire", "Wipe"]).describe("The remote action to send"),
                    keepEnrollmentData: z.boolean().optional().describe("Wipe only: keep MDM enrollment data (device stays enrolled after reset)"),
                    keepUserData: z.boolean().optional().describe("Wipe only: keep user data during the reset"),
                    macOsUnlockCode: z.string().optional().describe("Wipe only: 6-digit recovery PIN for wiping a Mac with a firmware password set"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true, destructiveHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, action, keepEnrollmentData, keepUserData, macOsUnlockCode }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    const actionMap = {
                        Sync: "sync",
                        Reboot: "reboot",
                        RemoteLock: "remoteLock",
                        Retire: "retire",
                        Wipe: "wipe",
                    } as const;

                    await client.sendManagedDeviceAction(resolved.deviceId, actionMap[action], {
                        keepEnrollmentData,
                        keepUserData,
                        macOsUnlockCode,
                    });

                    const text = `**${action}** sent successfully to device ${deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId}.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 18. intune_set_device_category ───────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_set_device_category",
            {
                description:
                    "Set the Intune device category for a managed device. Accepts device name, Intune device ID, " +
                    "or serial number. The category must already exist in Intune (categories are created in the " +
                    "Intune portal — there is no write API for creating them exposed here).",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    categoryName: z.string().describe("Exact display name of an existing Intune device category"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, categoryName }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    const result = await client.setDeviceCategory(resolved.deviceId, categoryName);
                    const text = `Device category set to **${result.category.displayName}** for device ${deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId}.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 19. intune_set_device_name ───────────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_set_device_name",
            {
                description:
                    "Rename a managed device in Intune via the setDeviceName remote action. Windows-only " +
                    "(the device must support remote rename) — this action has no v1.0 form in Graph, so it's " +
                    "called against the beta endpoint. The device will reflect the new name after its next check-in.",
                inputSchema: {
                    ...DeviceIdentifierSchema,
                    newDeviceName: z.string().describe("The new device name to set"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ deviceName, deviceId, serialNumber, newDeviceName }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const resolved = await resolveDevice(client, { deviceName, deviceId, serialNumber });
                    if (!resolved) {
                        return notFound(`device (name: "${deviceName ?? "—"}", id: "${deviceId ?? "—"}", serial: "${serialNumber ?? "—"}")`);
                    }

                    await client.setDeviceName(resolved.deviceId, newDeviceName);
                    const text = `Rename to **${newDeviceName}** sent successfully for device ${deviceName ?? deviceId ?? serialNumber ?? resolved.deviceId}. It will take effect after the device's next check-in.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 20. intune_set_autopilot_group_tag ───────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_set_autopilot_group_tag",
            {
                description:
                    "Set the Windows Autopilot group tag for a device by serial number (or device name, resolved " +
                    "to serial automatically). Group tags are the standard mechanism for dynamic Azure AD group " +
                    "membership rules based on Autopilot registration, so this is the way to retroactively sort " +
                    "already-registered devices into those groups without re-running Autopilot registration.",
                inputSchema: {
                    serialNumber: z.string().optional().describe("Device serial number (preferred for Autopilot lookups)"),
                    deviceName: z.string().optional().describe("Intune device display name (resolved to serial automatically)"),
                    groupTag: z.string().describe("The group tag value to set"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ serialNumber, deviceName, groupTag }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let targetSerial = serialNumber;

                    if (deviceName && !targetSerial) {
                        const device = await client.getManagedDeviceByName(deviceName);
                        if (!device) return notFound(`device "${deviceName}"`);
                        targetSerial = (device as any).serialNumber;
                    }

                    if (!targetSerial) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide serialNumber or deviceName." }],
                        };
                    }

                    const result = await client.updateAutopilotGroupTag(targetSerial, groupTag);
                    const text = `Autopilot group tag set to **${result.groupTag}** for serial **${result.serialNumber}**.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 21. intune_assign_policy ──────────────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_assign_policy",
            {
                description:
                    "Add (or move) a group assignment on an Intune configuration policy — classic device " +
                    "configuration or Settings Catalog. Accepts policy by ID or name. " +
                    "IMPORTANT: Graph's assign action REPLACES the entire assignment set rather than appending " +
                    "to it, so this tool always reads the policy's current assignments first, removes any " +
                    "existing assignment for the same group (so calling again with a different exclude value " +
                    "moves the group rather than duplicating it), adds the new one, and posts the full set back — " +
                    "other groups' assignments are preserved untouched.",
                inputSchema: {
                    policyId: z.string().optional().describe("Intune policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    source: z
                        .enum(["classic", "settingsCatalog", "auto"])
                        .default("auto")
                        .describe('Policy type: "classic" for device configuration profiles, "settingsCatalog" for Settings Catalog, "auto" to detect (default)'),
                    group: z.string().describe("Azure AD group display name or object ID (GUID) to assign"),
                    exclude: z.boolean().optional().describe("If true, EXCLUDE this group from the policy's scope instead of including it"),
                    filterId: z.string().optional().describe("Optional assignment filter ID to attach to this assignment"),
                    filterType: z.enum(["include", "exclude"]).optional().describe('How the filter narrows scope (default "include"). Only used if filterId is set.'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ policyId, policyName, source = "auto", group, exclude, filterId, filterType, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedPolicyId = policyId;
                    let resolvedSource: "classic" | "settingsCatalog" | undefined;
                    let resolvedName = policyName;

                    if (!resolvedPolicyId && policyName) {
                        const resolved = await resolvePolicyByName(client, policyName, source);
                        if (!resolved) return notFound(`policy "${policyName}"`);
                        resolvedPolicyId = resolved.policyId;
                        resolvedSource = resolved.source;
                        resolvedName = resolved.policyName;
                    }

                    if (!resolvedPolicyId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide policyId or policyName." }],
                        };
                    }

                    if (!resolvedSource) {
                        if (source === "auto") {
                            return {
                                isError: true,
                                content: [{ type: "text", text: "Error: source must be \"classic\" or \"settingsCatalog\" when providing policyId directly (auto-detection requires policyName)." }],
                            };
                        }
                        resolvedSource = source;
                    }

                    const result = await client.assignConfigurationPolicyToGroup(resolvedPolicyId, resolvedSource, group, {
                        exclude,
                        filterId,
                        filterType,
                    });

                    const text = toText(result, response_format, () => {
                        const label = resolvedName ?? resolvedPolicyId;
                        const direction = exclude ? "excluded from" : "included in";
                        return [
                            `## Assignment updated — "${label}"`,
                            `Group **${result.group.displayName}** is now ${direction} this policy's scope.`,
                            `- Total assignments on policy: ${result.totalAssignments}`,
                            result.replacedExistingForGroup ? `- This replaced a prior assignment for the same group.` : "",
                        ].filter(Boolean).join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 22. intune_assign_app ─────────────────────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_assign_app",
            {
                description:
                    "Add (or move) a group assignment on an Intune app deployment, with the given install intent. " +
                    "Accepts app by ID or name. " +
                    "IMPORTANT: Graph's assign action REPLACES the entire assignment set rather than appending " +
                    "to it, so this tool always reads the app's current assignments first, removes any existing " +
                    "assignment for the same group (so calling again with a different intent or exclude value " +
                    "moves the group rather than duplicating it), adds the new one, and posts the full set back — " +
                    "other groups' assignments are preserved untouched.",
                inputSchema: {
                    appId: z.string().optional().describe("Intune mobile app ID (GUID). Use if you already have it."),
                    appName: z.string().optional().describe("App display name (resolved to ID automatically)"),
                    group: z.string().describe("Azure AD group display name or object ID (GUID) to assign"),
                    intent: z
                        .enum(["required", "available", "uninstall", "availableWithoutEnrollment"])
                        .default("required")
                        .describe("Install intent for this assignment"),
                    exclude: z.boolean().optional().describe("If true, EXCLUDE this group from the app's scope instead of including it"),
                    filterId: z.string().optional().describe("Optional assignment filter ID to attach to this assignment"),
                    filterType: z.enum(["include", "exclude"]).optional().describe('How the filter narrows scope (default "include"). Only used if filterId is set.'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ appId, appName, group, intent = "required", exclude, filterId, filterType, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedAppId = appId;
                    let resolvedAppName = appName;

                    if (!resolvedAppId && appName) {
                        const resolved = await resolveAppByName(client, appName);
                        if (!resolved) return notFound(`app "${appName}"`);
                        resolvedAppId = resolved.appId;
                        resolvedAppName = resolved.appName;
                    }

                    if (!resolvedAppId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide appId or appName." }],
                        };
                    }

                    const result = await client.assignAppToGroup(resolvedAppId, group, intent, { exclude, filterId, filterType });

                    const text = toText(result, response_format, () => {
                        const label = resolvedAppName ?? resolvedAppId;
                        const direction = exclude ? "excluded from" : `included in (intent: ${intent})`;
                        return [
                            `## Assignment updated — "${label}"`,
                            `Group **${result.group.displayName}** is now ${direction} this app's scope.`,
                            `- Total assignments on app: ${result.totalAssignments}`,
                            result.replacedExistingForGroup ? `- This replaced a prior assignment for the same group.` : "",
                        ].filter(Boolean).join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 23. intune_get_configuration_profile ─────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_configuration_profile",
            {
                description:
                    "Get the full detail of a single Intune configuration policy — classic device configuration " +
                    "or Settings Catalog — by ID or name. Unlike intune_list_configuration_policies (metadata only), " +
                    "this returns the actual policy body: every type-specific property for classic profiles, or the " +
                    "full settings array (settingDefinitionId + value for each configured setting) for Settings " +
                    "Catalog policies. Use response_format=\"json\" to get the raw settings array as a template " +
                    "before calling intune_create_android_configuration_profile or intune_update_configuration_profile.",
                inputSchema: {
                    policyId: z.string().optional().describe("Intune policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    source: z
                        .enum(["classic", "settingsCatalog", "auto"])
                        .default("auto")
                        .describe('Policy type: "classic" for device configuration profiles, "settingsCatalog" for Settings Catalog, "auto" to detect (default)'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyId, policyName, source = "auto", response_format = "markdown" }) => {
                try {
                    let resolvedPolicyId = policyId;
                    let resolvedSource: "classic" | "settingsCatalog" | undefined;
                    let resolvedName = policyName;

                    if (!resolvedPolicyId && policyName) {
                        const resolved = await resolvePolicyByName(client, policyName, source);
                        if (!resolved) return notFound(`policy "${policyName}"`);
                        resolvedPolicyId = resolved.policyId;
                        resolvedSource = resolved.source;
                        resolvedName = resolved.policyName;
                    }

                    if (!resolvedPolicyId) {
                        return {
                            isError: true,
                            content: [{ type: "text", text: "Error: provide policyId or policyName." }],
                        };
                    }

                    if (!resolvedSource) {
                        if (source === "auto") {
                            return {
                                isError: true,
                                content: [{ type: "text", text: "Error: source must be \"classic\" or \"settingsCatalog\" when providing policyId directly (auto-detection requires policyName)." }],
                            };
                        }
                        resolvedSource = source;
                    }

                    const detail = await client.getConfigurationPolicyDetail(resolvedPolicyId, resolvedSource);

                    const text = toText(detail, response_format, () => {
                        const label = resolvedName ?? resolvedPolicyId;
                        const d = detail as any;

                        if (d.source === "classic") {
                            const raw = d.raw ?? {};
                            const skipKeys = new Set(["id", "displayName", "description", "@odata.type", "createdDateTime", "lastModifiedDateTime", "version", "roleScopeTagIds", "supportsScopeTags"]);
                            const propRows = Object.entries(raw)
                                .filter(([k]) => !skipKeys.has(k))
                                .map(([k, v]) => `- **${k}**: ${JSON.stringify(v)}`)
                                .join("\n");
                            return [
                                `## Configuration Profile — "${label}" (classic)`,
                                `Type: ${raw["@odata.type"] ?? "—"}`,
                                d.description ? `Description: ${d.description}` : "",
                                `Modified: ${raw.lastModifiedDateTime ?? "—"}`,
                                `\n### Properties\n${propRows || "_None_"}`,
                            ].filter(Boolean).join("\n");
                        }

                        const settings: any[] = d.settings ?? [];
                        const preview = settings.slice(0, 20)
                            .map((s: any) => `- ${s.settingInstance?.settingDefinitionId ?? "(unknown setting)"}`)
                            .join("\n");
                        const truncatedNote = settings.length > 20 ? `\n_...and ${settings.length - 20} more (use response_format="json" to see all)_` : "";
                        return [
                            `## Configuration Profile — "${label}" (Settings Catalog)`,
                            `Platform: ${d.platforms || "—"} | Technologies: ${d.technologies || "—"}`,
                            d.description ? `Description: ${d.description}` : "",
                            `Settings: ${d.settingsCount}`,
                            `\n### Configured settings\n${preview || "_None_"}${truncatedNote}`,
                        ].filter(Boolean).join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 24. intune_list_compliance_policies ──────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_compliance_policies",
            {
                description:
                    "List device compliance policies in Microsoft Intune. Optionally filter by name or platform " +
                    "(e.g. \"androidWorkProfile\", \"androidDeviceOwner\", \"windows10\", \"ios\", \"macos\"). " +
                    "Returns policy ID, name, inferred platform, and last modified date.",
                inputSchema: {
                    policyName: z.string().optional().describe("Optional name filter (case-insensitive substring match)"),
                    platform: z.string().optional().describe('Optional platform filter (e.g. "android", "androidWorkProfile", "androidDeviceOwner")'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyName, platform, response_format = "markdown" }) => {
                try {
                    const data = await client.getCompliancePolicies({ policyName, platform });

                    const text = toText(data, response_format, () => {
                        const policies: any[] = (data as any).policies ?? [];
                        if (policies.length === 0) {
                            const filters = [policyName && `name: "${policyName}"`, platform && `platform: "${platform}"`].filter(Boolean).join(", ");
                            return `No compliance policies found${filters ? ` matching ${filters}` : ""}.`;
                        }
                        const rows = policies
                            .map((p: any) => `- **${p.name}** (ID: ${p.id}) | Platform: ${p.platformHint} | Modified: ${p.lastModifiedDateTime ?? "—"}`)
                            .join("\n");
                        return `## Compliance Policies — ${policies.length} total\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 25. intune_get_compliance_policy ─────────────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_compliance_policy",
            {
                description:
                    "Get the full detail and group assignments of a single Intune compliance policy, by ID or name.",
                inputSchema: {
                    policyId: z.string().optional().describe("Compliance policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyId, policyName, response_format = "markdown" }) => {
                try {
                    let resolvedId = policyId;
                    let resolvedName = policyName;
                    if (!resolvedId && policyName) {
                        const resolved = await resolveCompliancePolicyByName(client, policyName);
                        if (!resolved) return notFound(`compliance policy "${policyName}"`);
                        resolvedId = resolved.policyId;
                        resolvedName = resolved.policyName;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide policyId or policyName." }] };
                    }

                    const detail = await client.getCompliancePolicyDetail(resolvedId);

                    const text = toText(detail, response_format, () => {
                        const d = detail as any;
                        const label = resolvedName ?? resolvedId;
                        const targetRows = (d.resolvedTargets ?? [])
                            .map((t: any) => `- ${t.type === "includeGroup" ? "Include" : t.type === "excludeGroup" ? "Exclude" : t.type}: **${t.displayName ?? t.id}**`)
                            .join("\n");
                        return [
                            `## Compliance Policy — "${label}"`,
                            `Type: ${d.odataType ?? "—"}`,
                            d.description ? `Description: ${d.description}` : "",
                            `\n### Assignments (${d.summary?.totalAssignments ?? 0})\n${targetRows || "_None_"}`,
                        ].filter(Boolean).join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 26. intune_create_android_compliance_policy ─────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_create_android_compliance_policy",
            {
                description:
                    "Create an Android compliance policy (work profile or device owner variant). `settings` is a " +
                    "passthrough object of Graph's own androidWorkProfileCompliancePolicy/androidDeviceOwnerCompliancePolicy " +
                    "property names (e.g. passwordRequired, passwordMinimumLength, securityBlockJailbrokenDevices, " +
                    "storageRequireEncryption, minAndroidSecurityPatchLevel, securityPreventInstallAppsFromUnknownSources) — " +
                    "consult Microsoft Graph's deviceCompliancePolicy documentation for the full property list per variant. " +
                    "A default \"mark noncompliant immediately\" scheduled action is attached if scheduledActionsForRule is omitted.",
                inputSchema: {
                    name: z.string().describe("Display name for the new compliance policy"),
                    description: z.string().optional(),
                    androidVariant: z.enum(["workProfile", "deviceOwner"]).describe("Android Enterprise enrollment variant this policy targets"),
                    settings: z.record(z.any()).optional().describe("Passthrough compliance settings, using Graph's own property names for the chosen variant"),
                    scheduledActionsForRule: z.array(z.record(z.any())).optional().describe("Advanced: override the default scheduled noncompliance action(s)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, description, androidVariant, settings, scheduledActionsForRule, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const result = await client.createAndroidCompliancePolicy({ name, description, androidVariant, settings, scheduledActionsForRule });

                    const text = toText(result, response_format, () =>
                        `## Compliance policy created — "${result.name}"\n- ID: ${result.id}\n- Variant: ${result.androidVariant}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 27. intune_update_compliance_policy ──────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_update_compliance_policy",
            {
                description:
                    "Update fields on an existing compliance policy, by ID or name. `updates` is a passthrough " +
                    "object merged into the policy (use \"name\"/\"description\" for those two; any other key is " +
                    "sent verbatim as a Graph property name for the policy's existing @odata.type).",
                inputSchema: {
                    policyId: z.string().optional().describe("Compliance policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    updates: z.record(z.any()).describe("Fields to update, using Graph's own property names (plus \"name\" for displayName)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ policyId, policyName, updates, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedId = policyId;
                    let resolvedName = policyName;
                    if (!resolvedId && policyName) {
                        const resolved = await resolveCompliancePolicyByName(client, policyName);
                        if (!resolved) return notFound(`compliance policy "${policyName}"`);
                        resolvedId = resolved.policyId;
                        resolvedName = resolved.policyName;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide policyId or policyName." }] };
                    }

                    const result = await client.updateAndroidCompliancePolicy(resolvedId, updates);

                    const text = toText(result, response_format, () =>
                        `## Compliance policy updated — "${resolvedName ?? resolvedId}"\n- Updated fields: ${result.updatedFields.join(", ")}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 28. intune_assign_compliance_policy ──────────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_assign_compliance_policy",
            {
                description:
                    "Add (or move) a group assignment on an Intune compliance policy, by ID or name. " +
                    "IMPORTANT: Graph's assign action REPLACES the entire assignment set rather than appending " +
                    "to it, so this tool always reads the policy's current assignments first, removes any " +
                    "existing assignment for the same group, adds the new one, and posts the full set back — " +
                    "other groups' assignments are preserved untouched.",
                inputSchema: {
                    policyId: z.string().optional().describe("Compliance policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    group: z.string().describe("Azure AD group display name or object ID (GUID) to assign"),
                    exclude: z.boolean().optional().describe("If true, EXCLUDE this group from the policy's scope instead of including it"),
                    filterId: z.string().optional().describe("Optional assignment filter ID to attach to this assignment"),
                    filterType: z.enum(["include", "exclude"]).optional().describe('How the filter narrows scope (default "include"). Only used if filterId is set.'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ policyId, policyName, group, exclude, filterId, filterType, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedId = policyId;
                    let resolvedName = policyName;
                    if (!resolvedId && policyName) {
                        const resolved = await resolveCompliancePolicyByName(client, policyName);
                        if (!resolved) return notFound(`compliance policy "${policyName}"`);
                        resolvedId = resolved.policyId;
                        resolvedName = resolved.policyName;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide policyId or policyName." }] };
                    }

                    const result = await client.assignCompliancePolicyToGroup(resolvedId, group, { exclude, filterId, filterType });

                    const text = toText(result, response_format, () => {
                        const label = resolvedName ?? resolvedId;
                        const direction = exclude ? "excluded from" : "included in";
                        return [
                            `## Assignment updated — "${label}"`,
                            `Group **${result.group.displayName}** is now ${direction} this policy's scope.`,
                            `- Total assignments on policy: ${result.totalAssignments}`,
                            result.replacedExistingForGroup ? `- This replaced a prior assignment for the same group.` : "",
                        ].filter(Boolean).join("\n");
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 29. intune_create_android_configuration_profile ──────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_create_android_configuration_profile",
            {
                description:
                    "Create an Android configuration profile as a Settings Catalog policy — this tenant's actual " +
                    "Android config-profile model (there are no classic Android device-config objects here). " +
                    "`settings` is a raw passthrough array of Graph settingInstance objects (advanced — construct " +
                    "it by reading an existing similar policy via intune_get_configuration_profile with " +
                    "response_format=\"json\" and using its `settings` array as a copy-and-modify template).",
                inputSchema: {
                    name: z.string().describe("Display name for the new configuration profile"),
                    description: z.string().optional(),
                    settings: z.array(z.record(z.any())).describe("Raw Settings Catalog settingInstance objects"),
                    platforms: z.string().optional().describe('Defaults to "androidEnterprise"'),
                    technologies: z.string().optional().describe('Defaults to "android"'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, description, settings, platforms, technologies, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const result = await client.createSettingsCatalogPolicy({ name, description, settings, platforms, technologies });

                    const text = toText(result, response_format, () =>
                        `## Configuration profile created — "${result.name}"\n- ID: ${result.id}\n- Platform: ${result.platforms} | Technologies: ${result.technologies}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 30. intune_update_configuration_profile ──────────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_update_configuration_profile",
            {
                description:
                    "Update a configuration profile's name, description, or (Settings Catalog only) settings array, " +
                    "by ID or name. For classic device configuration profiles, only name/description are supported " +
                    "here (other type-specific fields aren't modeled); for Settings Catalog, `settings` fully " +
                    "replaces the existing settings array if provided.",
                inputSchema: {
                    policyId: z.string().optional().describe("Policy ID (GUID). Use if you already have it."),
                    policyName: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    source: z
                        .enum(["classic", "settingsCatalog", "auto"])
                        .default("auto")
                        .describe('Policy type: "classic" for device configuration profiles, "settingsCatalog" for Settings Catalog, "auto" to detect (default)'),
                    name: z.string().optional().describe("New display name"),
                    description: z.string().optional().describe("New description"),
                    settings: z.array(z.record(z.any())).optional().describe("Settings Catalog only: full replacement settings array"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ policyId, policyName, source = "auto", name, description, settings, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedId = policyId;
                    let resolvedSource: "classic" | "settingsCatalog" | undefined;
                    let resolvedName = policyName;

                    if (!resolvedId && policyName) {
                        const resolved = await resolvePolicyByName(client, policyName, source);
                        if (!resolved) return notFound(`policy "${policyName}"`);
                        resolvedId = resolved.policyId;
                        resolvedSource = resolved.source;
                        resolvedName = resolved.policyName;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide policyId or policyName." }] };
                    }
                    if (!resolvedSource) {
                        if (source === "auto") {
                            return { isError: true, content: [{ type: "text", text: "Error: source must be \"classic\" or \"settingsCatalog\" when providing policyId directly (auto-detection requires policyName)." }] };
                        }
                        resolvedSource = source;
                    }

                    if (resolvedSource === "classic" && settings !== undefined) {
                        return { isError: true, content: [{ type: "text", text: "Error: settings updates are only supported for Settings Catalog policies." }] };
                    }

                    const updates: Record<string, any> = {};
                    if (name !== undefined) updates.name = name;
                    if (description !== undefined) updates.description = description;
                    if (settings !== undefined) updates.settings = settings;

                    const result = resolvedSource === "classic"
                        ? await client.updateClassicConfigurationProfile(resolvedId, updates)
                        : await client.updateSettingsCatalogPolicy(resolvedId, updates);

                    const text = toText(result, response_format, () =>
                        `## Configuration profile updated — "${resolvedName ?? resolvedId}"\n- Updated fields: ${result.updatedFields.join(", ")}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 31. intune_list_app_configuration_policies ───────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_app_configuration_policies",
            {
                description:
                    "List Intune app configuration policies (mobileAppConfigurations), which carry regular managed-app " +
                    "config and OEMConfig payloads for Android Enterprise apps. Optionally filter by name.",
                inputSchema: {
                    name: z.string().optional().describe("Optional name filter (case-insensitive substring match)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ name, response_format = "markdown" }) => {
                try {
                    const data = await client.getAppConfigurationPolicies({ name });

                    const text = toText(data, response_format, () => {
                        const policies: any[] = (data as any).policies ?? [];
                        if (policies.length === 0) {
                            return `No app configuration policies found${name ? ` matching name: "${name}"` : ""}.`;
                        }
                        const rows = policies
                            .map((p: any) => `- **${p.name}** (ID: ${p.id}) | Targeted apps: ${p.targetedMobileApps.length} | Modified: ${p.lastModifiedDateTime ?? "—"}`)
                            .join("\n");
                        return `## App Configuration Policies — ${policies.length} total\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 32. intune_get_app_configuration_policy ──────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_get_app_configuration_policy",
            {
                description:
                    "Get the full detail (including decoded OEMConfig payload, if present) and group assignments " +
                    "of a single app configuration policy, by ID or name.",
                inputSchema: {
                    id: z.string().optional().describe("App configuration policy ID (GUID). Use if you already have it."),
                    name: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ id, name, response_format = "markdown" }) => {
                try {
                    let resolvedId = id;
                    let resolvedName = name;
                    if (!resolvedId && name) {
                        const resolved = await resolveAppConfigurationPolicyByName(client, name);
                        if (!resolved) return notFound(`app configuration policy "${name}"`);
                        resolvedId = resolved.id;
                        resolvedName = resolved.name;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide id or name." }] };
                    }

                    const detail = await client.getAppConfigurationPolicyDetail(resolvedId);

                    const text = toText(detail, response_format, () => {
                        const d = detail as any;
                        const label = resolvedName ?? resolvedId;
                        return [
                            `## App Configuration Policy — "${label}"`,
                            `Type: ${d.odataType ?? "—"}`,
                            d.description ? `Description: ${d.description}` : "",
                            `Targeted apps: ${d.targetedMobileApps.length}`,
                            `Assignments: ${d.assignments.length}`,
                            d.decodedPayload ? `\n### Decoded payload\n\`\`\`json\n${JSON.stringify(d.decodedPayload, null, 2)}\n\`\`\`` : "",
                        ].filter(Boolean).join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 33. intune_create_android_app_configuration_policy ───────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_create_android_app_configuration_policy",
            {
                description:
                    "Create an Android app configuration policy (OEMConfig or regular managed-app config — both use " +
                    "the same Graph type). NOT LIVE-VERIFIED: this tenant has no Android app in its Intune catalog " +
                    "today to test end-to-end, so this path is built to Graph's documented shape but unconfirmed — " +
                    "validate carefully against a real Managed Google Play app before relying on it in production.",
                inputSchema: {
                    name: z.string().describe("Display name for the new app configuration policy"),
                    description: z.string().optional(),
                    targetedAppId: z.string().describe("Intune mobile app ID (GUID) of the Android Managed Store app this config targets"),
                    payloadJson: z.record(z.any()).optional().describe("OEMConfig/managed-app JSON payload (encoded to base64 automatically)"),
                    permissionActions: z.array(z.record(z.any())).optional().describe("Advanced: runtime permission grant/deny actions"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, description, targetedAppId, payloadJson, permissionActions, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    const result = await client.createAndroidAppConfigurationPolicy({ name, description, targetedAppId, payloadJson, permissionActions });

                    const text = toText(result, response_format, () =>
                        `## App configuration policy created — "${result.name}"\n- ID: ${result.id}\n- Targeted app: ${result.targetedAppId}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 34. intune_update_app_configuration_policy ───────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_update_app_configuration_policy",
            {
                description:
                    "Update an app configuration policy's name, description, or payload, by ID or name. " +
                    "NOT LIVE-VERIFIED — see intune_create_android_app_configuration_policy.",
                inputSchema: {
                    id: z.string().optional().describe("App configuration policy ID (GUID). Use if you already have it."),
                    name: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    newName: z.string().optional().describe("New display name"),
                    description: z.string().optional().describe("New description"),
                    payloadJson: z.record(z.any()).optional().describe("New OEMConfig/managed-app JSON payload (encoded to base64 automatically)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ id, name, newName, description, payloadJson, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedId = id;
                    let resolvedName = name;
                    if (!resolvedId && name) {
                        const resolved = await resolveAppConfigurationPolicyByName(client, name);
                        if (!resolved) return notFound(`app configuration policy "${name}"`);
                        resolvedId = resolved.id;
                        resolvedName = resolved.name;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide id or name." }] };
                    }

                    const result = await client.updateAndroidAppConfigurationPolicy(resolvedId, { name: newName, description, payloadJson });

                    const text = toText(result, response_format, () =>
                        `## App configuration policy updated — "${resolvedName ?? resolvedId}"\n- Updated fields: ${result.updatedFields.join(", ")}`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 35. intune_assign_app_configuration_policy ───────────────────────────
    if (hasRole(roles, INTUNE_WRITE)) {
        server.registerTool(
            "intune_assign_app_configuration_policy",
            {
                description:
                    "Add (or move) a group assignment on an app configuration policy, by ID or name. Same " +
                    "replace-the-whole-set /assign semantics as the other assignment tools. " +
                    "NOT LIVE-VERIFIED — see intune_create_android_app_configuration_policy.",
                inputSchema: {
                    id: z.string().optional().describe("App configuration policy ID (GUID). Use if you already have it."),
                    name: z.string().optional().describe("Policy display name (resolved to ID automatically)"),
                    group: z.string().describe("Azure AD group display name or object ID (GUID) to assign"),
                    exclude: z.boolean().optional().describe("If true, EXCLUDE this group from the policy's scope instead of including it"),
                    filterId: z.string().optional().describe("Optional assignment filter ID to attach to this assignment"),
                    filterType: z.enum(["include", "exclude"]).optional().describe('How the filter narrows scope (default "include"). Only used if filterId is set.'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ id, name, group, exclude, filterId, filterType, response_format = "markdown" }) => {
                try {
                    assertRole(roles, INTUNE_WRITE);
                    let resolvedId = id;
                    let resolvedName = name;
                    if (!resolvedId && name) {
                        const resolved = await resolveAppConfigurationPolicyByName(client, name);
                        if (!resolved) return notFound(`app configuration policy "${name}"`);
                        resolvedId = resolved.id;
                        resolvedName = resolved.name;
                    }
                    if (!resolvedId) {
                        return { isError: true, content: [{ type: "text", text: "Error: provide id or name." }] };
                    }

                    const result = await client.assignAppConfigurationPolicyToGroup(resolvedId, group, { exclude, filterId, filterType });

                    const text = toText(result, response_format, () => {
                        const label = resolvedName ?? resolvedId;
                        const direction = exclude ? "excluded from" : "included in";
                        return [
                            `## Assignment updated — "${label}"`,
                            `Group **${result.group.displayName}** is now ${direction} this policy's scope.`,
                            `- Total assignments on policy: ${result.totalAssignments}`,
                            result.replacedExistingForGroup ? `- This replaced a prior assignment for the same group.` : "",
                        ].filter(Boolean).join("\n");
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 36. intune_list_conditional_access_policies ──────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_conditional_access_policies",
            {
                description:
                    "List Entra Conditional Access policies — name, state (enabled/disabled/reportOnly), " +
                    "targeted apps/platforms/users, and grant controls (MFA, compliant device required, etc). " +
                    "Read-only, no write tool exists for Conditional Access here. " +
                    "NOT YET WORKING (confirmed live 2026-07-28) — this app registration's token is missing the " +
                    "Policy.Read.All Graph application permission; the call cleanly 403s with 'required scopes are " +
                    "missing in the token' until an Entra admin grants and consents it, at which point this will " +
                    "start working with no code change.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getConditionalAccessPolicies();

                    const text = toText(data, response_format, () => {
                        const policies: any[] = data.policies ?? [];
                        if (policies.length === 0) return "No Conditional Access policies found.";

                        const rows = policies
                            .map((p: any) => {
                                const grant = p.grantControls?.builtInControls?.join(", ") || p.grantControls?.customAuthenticationFactors?.join(", ") || "—";
                                const platforms = p.conditions?.platforms?.includePlatforms?.join(", ") || "—";
                                return `- **${p.displayName ?? p.id}** | State: ${p.state ?? "—"} | Grant: ${grant} | Platforms: ${platforms}`;
                            })
                            .join("\n");

                        return `## Conditional Access Policies — ${policies.length} total\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 37. intune_list_enrollment_restrictions ──────────────────────────────
    if (hasRole(roles, INTUNE_READ)) {
        server.registerTool(
            "intune_list_enrollment_restrictions",
            {
                description:
                    "List device enrollment configurations — backs Devices > Enrollment restrictions in the " +
                    "Intune admin center, including per-platform device-type restrictions (e.g. blocking " +
                    "personally-owned Windows enrollment) and their priority order. Read-only; no write tool " +
                    "exists here since enabling a restriction has real enrollment-blocking consequences that " +
                    "should go through the admin center deliberately. " +
                    "Confirmed live 2026-07-28 — returned 8 real configurations for this tenant with no permission gap.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getEnrollmentRestrictions();

                    const text = toText(data, response_format, () => {
                        const configs: any[] = data.configurations ?? [];
                        if (configs.length === 0) return "No enrollment configurations found.";

                        const rows = configs
                            .map(
                                (c: any) =>
                                    `- **${c.displayName ?? c.id}** | Type: ${c.deviceEnrollmentConfigurationType ?? "—"} | Priority: ${c.priority ?? "—"}${c.description ? `\n  ${c.description}` : ""}`
                            )
                            .join("\n");

                        return `## Enrollment Restrictions — ${configs.length} total\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    return server;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

async function main() {
    const app = express();
    app.use(express.json());
    // Mounted before routes so it wraps everything below, including /health and /metrics itself.
    app.use(metricsMiddleware);

    const PORT = parseInt(process.env.PORT ?? "3002", 10);
    const publicUrl = process.env.INTUNE_MCP_PUBLIC_URL;
    const entraOAuthEnabled = process.env.ENTRA_OAUTH_ENABLED === "true";
    const resourceMetadataUrl = publicUrl ? getOAuthProtectedResourceMetadataUrl(new URL(`${publicUrl}/mcp`)) : undefined;

    if (entraOAuthEnabled) {
        if (!publicUrl) {
            throw new Error("INTUNE_MCP_PUBLIC_URL must be set when ENTRA_OAUTH_ENABLED=true");
        }
        const tenantId = process.env.ENTRA_TENANT_ID;
        if (!tenantId) {
            throw new Error("ENTRA_TENANT_ID must be set when ENTRA_OAUTH_ENABLED=true");
        }
        app.use(
            mcpAuthMetadataRouter({
                oauthMetadata: buildEntraOAuthMetadata(tenantId),
                resourceServerUrl: new URL(`${publicUrl}/mcp`),
                resourceName: "Intune MCP Server",
            })
        );
    }

    app.use(
        "/mcp",
        requireMcpAuth({
            staticTokenEnvVar: "INTUNE_MCP_AUTH_TOKEN",
            allRoles: INTUNE_ALL_ROLES,
            entraVerifier: createEntraVerifier({
                tenantId: process.env.ENTRA_TENANT_ID ?? "",
                audience: [process.env.ENTRA_RESOURCE_APP_ID_URI, process.env.ENTRA_RESOURCE_APP_ID].filter(
                    (v): v is string => !!v
                ),
            }),
            entraEnabledEnvVar: "ENTRA_OAUTH_ENABLED",
            resourceMetadataUrl,
        })
    );

    // Each request gets its own transport (stateless mode — required for APIM / multi-instance)
    app.post("/mcp", async (req: Request, res: Response) => {
        try {
            const roles = req.auth?.extra.roles ?? [];
            const caller = req.auth?.extra.upn ?? req.auth?.clientId ?? "unknown";
            const server = createIntuneMcpServer(roles, caller);
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: undefined, // stateless
            });

            res.on("close", () => {
                transport.close();
                server.close();
            });

            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch (err) {
            console.error("[intune-mcp] Error handling request:", err);
            if (!res.headersSent) {
                res.status(500).json({ error: "Internal server error" });
            }
        }
    });

    // MCP spec: GET and DELETE on /mcp return 405 for stateless servers
    app.get("/mcp", (_req: Request, res: Response) => {
        res.status(405).json({ error: "Method not allowed. This server uses stateless Streamable HTTP." });
    });

    app.delete("/mcp", (_req: Request, res: Response) => {
        res.status(405).json({ error: "Method not allowed. This server uses stateless Streamable HTTP." });
    });

    // Health check for APIM / load balancers
    app.get("/health", (_req: Request, res: Response) => {
        res.json({ status: "ok", server: "intune-mcp-server", version: "1.0.0" });
    });

    // Scraped by Prometheus. Open like /health — not behind requireMcpAuth — since
    // both servers are loopback-bound in production, fronted by Caddy.
    app.get("/metrics", metricsHandler);

    app.listen(PORT, () => {
        console.log(`[intune-mcp] Intune MCP server listening on port ${PORT}`);
        console.log(`[intune-mcp] MCP endpoint: http://localhost:${PORT}/mcp`);
        console.log(`[intune-mcp] Tenant: ${process.env.AZURE_TENANT_ID ?? "(not set)"}`);
    });
}

main().catch((err) => {
    console.error("[intune-mcp] Fatal error:", err);
    process.exit(1);
});
