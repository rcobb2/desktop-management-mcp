/**
 * Microsoft Intune MCP Server
 *
 * Standalone Streamable HTTP MCP server exposing Microsoft Intune device management,
 * configuration policies, app deployments, and troubleshooting via the Model Context Protocol.
 *
 * Transport: Streamable HTTP — deploy behind Azure APIM or any reverse proxy.
 *
 * Environment variables:
 *   AZURE_TENANT_ID      Azure AD tenant ID
 *   AZURE_CLIENT_ID      App registration client ID
 *   AZURE_CLIENT_SECRET  App registration client secret
 *   PORT                 HTTP port to listen on (default: 3002)
 */

import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { IntuneClient } from "../intune/graph-api.js";

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

const DeviceIdentifierSchema = {
    deviceName: z.string().optional().describe("Device display name in Intune"),
    deviceId: z.string().optional().describe("Intune managed device ID (GUID)"),
    serialNumber: z.string().optional().describe("Device serial number"),
};

// ─── Server factory ───────────────────────────────────────────────────────────

function createIntuneMcpServer(): McpServer {
    const client = new IntuneClient();

    const server = new McpServer({
        name: "intune-mcp-server",
        version: "1.0.0",
    });

    // ── 1. intune_get_device_by_name ─────────────────────────────────────────
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
                        `- **Last Sync:** ${d.lastSyncDateTime ?? "—"}`,
                        `- **Enrolled:** ${d.enrolledDateTime ?? "—"}`,
                        `- **Assigned User:** ${d.userDisplayName ?? "—"} (${d.userPrincipalName ?? "—"})`,
                        `- **Intune Device ID:** ${d.id ?? "—"}`,
                        `- **Azure AD Device ID:** ${d.azureADDeviceId ?? "—"}`,
                        `- **Join Type:** ${d.joinType ?? "—"}`,
                        `- **Autopilot:** ${d.autopilotEnrolled ? "Yes" : "No"}`,
                    ].join("\n");
                });

                return { content: [{ type: "text", text }] };
            } catch (err) {
                return errorResult(err);
            }
        }
    );

    // ── 2. intune_get_device_by_serial ───────────────────────────────────────
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

    // ── 3. intune_get_autopilot_status ───────────────────────────────────────
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

    // ── 4. intune_get_devices_by_user ────────────────────────────────────────
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
                                `- **${d.deviceName ?? "Unknown"}** | OS: ${d.operatingSystem ?? "—"} ${d.osVersion ?? ""} | Compliance: ${d.complianceState ?? "—"} | Last sync: ${d.lastSyncDateTime ?? "—"}`
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

    // ── 5. intune_get_device_groups ──────────────────────────────────────────
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

    // ── 6. intune_get_device_apps ────────────────────────────────────────────
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

    // ── 7. intune_list_configuration_policies ────────────────────────────────
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
                                    `- **${p.name}** (ID: ${p.id}) | Platform: ${p.platform ?? "—"} | Modified: ${p.lastModifiedDateTime ?? "—"}`
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

    // ── 8. intune_get_policy_assignments ─────────────────────────────────────
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

    // ── 9. intune_troubleshoot_device_policies ───────────────────────────────
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

    // ── 10. intune_troubleshoot_policy ───────────────────────────────────────
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
                                ? `### Findings\n${findings.map((f: any) => `- ${f}`).join("\n")}`
                                : "### Findings\n_No issues detected_";
                        const recoSection =
                            recommendations.length > 0
                                ? `### Recommendations\n${recommendations.map((r: any) => `- ${r}`).join("\n")}`
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

    // ── 11. intune_list_app_deployments ──────────────────────────────────────
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

    // ── 12. intune_get_app_assignments ───────────────────────────────────────
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

    // ── 13. intune_troubleshoot_app ──────────────────────────────────────────
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
                                ? `### Findings\n${findings.map((f: any) => `- ${f}`).join("\n")}`
                                : "### Findings\n_No issues detected_";
                        const recoSection =
                            recommendations.length > 0
                                ? `### Recommendations\n${recommendations.map((r: any) => `- ${r}`).join("\n")}`
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

    return server;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

async function main() {
    const app = express();
    app.use(express.json());

    const PORT = parseInt(process.env.PORT ?? "3002", 10);

    // Each request gets its own transport (stateless mode — required for APIM / multi-instance)
    app.post("/mcp", async (req: Request, res: Response) => {
        try {
            const server = createIntuneMcpServer();
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
