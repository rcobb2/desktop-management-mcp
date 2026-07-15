/**
 * JAMF Pro MCP Server
 *
 * Standalone Streamable HTTP MCP server exposing JAMF Pro inventory,
 * device management, and configuration data via the Model Context Protocol.
 *
 * Transport: Streamable HTTP — deploy behind Azure APIM or any reverse proxy.
 *
 * Environment variables:
 *   JAMF_URL                   JAMF Pro tenant URL (e.g. https://your-org.jamfcloud.com)
 *   JAMF_CLIENT_ID             OAuth client ID
 *   JAMF_CLIENT_SECRET         OAuth client secret
 *   JAMF_MCP_AUTH_TOKEN        Bearer token(s) required on /mcp requests (comma-separated to allow
 *                              rotation). Callers authenticated this way get full Jamf.Read + Jamf.Write
 *                              access, matching this token's behavior before Entra auth existed.
 *   ENTRA_OAUTH_ENABLED        "true" to additionally accept Entra-issued bearer tokens on /mcp, with
 *                              tool visibility driven by the token's `roles` claim (Jamf.Read/Jamf.Write).
 *   ENTRA_TENANT_ID            Entra tenant GUID (required when ENTRA_OAUTH_ENABLED=true)
 *   ENTRA_RESOURCE_APP_ID_URI  Application ID URI of the "Desktop Management MCP" resource app,
 *                              e.g. api://desktop-mgmt-mcp (required when ENTRA_OAUTH_ENABLED=true)
 *   ENTRA_RESOURCE_APP_ID      GUID app ID of the same resource app. Accepted as an alternate `aud`
 *                              value alongside ENTRA_RESOURCE_APP_ID_URI — a client that sends the
 *                              RFC 8707 `resource` parameter (as MCP-spec clients like OpenCode do)
 *                              gets back a token audienced to this GUID, not the URI, even on the
 *                              v2 endpoint. Optional but recommended once any such client is in use.
 *   JAMF_MCP_PUBLIC_URL        This server's externally-visible origin, e.g. https://jamf-mcp.colgate.edu
 *                              (required when ENTRA_OAUTH_ENABLED=true, used for RFC 9728 resource metadata)
 *   PORT                       HTTP port to listen on (default: 3001)
 */

import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthMetadataRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { z } from "zod";
import { JamfClient } from "../jamf/jamf-api.js";
import { requireMcpAuth } from "../utils/auth.js";
import { createEntraVerifier, buildEntraOAuthMetadata } from "../utils/entra-jwt.js";
import { hasRole, assertRole, JAMF_READ, JAMF_WRITE, JAMF_ALL_ROLES } from "../utils/roles.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

const ResponseFormatSchema = z
    .enum(["json", "markdown"])
    .default("markdown")
    .describe('Output format: "markdown" (default, human-readable) or "json" (structured data)');

function toText(data: unknown, format: "json" | "markdown", markdownFn: () => string): string {
    if (format === "json") {
        return JSON.stringify(data, null, 2);
    }
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

// ─── Server factory ──────────────────────────────────────────────────────────

function createJamfMcpServer(roles: string[]): McpServer {
    const client = new JamfClient();

    const server = new McpServer({
        name: "jamf-mcp-server",
        version: "1.0.0",
    });

    // ── 1. jamf_get_computer ─────────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_computer",
            {
                description:
                    "Get full inventory details for a single Mac from JAMF Pro by computer name. " +
                    "Returns hardware specs, OS version, last check-in, user assignment, IP address, " +
                    "serial number, site, and management status.",
                inputSchema: {
                    computerName: z.string().describe("The exact or partial display name of the computer in JAMF Pro"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ computerName, response_format = "markdown" }) => {
                try {
                    const response = await client.getComputerByName(computerName);
                    if (!response || response.totalCount === 0) return notFound(`computer "${computerName}"`);
                    const data: any = response.results[0];

                    const text = toText(response, response_format, () => {
                        const hw = data.hardware ?? {};
                        const gen = data.general ?? {};
                        const loc = data.location ?? {};
                        const os = data.operatingSystem ?? {};
                        const lines = [
                            `## ${gen.name ?? computerName}`,
                            `- **Serial:** ${gen.serialNumber ?? "—"}`,
                            `- **Asset Tag:** ${gen.assetTag ?? "—"}`,
                            `- **Model:** ${hw.model ?? "—"} (${hw.modelIdentifier ?? "—"})`,
                            `- **OS:** ${os.name ?? "—"} ${os.version ?? ""}`,
                            `- **Last Check-in:** ${gen.lastContactTime ?? "—"}`,
                            `- **IP Address:** ${gen.ipAddress ?? "—"}`,
                            `- **Assigned User:** ${loc.username ?? "—"} (${loc.realname ?? "—"})`,
                            `- **Email:** ${loc.emailAddress ?? "—"}`,
                            `- **Site:** ${gen.site?.name ?? "None"}`,
                            `- **MDM Capable:** ${gen.mdmCapable?.capable ? "Yes" : "No"}`,
                            `- **Supervised:** ${gen.supervised ? "Yes" : "No"}`,
                            `- **Management:** ${gen.remoteManagement?.managed ? "Managed" : "Unmanaged"}`,
                        ];
                        return lines.join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 2. jamf_list_computers ───────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_computers",
            {
                description:
                    "Search or list Mac computers in JAMF Pro inventory. Optionally filter by asset tag. " +
                    "Returns a paginated list with name, serial, model, OS, last check-in, and assigned user.",
                inputSchema: {
                    assetTag: z
                        .string()
                        .optional()
                        .describe(
                            "Filter by asset tag. Omit to list ALL computers. Pass empty string to list computers without an asset tag. Pass a specific value to filter by that tag."
                        ),
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed, default: 0)"),
                    pageSize: z.number().int().min(1).max(200).default(50).describe("Results per page (default: 50, max: 200)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ assetTag, page = 0, pageSize = 50, response_format = "markdown" }) => {
                try {
                    const data = await client.getComputersByAssetTag(assetTag, page, pageSize);
                    const computers = Array.isArray(data) ? data : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (computers.length === 0) return "No computers found.";
                        const header = assetTag !== undefined
                            ? assetTag === ""
                                ? `## Computers without asset tag (page ${page})`
                                : `## Computers with asset tag "${assetTag}" (page ${page})`
                            : `## All computers (page ${page})`;
                        const rows = computers
                            .map((c: any) => {
                                const os = [c.osName, c.osVersion].filter(Boolean).join(" ") || "—";
                                return `- **${c.name ?? "Unknown"}** | Serial: ${c.serialNumber || "—"} | Model: ${c.model || "—"} | OS: ${os} | Last seen: ${c.lastContactTime || "—"}`;
                            })
                            .join("\n");
                        return `${header}\n\n${rows}\n\n_Page ${page}, showing ${computers.length} records_`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 3. jamf_get_computers_by_user ────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_computers_by_user",
            {
                description:
                    "Find all Macs assigned to a user in JAMF Pro. Accepts email address, username, or real name. " +
                    "Searches all three fields in parallel and deduplicates results.",
                inputSchema: {
                    userIdentifier: z
                        .string()
                        .describe("The user's email address, JAMF username, or real/display name"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ userIdentifier, response_format = "markdown" }) => {
                try {
                    const computers = await client.getComputersByUserIdentifier(userIdentifier);
                    const list = Array.isArray(computers) ? computers : [];

                    const text = toText(computers, response_format, () => {
                        if (list.length === 0) return `No computers found for user "${userIdentifier}".`;
                        const rows = list
                            .map((c: any) => {
                                const gen = c.general ?? c;
                                return `- **${gen.name ?? "Unknown"}** | Serial: ${gen.serialNumber ?? "—"} | Model: ${c.hardware?.model ?? "—"} | Last seen: ${gen.lastContactTime ?? "—"}`;
                            })
                            .join("\n");
                        return `## Computers for "${userIdentifier}" (${list.length} found)\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 4. jamf_get_mobile_device ────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_mobile_device",
            {
                description:
                    "Get details for a single iOS/iPadOS/tvOS mobile device managed by JAMF Pro, looked up by device name. " +
                    "Returns model, OS, serial, UDID, assigned user, and management status.",
                inputSchema: {
                    deviceName: z.string().describe("The display name of the mobile device in JAMF Pro"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deviceName, response_format = "markdown" }) => {
                try {
                    const response = await client.getMobileDeviceByName(deviceName);
                    if (!response || response.totalCount === 0) return notFound(`mobile device "${deviceName}"`);
                    const d: any = response.results[0];

                    const text = toText(response, response_format, () => {
                        return [
                            `## ${d.name ?? deviceName}`,
                            `- **Serial:** ${d.serialNumber ?? "—"}`,
                            `- **UDID:** ${d.udid ?? "—"}`,
                            `- **Model:** ${d.model ?? "—"} (${d.modelIdentifier ?? "—"})`,
                            `- **OS:** ${d.osType ?? "—"} ${d.osVersion ?? ""}`,
                            `- **Supervised:** ${d.supervised ? "Yes" : "No"}`,
                            `- **MDM Managed:** ${d.managed ? "Yes" : "No"}`,
                            `- **Assigned User:** ${d.locationInformation?.username ?? "—"}`,
                            `- **Email:** ${d.locationInformation?.emailAddress ?? "—"}`,
                        ].join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 5. jamf_list_smart_groups ────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_smart_groups",
            {
                description:
                    "List all smart groups in JAMF Pro for computers or mobile devices. " +
                    "Smart groups are dynamic and update automatically based on criteria. " +
                    "Returns group ID, name, and member count.",
                inputSchema: {
                    type: z
                        .enum(["computer", "mobile_device"])
                        .describe('Type of smart groups to list: "computer" or "mobile_device"'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ type, response_format = "markdown" }) => {
                try {
                    const data =
                        type === "computer"
                            ? await client.getSmartComputerGroups()
                            : await client.getSmartMobileDeviceGroups();

                    const groups: any[] = Array.isArray(data) ? data : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (groups.length === 0) return `No smart ${type} groups found.`;
                        const rows = groups
                            .map((g: any) => `- **${g.name}** (ID: ${g.id}) — ${g.memberCount ?? "?"} members`)
                            .join("\n");
                        return `## Smart ${type === "computer" ? "Computer" : "Mobile Device"} Groups (${groups.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 6. jamf_get_smart_group_members ──────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_smart_group_members",
            {
                description:
                    "Get the list of Mac computers that currently belong to a JAMF Pro smart computer group. " +
                    "Returns member names, serials, models, and last check-in times. " +
                    "Use jamf_list_smart_groups first to find a group ID.",
                inputSchema: {
                    groupId: z.string().describe("The JAMF Pro ID of the smart computer group"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupId, response_format = "markdown" }) => {
                try {
                    const data = await client.getSmartComputerGroupMembers(groupId);
                    // getSmartComputerGroupMembers returns { totalCount, members }
                    const members: any[] = (data as any).members ?? [];

                    const text = toText(data, response_format, () => {
                        if (members.length === 0) return `Smart group ${groupId} has no members.`;
                        const rows = members
                            .map((m: any) => {
                                const gen = m.general ?? m;
                                return `- **${gen.name ?? "Unknown"}** | Serial: ${gen.serialNumber ?? "—"} | Model: ${m.hardware?.model ?? "—"} | Last seen: ${gen.lastContactTime ?? "—"}`;
                            })
                            .join("\n");
                        return `## Smart Group ${groupId} Members (${members.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 7. jamf_list_static_groups ───────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_static_groups",
            {
                description:
                    "List all static computer groups in JAMF Pro. " +
                    "Static groups have a fixed, manually-managed membership unlike smart groups. " +
                    "Returns group ID, name, and member count.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getStaticComputerGroups();
                    const groups: any[] = Array.isArray(data) ? data : [];

                    const text = toText(data, response_format, () => {
                        if (groups.length === 0) return "No static computer groups found.";
                        const rows = groups
                            .map((g: any) => `- **${g.name}** (ID: ${g.id}) — ${g.memberCount ?? "?"} members`)
                            .join("\n");
                        return `## Static Computer Groups (${groups.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 8. jamf_list_sites ───────────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_sites",
            {
                description:
                    "List all JAMF Pro sites (organizational units / divisions). " +
                    "Sites are used to segment JAMF management by department or location.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getSites();
                    const sites: any[] = Array.isArray(data) ? data : [];

                    const text = toText(data, response_format, () => {
                        if (sites.length === 0) return "No sites configured in JAMF Pro.";
                        const rows = sites.map((s: any) => `- **${s.name}** (ID: ${s.id})`).join("\n");
                        return `## JAMF Sites (${sites.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 9. jamf_list_scripts ─────────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_scripts",
            {
                description:
                    "List scripts available in JAMF Pro for deployment. " +
                    "Optionally filter by name (case-insensitive substring match) and paginate results. " +
                    "Returns script ID, name, category, and notes.",
                inputSchema: {
                    name: z
                        .string()
                        .optional()
                        .describe("Optional name filter (case-insensitive substring match)"),
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(100).describe("Results per page (default: 100)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ name, page = 0, pageSize = 100, response_format = "markdown" }) => {
                try {
                    const data = await client.getScripts(name, page, pageSize);
                    const scripts: any[] = Array.isArray(data)
                        ? data
                        : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (scripts.length === 0) return name ? `No scripts found matching "${name}".` : "No scripts found.";
                        const rows = scripts
                            .map((s: any) => `- **${s.name}** (ID: ${s.id}) | Category: ${s.categoryName ?? "—"} | Notes: ${s.info ?? "—"}`)
                            .join("\n");
                        const title = name ? `Scripts matching "${name}"` : "All Scripts";
                        return `## ${title} (page ${page}, ${scripts.length} results)\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 10. jamf_list_packages ───────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_packages",
            {
                description:
                    "List packages available in JAMF Pro for distribution to managed Macs. " +
                    "Optionally filter by name (case-insensitive substring match) and paginate results. " +
                    "Returns package ID, filename, category, and size.",
                inputSchema: {
                    name: z
                        .string()
                        .optional()
                        .describe("Optional name filter (case-insensitive substring match)"),
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(100).describe("Results per page (default: 100)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ name, page = 0, pageSize = 100, response_format = "markdown" }) => {
                try {
                    const data = await client.getPackages(name, page, pageSize);
                    const packages: any[] = Array.isArray(data)
                        ? data
                        : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (packages.length === 0) return name ? `No packages found matching "${name}".` : "No packages found.";
                        const rows = packages
                            .map((p: any) => `- **${p.packageName ?? p.fileName ?? p.name}** (ID: ${p.id}) | Category: ${p.categoryId ?? "—"}`)
                            .join("\n");
                        const title = name ? `Packages matching "${name}"` : "All Packages";
                        return `## ${title} (page ${page}, ${packages.length} results)\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 11. jamf_list_inventory_preload ──────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_inventory_preload",
            {
                description:
                    "List JAMF Pro inventory preload records used to pre-populate device information " +
                    "before enrollment (serial number, asset tag, username, etc.). Paginated.",
                inputSchema: {
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(100).describe("Results per page (default: 100)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ page = 0, pageSize = 100, response_format = "markdown" }) => {
                try {
                    const data = await client.getInventoryPreload(page, pageSize);
                    const records: any[] = Array.isArray(data)
                        ? data
                        : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (records.length === 0) return "No inventory preload records found.";
                        const rows = records
                            .map(
                                (r: any) =>
                                    `- Serial: **${r.serialNumber ?? "—"}** | Asset Tag: ${r.assetTag ?? "—"} | User: ${r.username ?? "—"} | Type: ${r.deviceType ?? "—"}`
                            )
                            .join("\n");
                        return `## Inventory Preload Records (page ${page}, ${records.length} results)\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 12. jamf_list_prestage_configs ───────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_prestage_configs",
            {
                description:
                    "List all computer prestage enrollment configurations in JAMF Pro. " +
                    "Prestages define how Macs are automatically configured during MDM enrollment via ADE/DEP. " +
                    "Returns prestage name, enrolled device count, site, and key settings.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getPrestageAssignments();
                    const prestages: any[] = Array.isArray(data)
                        ? data
                        : (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (prestages.length === 0) return "No computer prestage configurations found.";
                        const rows = prestages
                            .map(
                                (p: any) =>
                                    `- **${p.displayName ?? p.name ?? "Unnamed"}** (ID: ${p.id}) | Devices: ${p.profileUuid ? "assigned" : "unassigned"} | Site: ${p.site?.name ?? "None"}`
                            )
                            .join("\n");
                        return `## Computer Prestage Configurations (${prestages.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 13. jamf_get_computer_by_serial ─────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_computer_by_serial",
            {
                description:
                    "Look up a Mac in JAMF Pro by its serial number. " +
                    "Returns full inventory detail: hardware specs, OS, user assignment, IP, site, and management status.",
                inputSchema: {
                    serial: z.string().describe("The serial number of the Mac (e.g. C02ABC123DEF)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ serial, response_format = "markdown" }) => {
                try {
                    const response = await client.getComputerBySerial(serial.trim().toUpperCase());
                    if (!response || response.totalCount === 0) return notFound(`serial number "${serial}"`);
                    const data: any = response.results[0];

                    const text = toText(response, response_format, () => {
                        const hw = data.hardware ?? {};
                        const gen = data.general ?? {};
                        const loc = data.userAndLocation ?? data.location ?? {};
                        const os = data.operatingSystem ?? {};
                        return [
                            `## ${gen.name ?? serial}`,
                            `- **Serial:** ${hw.serialNumber ?? "—"}`,
                            `- **Asset Tag:** ${gen.assetTag ?? "—"}`,
                            `- **Model:** ${hw.model ?? "—"} (${hw.modelIdentifier ?? "—"})`,
                            `- **OS:** ${os.name ?? "—"} ${os.version ?? ""}`,
                            `- **Last Check-in:** ${gen.lastContactTime ?? "—"}`,
                            `- **IP Address:** ${gen.lastIpAddress ?? "—"}`,
                            `- **Assigned User:** ${loc.username ?? "—"} (${loc.realname ?? "—"})`,
                            `- **Email:** ${loc.email ?? loc.emailAddress ?? "—"}`,
                            `- **Department:** ${loc.department ?? "—"}`,
                            `- **Site:** ${gen.site?.name ?? "None"}`,
                            `- **MDM Capable:** ${gen.mdmCapable?.capable ? "Yes" : "No"}`,
                            `- **Supervised:** ${gen.supervised ? "Yes" : "No"}`,
                        ].join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 14. jamf_send_mdm_command ────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_send_mdm_command",
            {
                description:
                    "Send an MDM command to a Mac managed by JAMF Pro. " +
                    "Accepts the computer name or serial number. " +
                    "Supported commands: RestartDevice, ShutDownDevice, EraseDevice (IRREVERSIBLE), " +
                    "EnableRemoteDesktop, DisableRemoteDesktop, UnlockUserAccount, UpdateInventory, " +
                    "RotateFileVaultKey, BlankPush. " +
                    "EraseDevice requires erasurePasscode for Apple Silicon Macs. " +
                    "UnlockUserAccount requires the unlockUsername parameter.",
                inputSchema: {
                    computerNameOrSerial: z.string().describe("Computer display name or serial number"),
                    command: z.enum([
                        "RestartDevice",
                        "ShutDownDevice",
                        "EraseDevice",
                        "EnableRemoteDesktop",
                        "DisableRemoteDesktop",
                        "UnlockUserAccount",
                        "UpdateInventory",
                        "RotateFileVaultKey",
                        "BlankPush",
                    ]).describe("The MDM command to send"),
                    unlockUsername: z
                        .string()
                        .optional()
                        .describe("Required for UnlockUserAccount: the local username to unlock"),
                    erasurePasscode: z
                        .string()
                        .optional()
                        .describe("6-digit passcode for EraseDevice on Apple Silicon Macs"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true, destructiveHint: true },
            },
            async ({ computerNameOrSerial, command, unlockUsername, erasurePasscode }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.sendComputerMdmCommand(
                        computerNameOrSerial,
                        command,
                        { unlockUsername, erasurePasscode }
                    );
                    const text = `MDM command **${command}** sent successfully to computer ID ${result.computerId}.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 15. jamf_update_computer ─────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_update_computer",
            {
                description:
                    "Update a Mac's inventory record in JAMF Pro. " +
                    "Accepts the computer name or serial number to identify the device. " +
                    "Can update: assigned username, real name, email, department, building, room, and asset tag. " +
                    "Only fields you provide will be changed — omitted fields are left as-is.",
                inputSchema: {
                    computerNameOrSerial: z.string().describe("Computer display name or serial number"),
                    username: z.string().optional().describe("JAMF username to assign to this computer"),
                    realName: z.string().optional().describe("Full name of the assigned user"),
                    emailAddress: z.string().optional().describe("Email address of the assigned user"),
                    department: z.string().optional().describe("Department name (must match a JAMF department)"),
                    building: z.string().optional().describe("Building name (must match a JAMF building)"),
                    room: z.string().optional().describe("Room number or name"),
                    assetTag: z.string().optional().describe("Asset tag to assign to this computer"),
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ computerNameOrSerial, username, realName, emailAddress, department, building, room, assetTag }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.updateComputerRecord(computerNameOrSerial, {
                        username, realName, emailAddress, department, building, room, assetTag
                    });
                    const text = `Computer record updated successfully (JAMF ID: ${result.computerId}).`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 15b. jamf_assign_computers_to_prestage ───────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_assign_computers_to_prestage",
            {
                description:
                    "Assign one or more Mac serial numbers to a computer prestage enrollment's scope in JAMF Pro. " +
                    "Safely merges with the prestage's existing scope (read-modify-write with versionLock) — " +
                    "existing serials already scoped there are left untouched. Does NOT un-scope a serial from any " +
                    "OTHER prestage it may currently belong to. Accepts the prestage by its displayName (e.g. " +
                    "\"Classroom\") or numeric ID — use jamf_list_prestage_configs to see available prestages.",
                inputSchema: {
                    prestage: z.string().describe('Prestage displayName (e.g. "Classroom") or numeric ID'),
                    serialNumbers: z.array(z.string()).min(1).describe("Mac serial numbers to add to this prestage's scope"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ prestage, serialNumbers, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.assignSerialsToPrestage(prestage, serialNumbers);
                    const text = toText(result, response_format, () => {
                        const lines = [`## Assigned to prestage **${result.prestageName}** (ID: ${result.prestageId})`];
                        lines.push(`- Newly added (${result.added.length}): ${result.added.length ? result.added.join(", ") : "none"}`);
                        if (result.alreadyScoped.length) {
                            lines.push(`- Already scoped, skipped (${result.alreadyScoped.length}): ${result.alreadyScoped.join(", ")}`);
                        }
                        lines.push(`- Total serials now scoped: ${result.totalScoped}`);
                        return lines.join("\n");
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 15c. jamf_upsert_inventory_preload_record ────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_upsert_inventory_preload_record",
            {
                description:
                    "Create or update a JAMF Pro inventory preload record, identified by serial number. " +
                    "Inventory Preload records pre-populate a device's asset tag/building/room/user info so it's " +
                    "applied automatically at prestage enrollment — this is the correct way to set that data " +
                    "for a device that hasn't enrolled yet (jamf_update_computer only works on already-enrolled " +
                    "computers). If no preload record exists for the serial, one is created; if one exists, the " +
                    "given fields are merged into it (omitted fields keep their current value).",
                inputSchema: {
                    serialNumber: z.string().describe("Mac serial number (e.g. C02ABC123DEF)"),
                    assetTag: z.string().optional().describe("Asset tag"),
                    building: z.string().optional().describe("Building name — must match a JAMF building exactly"),
                    room: z.string().optional().describe("Room number or name"),
                    username: z.string().optional().describe("Assigned username"),
                    fullName: z.string().optional().describe("Full name of the assigned user"),
                    emailAddress: z.string().optional().describe("Email address of the assigned user"),
                    deviceType: z.string().optional().describe('Device type, e.g. "Computer" (default) or "Mobile Device"'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ serialNumber, assetTag, building, room, username, fullName, emailAddress, deviceType, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertInventoryPreloadRecord({
                        serialNumber: serialNumber.trim().toUpperCase(),
                        assetTag, building, room, username, fullName, emailAddress, deviceType,
                    });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created inventory preload record for serial **${result.serialNumber}**.`
                            : `Updated inventory preload record (ID ${result.id}) for serial **${result.serialNumber}**.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 16. jamf_list_policies ───────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_policies",
            {
                description:
                    "List policies configured in JAMF Pro. Optionally filter by name (case-insensitive substring). " +
                    "Returns policy ID and name. Use jamf_get_policy to see full details for a specific policy.",
                inputSchema: {
                    name: z.string().optional().describe("Optional name filter (case-insensitive substring)"),
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(100).describe("Results per page (default: 100)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ name, page = 0, pageSize = 100, response_format = "markdown" }) => {
                try {
                    const data = await client.getPolicies(name, page, pageSize);
                    const policies: any[] = (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (policies.length === 0) return name ? `No policies found matching "${name}".` : "No policies found.";
                        const rows = policies
                            .map((p: any) => `- **${p.name}** (ID: ${p.id})`)
                            .join("\n");
                        const title = name ? `Policies matching "${name}"` : "All Policies";
                        return `## ${title} (${(data as any).totalCount} total, page ${page})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 17. jamf_get_policy ──────────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_policy",
            {
                description:
                    "Get full details for a single JAMF Pro policy by its ID. " +
                    "Returns scope, triggers, scripts, packages, self-service settings, and all configuration. " +
                    "Use jamf_list_policies first to find a policy ID.",
                inputSchema: {
                    policyId: z.string().describe("The JAMF Pro numeric ID of the policy"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ policyId, response_format = "markdown" }) => {
                try {
                    const policy: any = await client.getPolicyDetail(policyId);
                    if (!policy) return notFound(`policy ID ${policyId}`);

                    const text = toText(policy, response_format, () => {
                        const gen = policy.general ?? {};
                        const scope = policy.scope ?? {};
                        const scripts = policy.scripts?.script ?? [];
                        const packages = policy.package_configuration?.packages?.package ?? [];
                        const lines = [
                            `## ${gen.name ?? `Policy ${policyId}`}`,
                            `- **ID:** ${gen.id ?? policyId}`,
                            `- **Enabled:** ${gen.enabled ? "Yes" : "No"}`,
                            `- **Trigger:** ${gen.trigger ?? "—"} (${gen.trigger_checkin ? "check-in" : ""} ${gen.trigger_enrollment_complete ? "enrollment" : ""} ${gen.trigger_startup ? "startup" : ""} ${gen.trigger_other ?? ""})`.trim(),
                            `- **Frequency:** ${gen.frequency ?? "—"}`,
                            `- **Category:** ${gen.category?.name ?? "None"}`,
                            `- **Site:** ${gen.site?.name ?? "None"}`,
                            `- **Scope — All Computers:** ${scope.all_computers ? "Yes" : "No"}`,
                            scope.computers?.computer?.length
                                ? `- **Scope — Computers:** ${scope.computers.computer.map((c: any) => c.name).join(", ")}`
                                : null,
                            scope.computer_groups?.computer_group?.length
                                ? `- **Scope — Groups:** ${scope.computer_groups.computer_group.map((g: any) => g.name).join(", ")}`
                                : null,
                            scripts.length
                                ? `- **Scripts:** ${(Array.isArray(scripts) ? scripts : [scripts]).map((s: any) => s.name).join(", ")}`
                                : null,
                            packages.length
                                ? `- **Packages:** ${(Array.isArray(packages) ? packages : [packages]).map((p: any) => p.name).join(", ")}`
                                : null,
                        ].filter(Boolean).join("\n");
                        return lines;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 18. jamf_list_configuration_profiles ────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_configuration_profiles",
            {
                description:
                    "List macOS configuration profiles deployed via JAMF Pro. " +
                    "Optionally filter by name (case-insensitive substring). " +
                    "Returns profile ID, name, category, and site.",
                inputSchema: {
                    name: z.string().optional().describe("Optional name filter (case-insensitive substring)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ name, response_format = "markdown" }) => {
                try {
                    const data = await client.getComputerConfigurationProfiles(name);
                    const profiles: any[] = (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (profiles.length === 0) return name ? `No profiles found matching "${name}".` : "No configuration profiles found.";
                        const rows = profiles
                            .map((p: any) => `- **${p.name}** (ID: ${p.id}) | Category: ${p.category?.name ?? "—"} | Site: ${p.site?.name ?? "None"}`)
                            .join("\n");
                        const title = name ? `Profiles matching "${name}"` : "macOS Configuration Profiles";
                        return `## ${title} (${profiles.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 19. jamf_list_patch_policies ────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_patch_policies",
            {
                description:
                    "List patch policies configured in JAMF Pro for software patching. " +
                    "Returns patch policy ID, name, enabled status, and target software title.",
                inputSchema: {
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(100).describe("Results per page (default: 100)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ page = 0, pageSize = 100, response_format = "markdown" }) => {
                try {
                    const data = await client.getPatchPolicies(page, pageSize);
                    const policies: any[] = (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (policies.length === 0) return "No patch policies found.";
                        const rows = policies
                            .map((p: any) =>
                                `- **${p.name ?? p.displayName ?? "Unnamed"}** (ID: ${p.id}) | Enabled: ${p.enabled ? "Yes" : "No"} | Software Title: ${p.softwareTitleConfigurationId ?? "—"}`
                            )
                            .join("\n");
                        return `## Patch Policies (${(data as any).totalCount ?? policies.length} total, page ${page})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 20. jamf_list_departments ────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_departments",
            {
                description:
                    "List all departments configured in JAMF Pro. " +
                    "Use this to find valid department names when updating computer records.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getDepartments();
                    const departments: any[] = (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (departments.length === 0) return "No departments found.";
                        const rows = departments.map((d: any) => `- **${d.name}** (ID: ${d.id})`).join("\n");
                        return `## Departments (${departments.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 21. jamf_list_categories ─────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_categories",
            {
                description:
                    "List all categories configured in JAMF Pro. " +
                    "Categories are used to organize policies, scripts, packages, and profiles.",
                inputSchema: {
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(200).default(200).describe("Results per page (default: 200)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ page = 0, pageSize = 200, response_format = "markdown" }) => {
                try {
                    const data = await client.getCategories(page, pageSize);
                    const categories: any[] = (data as any).results ?? [];

                    const text = toText(data, response_format, () => {
                        if (categories.length === 0) return "No categories found.";
                        const rows = categories.map((c: any) => `- **${c.name}** (ID: ${c.id}) | Priority: ${c.priority ?? "—"}`).join("\n");
                        return `## Categories (${(data as any).totalCount ?? categories.length} total)\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 22. jamf_flush_mdm_commands ──────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_flush_mdm_commands",
            {
                description:
                    "Flush pending or failed MDM commands from a Mac's command queue in JAMF Pro. " +
                    "Use this when a device has stuck MDM commands that are blocking other management tasks. " +
                    "Accepts computer name or serial number.",
                inputSchema: {
                    computerNameOrSerial: z.string().describe("Computer display name or serial number"),
                    status: z
                        .enum(["Pending", "Failed", "Pending+Failed"])
                        .default("Pending+Failed")
                        .describe('Which commands to flush: "Pending", "Failed", or "Pending+Failed" (default)'),
                },
                annotations: { readOnlyHint: false, openWorldHint: true, destructiveHint: false },
            },
            async ({ computerNameOrSerial, status = "Pending+Failed" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.flushComputerMdmCommands(computerNameOrSerial, status);
                    const text = `Successfully flushed **${status}** MDM commands for computer ID ${result.computerId}.`;
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 23. jamf_get_filevault_status ────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_filevault_status",
            {
                description:
                    "Get FileVault encryption status for a Mac managed by JAMF Pro. " +
                    "Returns encryption state, individual disk partition status, and whether the recovery key is escrowed. " +
                    "Accepts computer name or serial number.",
                inputSchema: {
                    computerNameOrSerial: z.string().describe("Computer display name or serial number"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ computerNameOrSerial, response_format = "markdown" }) => {
                try {
                    const data = await client.getFilevaultStatus(computerNameOrSerial);
                    if (!data) return notFound(`computer "${computerNameOrSerial}"`);

                    const text = toText(data, response_format, () => {
                        const fv = (data as any).diskEncryption ?? {};
                        const partitions: any[] = fv.individualDiskEncryptionCapabilities ?? fv.partitions ?? [];
                        const lines = [
                            `## FileVault Status — ${(data as any).name ?? computerNameOrSerial}`,
                            `- **Serial:** ${(data as any).serialNumber ?? "—"}`,
                            `- **Overall State:** ${fv.bootPartitionEncryptionDetails?.partitionFileVault2State ?? fv.overallEncryptionStatus ?? "—"}`,
                            `- **Recovery Key Escrowed:** ${fv.institutionalRecoveryKeyPresent ? "Yes" : fv.individualRecoveryKeyPresent ? "Yes (personal)" : "No"}`,
                        ];
                        if (partitions.length > 0) {
                            lines.push("", "**Partitions:**");
                            partitions.forEach((p: any) => {
                                lines.push(`  - ${p.name ?? p.partitionName ?? "—"}: ${p.fileVault2State ?? p.encryptionState ?? "—"} (${p.fileVault2Percent ?? p.percentage ?? "?"}%)`);
                            });
                        }
                        return lines.join("\n");
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 24. jamf_list_mobile_devices ─────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_mobile_devices",
            {
                description:
                    "List mobile devices (iOS/iPadOS/tvOS) across the whole JAMF fleet, optionally filtered by " +
                    "device type, managed state, or supervised state. Pages through the full result set for an " +
                    "accurate fleet-wide count and breakdown by type, managed/supervised state, and model. " +
                    "Use this for fleet counts rather than repeated single-device lookups.",
                inputSchema: {
                    type: z.string().optional().describe('Filter by device type, e.g. "ios", "tvos"'),
                    managed: z.boolean().optional().describe("Filter to only managed (true) or unmanaged (false) devices"),
                    supervised: z.boolean().optional().describe("Filter to only supervised (true) or unsupervised (false) devices"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ type, managed, supervised, response_format = "markdown" }) => {
                try {
                    const data = await client.listMobileDevices({ type, managed, supervised });

                    const text = toText(data, response_format, () => {
                        const devices: any[] = data.devices ?? [];
                        const filterNote = [
                            type && `type="${type}"`,
                            managed !== undefined && `managed=${managed}`,
                            supervised !== undefined && `supervised=${supervised}`,
                        ]
                            .filter(Boolean)
                            .join(", ");

                        if (devices.length === 0) {
                            return `No mobile devices found${filterNote ? ` matching ${filterNote}` : ""}.`;
                        }

                        const byType = new Map<string, number>();
                        const byManaged = new Map<string, number>();
                        const byModel = new Map<string, number>();
                        for (const d of devices) {
                            const t = d.type ?? "unknown";
                            const m = d.managed === null ? "unknown" : d.managed ? "managed" : "unmanaged";
                            const model = d.model ?? "Unknown";
                            byType.set(t, (byType.get(t) ?? 0) + 1);
                            byManaged.set(m, (byManaged.get(m) ?? 0) + 1);
                            byModel.set(model, (byModel.get(model) ?? 0) + 1);
                        }

                        const sortedEntries = (m: Map<string, number>) =>
                            [...m.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `- **${k}:** ${v}`).join("\n");

                        const rows = devices
                            .slice(0, 50)
                            .map(
                                (d: any) =>
                                    `- **${d.name ?? "Unknown"}** | ${d.model ?? "—"} | Managed: ${d.managed === null ? "—" : d.managed ? "Yes" : "No"} | Supervised: ${d.supervised === null ? "—" : d.supervised ? "Yes" : "No"} | Serial: ${d.serialNumber ?? "—"}`
                            )
                            .join("\n");

                        const truncationNote = data.truncated
                            ? `\n\n_⚠️ Hit the pagination safety cap — counts above reflect only the first ${devices.length} devices fetched, not necessarily the entire tenant._`
                            : "";

                        return (
                            [
                                `## Mobile Devices${filterNote ? ` (${filterNote})` : ""} — ${devices.length} total`,
                                `### By Type\n${sortedEntries(byType)}`,
                                `### By Managed State\n${sortedEntries(byManaged)}`,
                                `### By Model\n${sortedEntries(byModel)}`,
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

    return server;
}

// ─── HTTP Server ─────────────────────────────────────────────────────────────

async function main() {
    const app = express();
    app.use(express.json());

    const PORT = parseInt(process.env.PORT ?? "3001", 10);
    const publicUrl = process.env.JAMF_MCP_PUBLIC_URL;
    const entraOAuthEnabled = process.env.ENTRA_OAUTH_ENABLED === "true";
    const resourceMetadataUrl = publicUrl ? getOAuthProtectedResourceMetadataUrl(new URL(`${publicUrl}/mcp`)) : undefined;

    if (entraOAuthEnabled) {
        if (!publicUrl) {
            throw new Error("JAMF_MCP_PUBLIC_URL must be set when ENTRA_OAUTH_ENABLED=true");
        }
        const tenantId = process.env.ENTRA_TENANT_ID;
        if (!tenantId) {
            throw new Error("ENTRA_TENANT_ID must be set when ENTRA_OAUTH_ENABLED=true");
        }
        app.use(
            mcpAuthMetadataRouter({
                oauthMetadata: buildEntraOAuthMetadata(tenantId),
                resourceServerUrl: new URL(`${publicUrl}/mcp`),
                resourceName: "JAMF Pro MCP Server",
            })
        );
    }

    app.use(
        "/mcp",
        requireMcpAuth({
            staticTokenEnvVar: "JAMF_MCP_AUTH_TOKEN",
            allRoles: JAMF_ALL_ROLES,
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
            const server = createJamfMcpServer(roles);
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
            console.error("[jamf-mcp] Error handling request:", err);
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
        res.json({ status: "ok", server: "jamf-mcp-server", version: "1.0.0" });
    });

    app.listen(PORT, () => {
        console.log(`[jamf-mcp] JAMF Pro MCP server listening on port ${PORT}`);
        console.log(`[jamf-mcp] MCP endpoint: http://localhost:${PORT}/mcp`);
        console.log(`[jamf-mcp] JAMF URL: ${process.env.JAMF_URL ?? "(not set)"}`);
    });
}

main().catch((err) => {
    console.error("[jamf-mcp] Fatal error:", err);
    process.exit(1);
});
