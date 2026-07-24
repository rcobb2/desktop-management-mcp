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
 *   JAMF_PACKAGE_UPLOAD_DIR    Directory jamf_upload_package is allowed to read files from on this
 *                              server's own filesystem (not the MCP client's). Required for that tool —
 *                              it refuses every call if unset, and rejects any localFilePath outside it.
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
import { metricsMiddleware, metricsHandler, instrumentToolCalls } from "../utils/metrics.js";

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

function createJamfMcpServer(roles: string[], caller: string): McpServer {
    const client = new JamfClient();

    const server = new McpServer({
        name: "jamf-mcp-server",
        version: "1.0.0",
    });
    instrumentToolCalls(server, "jamf", caller);

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

    // ── 6b. jamf_get_smart_group ──────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_smart_group",
            {
                description:
                    "Get the full definition of a JAMF Pro smart computer group, including its criteria " +
                    "(the boolean logic — field, operator, value, and/or, grouping parens — that defines " +
                    "membership). jamf_list_smart_groups only returns name/ID/member count; use this when you " +
                    "need to see or confirm how a group is actually built. Use jamf_list_smart_groups first to " +
                    "find a group ID.",
                inputSchema: {
                    groupId: z.string().describe("The JAMF Pro ID of the smart computer group"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupId, response_format = "markdown" }) => {
                try {
                    const data = await client.getSmartGroupDetail(groupId);

                    const text = toText(data, response_format, () => {
                        const criteria: any[] = data.criteria ?? [];
                        const rows = criteria.length
                            ? criteria
                                  .map((c: any) => `- ${c.and_or ?? ""} ${c.name} ${c.search_type} "${c.value}"`.trim())
                                  .join("\n")
                            : "No criteria defined.";
                        return `## Smart Group **${data.name}** (ID ${groupId})\n\n${rows}`;
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

    // ── 7b. jamf_list_user_groups ────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_user_groups",
            {
                description:
                    "List all JAMF Pro user groups (smart and static). Unlike computer groups, Jamf has no " +
                    "modern-API surface for user groups — this goes through the Classic API. Returns group ID, " +
                    "name, and whether it's smart or static. Use jamf_get_user_group for a group's criteria or " +
                    "member list.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getUserGroups();
                    const groups: any[] = data.results ?? [];

                    const text = toText(data, response_format, () => {
                        if (groups.length === 0) return "No user groups found.";
                        const rows = groups
                            .map((g: any) => `- **${g.name}** (ID: ${g.id}) — ${g.is_smart ? "Smart" : "Static"}`)
                            .join("\n");
                        return `## User Groups (${groups.length})\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 7c. jamf_get_user_group ──────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_user_group",
            {
                description:
                    "Get the full definition of a JAMF Pro user group, including its criteria (if smart) or " +
                    "member list (if static). jamf_list_user_groups only returns name/ID/smart-vs-static; use " +
                    "this to inspect how a group is actually built or confirm current membership — e.g. the " +
                    "'Directory Service Group shows 0 members' class of investigation. Use jamf_list_user_groups " +
                    "first to find a group ID.",
                inputSchema: {
                    groupId: z.string().describe("The JAMF Pro ID of the user group"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupId, response_format = "markdown" }) => {
                try {
                    const data = await client.getUserGroupDetail(groupId);

                    const text = toText(data, response_format, () => {
                        const header = `## User Group **${data.name}** (ID ${groupId}) — ${data.is_smart ? "Smart" : "Static"}`;
                        if (data.is_smart) {
                            const criteria: any[] = data.criteria ?? [];
                            const rows = criteria.length
                                ? criteria.map((c: any) => `- ${c.and_or ?? ""} ${c.name} ${c.search_type} "${c.value}"`.trim()).join("\n")
                                : "No criteria defined.";
                            return `${header}\n\n${rows}`;
                        }
                        const users: any[] = data.users ?? [];
                        const rows = users.length
                            ? users.map((u: any) => `- **${u.name}** (ID: ${u.id})`).join("\n")
                            : "No members.";
                        return `${header}\n\n${rows}`;
                    });

                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 7d. jamf_create_user_group ───────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_user_group",
            {
                description:
                    "Create or update a JAMF Pro user group (upsert by name, like jamf_create_smart_group_v2). " +
                    "Pass exactly one of `criteria` (for a smart group — any Jamf Classic API criterion, e.g. " +
                    "'Directory Service Group', 'Full Name', 'Email Address') or `memberUsernames` (for a static " +
                    "group — an explicit member list). memberUsernames must already exist as Jamf Pro User " +
                    "objects; this does not search or import from the directory service — a username with no " +
                    "matching Jamf User errors out rather than creating one.",
                inputSchema: {
                    name: z.string().describe("User group name — used as the upsert key"),
                    criteria: z
                        .array(z.object({
                            name: z.string().describe('Criterion field name, e.g. "Directory Service Group", "Full Name", "Email Address"'),
                            priority: z.number().optional().describe("Row order (defaults to array index)"),
                            and_or: z.enum(["and", "or"]).default("and"),
                            search_type: z.string().describe('Operator, e.g. "is", "is not", "like", "has"'),
                            value: z.string(),
                            opening_paren: z.boolean().optional(),
                            closing_paren: z.boolean().optional(),
                        }))
                        .optional()
                        .describe("Criteria for a smart user group — pass this OR memberUsernames, not both"),
                    memberUsernames: z
                        .array(z.string())
                        .optional()
                        .describe("Explicit member usernames for a static user group — pass this OR criteria, not both"),
                    siteId: z.string().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, criteria, memberUsernames, siteId, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertUserGroup({ name, criteria, memberUsernames, siteId });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created ${result.isSmart ? "smart" : "static"} user group **${result.name}** (ID ${result.id}).`
                            : `Updated ${result.isSmart ? "smart" : "static"} user group **${result.name}** (ID ${result.id}).`
                    );
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
                        // Classic API's JSON representation uses flat arrays directly
                        // (scope.computer_groups, policy.scripts, package_configuration.packages) —
                        // not the XML-derived `{computer_group: [...]}`/`{script: [...]}` wrapper
                        // shapes, confirmed against a real policy with populated scope/scripts/packages.
                        const scripts: any[] = Array.isArray(policy.scripts) ? policy.scripts : [];
                        const packages: any[] = Array.isArray(policy.package_configuration?.packages)
                            ? policy.package_configuration.packages
                            : [];
                        const computers: any[] = Array.isArray(scope.computers) ? scope.computers : [];
                        const computerGroups: any[] = Array.isArray(scope.computer_groups) ? scope.computer_groups : [];
                        const lines = [
                            `## ${gen.name ?? `Policy ${policyId}`}`,
                            `- **ID:** ${gen.id ?? policyId}`,
                            `- **Enabled:** ${gen.enabled ? "Yes" : "No"}`,
                            `- **Trigger:** ${gen.trigger ?? "—"} (${gen.trigger_checkin ? "check-in" : ""} ${gen.trigger_enrollment_complete ? "enrollment" : ""} ${gen.trigger_startup ? "startup" : ""} ${gen.trigger_other ?? ""})`.trim(),
                            `- **Frequency:** ${gen.frequency ?? "—"}`,
                            `- **Category:** ${gen.category?.name ?? "None"}`,
                            `- **Site:** ${gen.site?.name ?? "None"}`,
                            `- **Scope — All Computers:** ${scope.all_computers ? "Yes" : "No"}`,
                            computers.length
                                ? `- **Scope — Computers:** ${computers.map((c: any) => c.name).join(", ")}`
                                : null,
                            computerGroups.length
                                ? `- **Scope — Groups:** ${computerGroups.map((g: any) => g.name).join(", ")}`
                                : null,
                            scripts.length
                                ? `- **Scripts:** ${scripts.map((s: any) => s.name).join(", ")}`
                                : null,
                            packages.length
                                ? `- **Packages:** ${packages.map((p: any) => p.name).join(", ")}`
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

    // ── 25. jamf_create_script ────────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_script",
            {
                description:
                    "Create or update a JAMF Pro script, identified by name (upsert — re-running with the same " +
                    "name OVERWRITES that script's contents and parameters, it does not create a duplicate). " +
                    "Parameters 4-11 are available for custom use (JAMF reserves 1-3 for mount point, computer " +
                    "name, and username at runtime).",
                inputSchema: {
                    name: z.string().describe("Script name — used as the upsert key"),
                    scriptContents: z.string().describe("The full script body (e.g. bash or zsh source)"),
                    categoryName: z.string().optional().describe("Category name — must match an existing JAMF category (see jamf_list_categories)"),
                    info: z.string().optional().describe("Longer description shown in JAMF Pro"),
                    notes: z.string().optional(),
                    priority: z.enum(["BEFORE", "AFTER"]).optional().describe("Execution priority relative to package installs"),
                    osRequirements: z.string().optional().describe('e.g. "13.0.x" or a comma-separated list'),
                    parameter4: z.string().optional(),
                    parameter5: z.string().optional(),
                    parameter6: z.string().optional(),
                    parameter7: z.string().optional(),
                    parameter8: z.string().optional(),
                    parameter9: z.string().optional(),
                    parameter10: z.string().optional(),
                    parameter11: z.string().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                name, scriptContents, categoryName, info, notes, priority, osRequirements,
                parameter4, parameter5, parameter6, parameter7, parameter8, parameter9, parameter10, parameter11,
                response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertScript({
                        name, scriptContents, categoryName, info, notes, priority, osRequirements,
                        parameter4, parameter5, parameter6, parameter7, parameter8, parameter9, parameter10, parameter11,
                    });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created script **${result.name}** (ID ${result.id}).`
                            : `Updated script **${result.name}** (ID ${result.id}).`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 26. jamf_upload_package ──────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_upload_package",
            {
                description:
                    "Upload a .pkg/.dmg installer to JAMF Pro and create (or update, if a package with the " +
                    "same packageName already exists) its package object. Re-running with the same packageName " +
                    "updates that package's metadata and replaces its uploaded bytes — it does not create a " +
                    "duplicate (the yearly re-publish case, e.g. Office or MATLAB version bumps). " +
                    "Pass exactly ONE of localFilePath or fileContentBase64: " +
                    "localFilePath must be a path on THIS MCP SERVER'S OWN FILESYSTEM (not the MCP client's " +
                    "machine), inside the directory configured by JAMF_PACKAGE_UPLOAD_DIR, and streams the file " +
                    "off disk — the only sane option for large installers. fileContentBase64 (with fileName) " +
                    "lets the file live on the MCP client's machine instead — practical for smaller packages, " +
                    "but the whole decoded file is buffered in memory with no streaming, so it's a poor fit for " +
                    "multi-GB installers; use localFilePath for those.",
                inputSchema: {
                    localFilePath: z.string().optional().describe(
                        "Absolute path to the .pkg/.dmg file on the MCP server's local filesystem, inside JAMF_PACKAGE_UPLOAD_DIR. " +
                        "Pass this OR fileContentBase64, not both."
                    ),
                    fileContentBase64: z.string().optional().describe(
                        "Base64-encoded file bytes, for uploading from the MCP client's machine instead of the server's filesystem. " +
                        "Pass this OR localFilePath, not both. Requires fileName."
                    ),
                    fileName: z.string().optional().describe("File name (with extension) — required when using fileContentBase64"),
                    packageName: z.string().describe("The package's display name in JAMF Pro (used as the upsert key)"),
                    categoryName: z.string().optional().describe("Category name — must match an existing JAMF category (see jamf_list_categories)"),
                    priority: z.number().int().min(1).max(20).optional().describe("Install priority (default: 10)"),
                    fillUserTemplate: z.boolean().optional(),
                    rebootRequired: z.boolean().optional(),
                    osInstall: z.boolean().optional().describe("True if this package is a full OS installer"),
                    suppressUpdates: z.boolean().optional(),
                    suppressFromDock: z.boolean().optional(),
                    suppressEula: z.boolean().optional(),
                    suppressRegistration: z.boolean().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                localFilePath, fileContentBase64, fileName, packageName, categoryName, priority, fillUserTemplate, rebootRequired,
                osInstall, suppressUpdates, suppressFromDock, suppressEula, suppressRegistration,
                response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertPackage({
                        localFilePath, fileContentBase64, fileName, packageName, categoryName, priority,
                        fillUserTemplate, rebootRequired, osInstall,
                        suppressUpdates, suppressFromDock, suppressEula, suppressRegistration,
                    });
                    const text = toText(result, response_format, () =>
                        `${result.action === "created" ? "Created" : "Updated"} package **${result.packageName}** (ID ${result.id}, file "${result.fileName}") and uploaded its bytes successfully.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 27. jamf_create_smart_group ──────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_smart_group",
            {
                description:
                    "Create or update an 'Application - detection' smart computer group in JAMF Pro, matching " +
                    "on exact Application Title + Application Version (upsert by name — rerunning for a version " +
                    "bump, e.g. re-publishing after MATLAB 2025b becomes 2026a, updates the existing group's " +
                    "criteria in place rather than creating a duplicate). NOTE: if you immediately reference a " +
                    "just-created group by name in jamf_create_policy or jamf_update_policy, JAMF's internal " +
                    "indexing can lag a few seconds and return a transient 409 — retry once if that happens.",
                inputSchema: {
                    name: z.string().describe("Smart group name — used as the upsert key"),
                    applicationTitle: z.string().describe('Exact application bundle name as JAMF inventories it, e.g. "MATLAB.app"'),
                    applicationVersion: z.string().describe('Exact version string to match, e.g. "25.2"'),
                    siteId: z.string().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, applicationTitle, applicationVersion, siteId, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertApplicationSmartGroup({ name, applicationTitle, applicationVersion, siteId });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created smart group **${result.name}** (ID ${result.id}) matching ${applicationTitle} == ${applicationVersion}.`
                            : `Updated smart group **${result.name}** (ID ${result.id}) to match ${applicationTitle} == ${applicationVersion}.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 27b. jamf_create_smart_group_v2 ──────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_smart_group_v2",
            {
                description:
                    "Create or update a smart computer group in JAMF Pro with an arbitrary criteria list " +
                    "(upsert by name, like jamf_create_smart_group). Unlike jamf_create_smart_group — which only " +
                    "supports the 'Application Title + Version' detection pattern — this accepts any criteria " +
                    "Jamf's Classic API supports: extension attributes, 'Directory Service Group', 'Department', " +
                    "'Last Check-in', hardware fields, etc. Criteria are ANDed/ORed in the order given, matching " +
                    "how they'd be built in the Jamf Pro UI's smart group criteria table. NOTE: if you immediately " +
                    "reference a just-created group by name in jamf_create_policy or jamf_update_policy, JAMF's " +
                    "internal indexing can lag a few seconds and return a transient 409 — retry once if that happens.",
                inputSchema: {
                    name: z.string().describe("Smart group name — used as the upsert key"),
                    criteria: z
                        .array(z.object({
                            name: z.string().describe('Criterion field name, e.g. "Application Title", "Department", "Directory Service Group", or an extension attribute name'),
                            priority: z.number().optional().describe("Row order (defaults to array index)"),
                            and_or: z.enum(["and", "or"]).default("and"),
                            search_type: z.string().describe('Operator, e.g. "is", "is not", "like", "has", "greater than"'),
                            value: z.string(),
                            opening_paren: z.boolean().optional(),
                            closing_paren: z.boolean().optional(),
                        }))
                        .min(1)
                        .describe("Ordered list of criteria defining group membership"),
                    siteId: z.string().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, criteria, siteId, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertSmartGroup({ name, criteria, siteId });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created smart group **${result.name}** (ID ${result.id}) with ${criteria.length} criteria.`
                            : `Updated smart group **${result.name}** (ID ${result.id}) with ${criteria.length} criteria.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 28. jamf_create_policy ────────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_policy",
            {
                description:
                    "Create or update a JAMF Pro policy scoped to one or more smart/static computer groups by name " +
                    "(upsert by name — rerunning with the same policy name updates the existing policy in place " +
                    "rather than creating a duplicate, matching jamf_create_script/jamf_upload_package). The update " +
                    "path replaces general/scope/self_service/packages/scripts/maintenance/disk_encryption/" +
                    "user_interaction with what's passed here — any of those left unset revert to this call's " +
                    "defaults, so pass the full desired policy config each time rather than assuming prior values " +
                    "persist. Scripts and packages are both optional and independent — a script-only policy (e.g. a " +
                    "maintenance/remediation policy with no package) is fully supported. diskEncryption's `apply` " +
                    "and `remediate` actions represent distinct intents (enable FileVault on an unencrypted Mac, " +
                    "vs. re-issue/escrow a key on an already-encrypted one) — confirmed live that combining fields " +
                    "from both in one policy silently no-ops the whole section, so use two separate policies if you " +
                    "need both behaviors. Does NOT support individual-computer, building, or department " +
                    "scoping/limitations, or configuration profiles — use smart/static computer groups for targeting.",
                inputSchema: {
                    name: z.string().describe("Policy display name"),
                    enabled: z.boolean().default(true),
                    triggerCheckin: z.boolean().optional(),
                    triggerEnrollmentComplete: z.boolean().optional(),
                    triggerLogin: z.boolean().optional(),
                    triggerStartup: z.boolean().optional(),
                    triggerOther: z.string().optional().describe('Custom event trigger name (for `jamf policy -trigger <name>`)'),
                    // Confirmed live (Jamf Pro 11.29.1) against an existing policy's own
                    // GET response — the real enum strings are "Once every day/week/month",
                    // not "Once per day/week/month" (a pre-existing mismatch in this schema
                    // found while investigating why frequency changes weren't sticking).
                    frequency: z
                        .enum(["Once per computer", "Once per user per computer", "Once per user", "Once every day", "Once every week", "Once every month", "Ongoing"])
                        .default("Once per computer"),
                    categoryName: z.string().optional(),
                    targetGroupNames: z.array(z.string()).default([]).describe("Smart/static computer group names to scope this policy to"),
                    exclusionGroupNames: z.array(z.string()).default([]).describe("Smart/static computer group names to exclude from scope"),
                    scripts: z
                        .array(z.object({
                            name: z.string(),
                            priority: z.enum(["Before", "After"]).default("After"),
                            parameter4: z.string().optional(),
                        }))
                        .default([])
                        .describe("Scripts to run, by name — must already exist (see jamf_create_script)"),
                    packages: z
                        .array(z.object({
                            name: z.string(),
                            action: z.enum(["Install", "Cache", "Install Cached"]).default("Install"),
                        }))
                        .default([])
                        .describe("Packages to deploy, by name — must already exist (see jamf_upload_package)"),
                    selfService: z
                        .object({
                            useForSelfService: z.boolean(),
                            displayName: z.string().optional(),
                            installButtonText: z.string().optional(),
                            description: z.string().optional(),
                        })
                        .optional(),
                    maintenanceRecon: z.boolean().default(false).describe("Update computer inventory (recon) when this policy runs"),
                    diskEncryption: z
                        .discriminatedUnion("action", [
                            z.object({
                                action: z.literal("apply"),
                                configurationName: z.string().describe("Disk Encryption Configuration name — see jamf_list_disk_encryption_configurations"),
                                authRestart: z.boolean().optional().describe("Require an authenticated restart to complete encryption (default: false)"),
                            }),
                            z.object({
                                action: z.literal("remediate"),
                                remediateKeyType: z.enum(["Individual", "Institutional"]).describe("Which recovery key type to re-issue/escrow"),
                                configurationName: z.string().optional().describe("Disk Encryption Configuration name — only relevant when remediateKeyType is Institutional"),
                            }),
                        ])
                        .optional()
                        .describe(
                            "FileVault behavior for this policy. `apply` enables FileVault on an unencrypted Mac; " +
                            "`remediate` re-issues/escrows a recovery key on an already-encrypted one — these are " +
                            "mutually exclusive intents, use separate policies if you need both."
                        ),
                    userInteraction: z
                        .object({
                            messageStart: z.string().optional().describe("Message shown to the user before the policy runs"),
                            allowUserToDefer: z.boolean().optional().describe("Allow the user to postpone running this policy"),
                            allowDeferralUntilUtc: z.string().optional().describe("ISO 8601 UTC deadline after which deferral is no longer allowed"),
                            allowDeferralMinutes: z.number().int().min(0).optional().describe("Minutes the user may defer by, each time they defer"),
                            messageFinish: z.string().optional().describe("Message shown to the user after the policy completes"),
                        })
                        .optional()
                        .describe("End-user notification/deferral settings for this policy"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                name, enabled, triggerCheckin, triggerEnrollmentComplete, triggerLogin, triggerStartup, triggerOther,
                frequency, categoryName, targetGroupNames, exclusionGroupNames, scripts, packages, selfService,
                maintenanceRecon, diskEncryption, userInteraction, response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertPolicy({
                        name, enabled, triggerCheckin, triggerEnrollmentComplete, triggerLogin, triggerStartup, triggerOther,
                        frequency, categoryName, targetGroupNames, exclusionGroupNames, scripts, packages, selfService,
                        maintenanceRecon, diskEncryption, userInteraction,
                    });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created policy **${result.name}** (ID ${result.id}).`
                            : `Updated policy **${result.name}** (ID ${result.id}) in place.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 29. jamf_update_policy ────────────────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_update_policy",
            {
                description:
                    "Enable/disable an existing JAMF Pro policy, change its execution frequency, and/or widen or " +
                    "narrow its scope by adding/removing target or exclusion computer groups (smart or static, by " +
                    "name). Safely merges with the policy's existing scope — reads the full current policy, merges " +
                    "only the requested changes, and writes the whole thing back. Does not touch triggers, scripts, " +
                    "packages, or Self Service settings — use this only for the enable/disable + frequency + " +
                    "scope-widening workflow (e.g. staged rollout). Because this can meaningfully widen deployment " +
                    "or disable an active fix, double-check the group names before calling.",
                inputSchema: {
                    policy: z.string().describe("Policy name or numeric ID — use jamf_list_policies to find one"),
                    enabled: z.boolean().optional().describe(
                        "Set to enable/disable the policy. WARNING: confirmed live (Jamf Pro 11.29.1) — reads of a " +
                        "just-changed `enabled` value can be genuinely non-monotonic (a read can show the new " +
                        "value, then revert to the old one, before finally settling) for up to a minute or more. " +
                        "This tool waits and re-checks before responding, but for anything operationally important " +
                        "(disabling an active fix, or re-enabling one), independently re-verify with jamf_get_policy " +
                        "after a minute rather than trusting this call's response alone — check `enabledChangeFailed`."
                    ),
                    frequency: z
                        .enum(["Once per computer", "Once per user per computer", "Once per user", "Once every day", "Once every week", "Once every month", "Ongoing"])
                        .optional()
                        .describe(
                            "Change the policy's execution frequency. WARNING: confirmed live (Jamf Pro 11.29.1) — " +
                            "this has the same non-monotonic read-lag behavior as `enabled` above (can take up to a " +
                            "minute or more to settle). The response's `frequencyChangeFailed` field and markdown " +
                            "output reflect the actual post-write value after this tool's own wait/re-check, not " +
                            "just what you asked for — check it rather than assuming success."
                        ),
                    addTargetGroupNames: z.array(z.string()).default([]),
                    removeTargetGroupNames: z.array(z.string()).default([]),
                    addExclusionGroupNames: z.array(z.string()).default([]),
                    removeExclusionGroupNames: z.array(z.string()).default([]),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                policy, enabled, frequency, addTargetGroupNames, removeTargetGroupNames, addExclusionGroupNames, removeExclusionGroupNames,
                response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.updatePolicyScope(policy, {
                        enabled, frequency, addTargetGroupNames, removeTargetGroupNames, addExclusionGroupNames, removeExclusionGroupNames,
                    });
                    const text = toText(result, response_format, () => [
                        `## Policy **${result.name}** updated`,
                        `- **Enabled:** ${result.enabled ? "Yes" : "No"}${result.enabledChangeFailed ? " ⚠️ (requested change to " + enabled + " did NOT apply after waiting — re-verify with jamf_get_policy before trusting this)" : ""}`,
                        `- **Frequency:** ${result.frequency ?? "—"}${result.frequencyChangeFailed ? " ⚠️ (requested change to \"" + frequency + "\" did NOT apply after waiting — re-verify with jamf_get_policy before trusting this)" : ""}`,
                        `- **Target groups:** ${result.targetGroups.join(", ") || "none"}`,
                        `- **Exclusion groups:** ${result.exclusionGroups.join(", ") || "none"}`,
                    ].join("\n"));
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 30. jamf_list_ldap_servers ───────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_ldap_servers",
            {
                description:
                    "List LDAP servers configured in JAMF Pro (Settings > System > LDAP Servers). Use the " +
                    "returned ID with jamf_search_directory_user/jamf_search_directory_group, or omit serverId " +
                    "on those tools to search all configured servers.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getLdapServers();
                    const servers: any[] = data.results ?? [];
                    const text = toText(data, response_format, () => {
                        if (servers.length === 0) return "No LDAP servers configured.";
                        const rows = servers.map((s: any) => `- **${s.name}** (ID: ${s.id})`).join("\n");
                        return `## LDAP Servers (${servers.length})\n\n${rows}`;
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 31. jamf_search_directory_user ───────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_search_directory_user",
            {
                description:
                    "Search a configured LDAP server for a directory user by username. Returns the raw match — " +
                    "field names (e.g. username/realname/email_address) depend on how that server's attribute " +
                    "mappings are configured in Jamf Pro, so treat the raw result as authoritative. This searches " +
                    "the directory service directly, NOT existing Jamf Pro User objects (use jamf_list_computers " +
                    "or a Jamf User lookup for that) — use jamf_import_directory_user to create a Jamf Pro User " +
                    "from a directory match.",
                inputSchema: {
                    username: z.string().describe("Directory username to search for"),
                    serverId: z.string().describe("LDAP server ID — use jamf_list_ldap_servers to find one"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ username, serverId, response_format = "markdown" }) => {
                try {
                    const data = await client.searchLdapUsers(serverId, username);
                    const text = toText(data, response_format, () => {
                        if (data.results.length === 0) return `No directory match for "${username}" on LDAP server ${serverId}.`;
                        return `## Directory match for "${username}"\n\n\`\`\`json\n${JSON.stringify(data.results, null, 2)}\n\`\`\``;
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 32. jamf_search_directory_group ──────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_search_directory_group",
            {
                description:
                    "Search a configured LDAP server for a directory group by name, or (with username) check " +
                    "whether a specific user is a member of that group. Returns the raw match — field names " +
                    "depend on that server's attribute mappings in Jamf Pro.",
                inputSchema: {
                    groupName: z.string().describe("Directory group name to search for"),
                    username: z.string().optional().describe("If given, checks this user's membership in the group instead of just searching for the group"),
                    serverId: z.string().describe("LDAP server ID — use jamf_list_ldap_servers to find one"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupName, username, serverId, response_format = "markdown" }) => {
                try {
                    const data = username
                        ? await client.checkLdapGroupMembership(serverId, groupName, username)
                        : await client.searchLdapGroups(serverId, groupName);
                    const text = toText(data, response_format, () => {
                        if (data.results.length === 0) {
                            return username
                                ? `"${username}" is not a member of "${groupName}" on LDAP server ${serverId} (or the group doesn't exist).`
                                : `No directory match for group "${groupName}" on LDAP server ${serverId}.`;
                        }
                        const header = username ? `## Membership check: "${username}" in "${groupName}"` : `## Directory match for group "${groupName}"`;
                        return `${header}\n\n\`\`\`json\n${JSON.stringify(data.results, null, 2)}\n\`\`\``;
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 33. jamf_import_directory_user ───────────────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_import_directory_user",
            {
                description:
                    "Import a directory account as a Jamf Pro User object — the actual fix for a 'Directory " +
                    "Service Group shows 0 members' issue (smart user groups match against Jamf Pro User objects, " +
                    "not raw directory accounts). Idempotent: if a Jamf User with this username already exists, " +
                    "returns it rather than creating a duplicate. Searches all configured LDAP servers for a " +
                    "match unless serverId is given. fullName/email/position always override whatever the " +
                    "directory match parsed to — pass them explicitly if the LDAP attribute mapping doesn't " +
                    "produce the right values, or to import a user with no directory match at all (fullName " +
                    "required in that case). The response always includes the raw ldapMatch so you can verify " +
                    "what was imported.",
                inputSchema: {
                    username: z.string().describe("Directory/Jamf username"),
                    serverId: z.string().optional().describe("LDAP server ID to search — omit to search all configured servers"),
                    fullName: z.string().optional().describe("Override display name (required if no directory match exists)"),
                    email: z.string().optional().describe("Override email address"),
                    position: z.string().optional().describe("Override job title/position"),
                    siteId: z.string().optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ username, serverId, fullName, email, position, siteId, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.importDirectoryUser({ username, serverId, fullName, email, position, siteId });
                    const text = toText(result, response_format, () =>
                        result.action === "exists"
                            ? `Jamf User **${result.name}** (ID ${result.id}) already exists — no import needed.`
                            : `Imported **${result.name}** (ID ${result.id}) as a Jamf Pro User${result.matchedServerId ? ` from LDAP server ${result.matchedServerId}` : " (no directory match — created from overrides)"}.`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 34. jamf_test_directory_lookup ───────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_test_directory_lookup",
            {
                description:
                    "Passthrough for the Settings > Global > Cloud Identity Providers > Search test screen — " +
                    "confirms whether a group (and optionally a specific user's membership in it) resolves " +
                    "correctly against a Cloud Identity Provider (e.g. Entra ID/Azure AD sync), returning the " +
                    "same match-by-name/match-by-UUID result shown in the UI. This is the Cloud Identity Provider " +
                    "equivalent of jamf_search_directory_group, which is for classic LDAP servers instead. If " +
                    "idpId is omitted and exactly one Cloud Identity Provider is configured, it's used " +
                    "automatically; otherwise pass idpId to disambiguate.",
                inputSchema: {
                    groupName: z.string().describe("Directory group name to test"),
                    username: z.string().optional().describe("If given, tests this user's membership in the group instead of just resolving the group"),
                    idpId: z.string().optional().describe("Cloud Identity Provider ID — required only if more than one is configured"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ groupName, username, idpId, response_format = "markdown" }) => {
                try {
                    const data = await client.testCloudIdpLookup({ idpId, username, groupName });
                    const text = toText(data, response_format, () =>
                        `## Cloud Identity Provider test lookup (IdP ${data.idpId})\n\n\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 35. jamf_whoami ───────────────────────────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_whoami",
            {
                description:
                    "Report the current JAMF API client's identity and privilege list (wraps GET /api/v1/auth). " +
                    "Use this to diagnose a bare 401/403 from another tool — it distinguishes 'client authenticated " +
                    "fine but its role lacks this one privilege' from 'bad token', without having to hand-construct " +
                    "the /api/v1/auth call yourself.",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data: any = await client.getAuthDetails();
                    const text = toText(data, response_format, () => {
                        // Confirmed live (Jamf Pro 11.29.1): the response nests
                        // everything under `account`, with privileges grouped by
                        // site ID under `account.privilegesBySite` (not a flat
                        // `privileges` array) — e.g. {"-1": ["Read Computers", ...]}.
                        const account = data.account ?? {};
                        const privilegesBySite: Record<string, string[]> = account.privilegesBySite ?? {};
                        const lines = [
                            `## JAMF API Client Identity`,
                            `- **Account:** ${account.username ?? "—"}`,
                            `- **Access Level:** ${account.accessLevel ?? "—"}`,
                            `- **Privilege Set:** ${account.privilegeSet ?? "—"}`,
                            `- **Current Site:** ${account.currentSiteId ?? "—"}`,
                        ];
                        for (const [siteId, privileges] of Object.entries(privilegesBySite)) {
                            lines.push(`- **Privileges (site ${siteId}, ${privileges.length}):**`);
                            privileges.forEach((p) => lines.push(`  - ${p}`));
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

    // ── 36. jamf_list_disk_encryption_configurations ─────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_disk_encryption_configurations",
            {
                description:
                    "List Disk Encryption Configuration objects in JAMF Pro (Settings > Computer Management > " +
                    "Disk Encryption). These define the recovery-key type (Individual/Institutional) and escrow " +
                    "behavior that a policy's disk_encryption section references by ID — a distinct object type " +
                    "from a computer's own FileVault status (see jamf_get_filevault_status).",
                inputSchema: {
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ response_format = "markdown" }) => {
                try {
                    const data = await client.getDiskEncryptionConfigurations();
                    const configs: any[] = data.results ?? [];
                    const text = toText(data, response_format, () => {
                        if (configs.length === 0) return "No Disk Encryption Configurations found.";
                        const rows = configs.map((c: any) => `- **${c.name}** (ID: ${c.id})`).join("\n");
                        return `## Disk Encryption Configurations (${configs.length})\n\n${rows}`;
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 36b. jamf_create_disk_encryption_configuration ───────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_disk_encryption_configuration",
            {
                description:
                    "Create or update a JAMF Pro Disk Encryption Configuration, identified by name (upsert — " +
                    "re-running with the same name updates the existing configuration in place, matching " +
                    "jamf_create_script/jamf_create_smart_group). Scoped to key_type=Individual only — an " +
                    "Institutional configuration additionally needs an uploaded recovery-key certificate, which " +
                    "this tool does not support; create those manually in the JAMF Pro UI instead. Reference the " +
                    "result by name in jamf_create_policy's diskEncryption parameter.",
                inputSchema: {
                    name: z.string().describe("Configuration name — used as the upsert key"),
                    fileVaultEnabledUsers: z
                        .enum(["Management Account", "Current or Next User", "Management Account And Current or Next User"])
                        .optional()
                        .describe('Which account(s) can unlock the encrypted disk (default: "Current or Next User")'),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({ name, fileVaultEnabledUsers, response_format = "markdown" }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.upsertDiskEncryptionConfiguration({ name, fileVaultEnabledUsers });
                    const text = toText(result, response_format, () =>
                        result.action === "created"
                            ? `Created Disk Encryption Configuration **${result.name}** (ID ${result.id}).`
                            : `Updated Disk Encryption Configuration **${result.name}** (ID ${result.id}).`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 37. jamf_list_app_installer_titles ───────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_list_app_installer_titles",
            {
                description:
                    "List titles available in the JAMF App Catalog (Settings > App Installers) — the curated " +
                    "installer packages (e.g. Chrome, Zoom, Slack) deployable via jamf_create_app_installer_deployment. " +
                    "Distinct from jamf_list_packages, which lists manually-uploaded packages instead.",
                inputSchema: {
                    page: z.number().int().min(0).default(0).describe("Page number (0-indexed)"),
                    pageSize: z.number().int().min(1).max(999).default(200).describe("Results per page (default: 200)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ page = 0, pageSize = 200, response_format = "markdown" }) => {
                try {
                    const data = await client.getAppInstallerTitles(page, pageSize);
                    const titles: any[] = (data as any).results ?? [];
                    const text = toText(data, response_format, () => {
                        if (titles.length === 0) return "No app installer titles found.";
                        const rows = titles
                            .map((t: any) => `- **${t.titleName}** (ID: ${t.id}) | Publisher: ${t.publisher ?? "—"} | Version: ${t.version ?? "—"}`)
                            .join("\n");
                        return `## App Installer Titles (${(data as any).totalCount ?? titles.length} total)\n\n${rows}`;
                    });
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 38. jamf_get_app_installer_deployment ────────────────────────────────
    if (hasRole(roles, JAMF_READ)) {
        server.registerTool(
            "jamf_get_app_installer_deployment",
            {
                description:
                    "Get a single App Installer deployment by name or numeric ID, or omit both to list all " +
                    "configured deployments. Use jamf_list_app_installer_titles first to find an appTitleId for " +
                    "jamf_create_app_installer_deployment.",
                inputSchema: {
                    deployment: z.string().optional().describe("Deployment name or numeric ID — omit to list all deployments"),
                    page: z.number().int().min(0).default(0).describe("Page number when listing all (0-indexed)"),
                    pageSize: z.number().int().min(1).max(999).default(200).describe("Results per page when listing all (default: 200)"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: true, openWorldHint: true },
            },
            async ({ deployment, page = 0, pageSize = 200, response_format = "markdown" }) => {
                try {
                    if (!deployment) {
                        const data = await client.listAppInstallerDeployments(page, pageSize);
                        const deployments: any[] = (data as any).results ?? [];
                        const text = toText(data, response_format, () => {
                            if (deployments.length === 0) return "No app installer deployments found.";
                            // Confirmed live: the list endpoint's shape differs from the
                            // single-deployment detail endpoint — smartGroup/category/app
                            // are expanded nested objects here (not flat *Id fields), and
                            // it additionally includes a computerStatuses breakdown.
                            const rows = deployments
                                .map((d: any) => {
                                    const cs = d.computerStatuses ?? {};
                                    return `- **${d.name}** (ID: ${d.id}) | Enabled: ${d.enabled ? "Yes" : "No"} | Group: ${d.smartGroup?.name ?? "—"} | Installed: ${cs.installed ?? 0}, In Progress: ${cs.inProgress ?? 0}, Failed: ${cs.failed ?? 0}`;
                                })
                                .join("\n");
                            return `## App Installer Deployments (${(data as any).totalCount ?? deployments.length} total)\n\n${rows}`;
                        });
                        return { content: [{ type: "text", text }] };
                    }

                    const id = /^\d+$/.test(deployment)
                        ? deployment
                        : String(((await client.listAppInstallerDeployments(0, 999)) as any).results?.find(
                              (d: any) => d.name?.toLowerCase() === deployment.toLowerCase()
                          )?.id ?? "");
                    if (!id) return notFound(`app installer deployment "${deployment}"`);

                    const data: any = await client.getAppInstallerDeploymentDetail(id);
                    const text = toText(data, response_format, () => [
                        `## App Installer Deployment — ${data.name}`,
                        `- **ID:** ${data.id}`,
                        `- **Enabled:** ${data.enabled ? "Yes" : "No"}`,
                        `- **App Title ID:** ${data.appTitleId ?? "—"}`,
                        `- **Smart Group ID:** ${data.smartGroupId ?? "—"}`,
                        `- **Category ID:** ${data.categoryId ?? "—"}`,
                        `- **Site ID:** ${data.siteId ?? "—"}`,
                        `- **Deployment Type:** ${data.deploymentType ?? "—"}`,
                        `- **Update Behavior:** ${data.updateBehavior ?? "—"}`,
                        `- **Notification Interval (hrs):** ${data.notificationSettings?.notificationInterval ?? "—"}`,
                        `- **Deadline (days):** ${data.notificationSettings?.deadline ?? "—"}`,
                        `- **Latest Available Version:** ${data.latestAvailableVersion ?? "—"}`,
                        `- **Selected Version:** ${data.selectedVersion || "(auto-update to latest)"}`,
                    ].join("\n"));
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 39. jamf_create_app_installer_deployment ─────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_create_app_installer_deployment",
            {
                description:
                    "Create a new App Installer deployment — an ongoing Jamf-managed install/update subscription " +
                    "for a catalog title (see jamf_list_app_installer_titles), scoped to a smart computer group. " +
                    "NOT an upsert: deployment names aren't unique keys in Jamf, so re-running this always creates " +
                    "another deployment — use jamf_update_app_installer_deployment to change an existing one instead.",
                inputSchema: {
                    name: z.string().describe("Deployment display name"),
                    appTitleName: z.string().describe('Catalog title name, e.g. "Google Chrome" — see jamf_list_app_installer_titles'),
                    smartGroupName: z.string().describe("Smart computer group name to scope this deployment to"),
                    enabled: z.boolean().optional().describe("Default: true"),
                    categoryName: z.string().optional().describe("Category name — must match an existing JAMF category"),
                    siteId: z.string().optional().describe('Site ID, or "-1" for all sites (default)'),
                    deploymentType: z.enum(["INSTALL_AUTOMATICALLY", "SELF_SERVICE"]).optional().describe("Default: INSTALL_AUTOMATICALLY"),
                    updateBehavior: z.enum(["AUTOMATIC", "MANUAL"]).optional().describe("Default: AUTOMATIC"),
                    notificationInterval: z.number().int().min(1).optional().describe("Hours between end-user update notifications (default: 24)"),
                    deadline: z.number().int().min(0).optional().describe("Days before update is enforced (default: 7)"),
                    installPredefinedConfigProfiles: z.boolean().optional().describe("Default: false"),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                name, appTitleName, smartGroupName, enabled, categoryName, siteId, deploymentType, updateBehavior,
                notificationInterval, deadline, installPredefinedConfigProfiles, response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.createAppInstallerDeployment({
                        name, appTitleName, smartGroupName, enabled, categoryName, siteId, deploymentType,
                        updateBehavior, notificationInterval, deadline, installPredefinedConfigProfiles,
                    });
                    const text = toText(result, response_format, () =>
                        `Created app installer deployment **${result.name}** (ID ${result.id}).`
                    );
                    return { content: [{ type: "text", text }] };
                } catch (err) {
                    return errorResult(err);
                }
            }
        );
    }

    // ── 40. jamf_update_app_installer_deployment ─────────────────────────────
    if (hasRole(roles, JAMF_WRITE)) {
        server.registerTool(
            "jamf_update_app_installer_deployment",
            {
                description:
                    "Update an existing App Installer deployment by name or numeric ID — enable/disable, " +
                    "re-scope to a different smart group, or change category/deployment-type/update-behavior/" +
                    "notification settings. Only the fields you pass are changed; everything else is left as-is.",
                inputSchema: {
                    deployment: z.string().describe("Deployment name or numeric ID — use jamf_get_app_installer_deployment to find one"),
                    enabled: z.boolean().optional(),
                    smartGroupName: z.string().optional().describe("New smart computer group name to scope this deployment to"),
                    categoryName: z.string().optional(),
                    deploymentType: z.enum(["INSTALL_AUTOMATICALLY", "SELF_SERVICE"]).optional(),
                    updateBehavior: z.enum(["AUTOMATIC", "MANUAL"]).optional(),
                    notificationInterval: z.number().int().min(1).optional(),
                    deadline: z.number().int().min(0).optional(),
                    response_format: ResponseFormatSchema,
                },
                annotations: { readOnlyHint: false, openWorldHint: true },
            },
            async ({
                deployment, enabled, smartGroupName, categoryName, deploymentType, updateBehavior,
                notificationInterval, deadline, response_format = "markdown",
            }) => {
                try {
                    assertRole(roles, JAMF_WRITE);
                    const result = await client.updateAppInstallerDeployment(deployment, {
                        enabled, smartGroupName, categoryName, deploymentType, updateBehavior, notificationInterval, deadline,
                    });
                    const text = toText(result, response_format, () =>
                        `Updated app installer deployment **${result.name}** (ID ${result.id}).`
                    );
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
    // Mounted before routes so it wraps everything below, including /health and /metrics itself.
    app.use(metricsMiddleware);

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
            const caller = req.auth?.extra.upn ?? req.auth?.clientId ?? "unknown";
            const server = createJamfMcpServer(roles, caller);
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

    // Scraped by Prometheus. Open like /health — not behind requireMcpAuth — since
    // both servers are loopback-bound in production, fronted by Caddy.
    app.get("/metrics", metricsHandler);

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
