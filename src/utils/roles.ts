/**
 * Entra App Role names and role-checking helpers shared by both MCP servers.
 *
 * Role names must match the App Roles defined on the "Desktop Management MCP"
 * Entra resource app registration exactly (case-sensitive).
 */

export const JAMF_READ = "Jamf.Read";
export const JAMF_WRITE = "Jamf.Write";
export const INTUNE_READ = "Intune.Read";
export const INTUNE_WRITE = "Intune.Write";

export const JAMF_ALL_ROLES = [JAMF_READ, JAMF_WRITE];
export const INTUNE_ALL_ROLES = [INTUNE_READ, INTUNE_WRITE];

export type AuthMode = "static-token" | "entra";

export function hasRole(roles: string[], required: string): boolean {
    return roles.includes(required);
}

/**
 * Defense-in-depth check for the handful of destructive JAMF write tools:
 * re-validates the same `roles` array already used to gate registration, so
 * it mainly guards against a future refactor that omits the registration-time
 * check, not against `roles` itself being computed wrong upstream.
 */
export function assertRole(roles: string[], required: string): void {
    if (!hasRole(roles, required)) {
        throw new Error(`Missing required role: ${required}`);
    }
}

/**
 * Resolves the effective role set for a request.
 *
 * Static-token callers are mapped to every role this server defines — that
 * token already grants full access today, and this preserves that behavior
 * exactly rather than inventing new granularity for the automation path.
 * Entra callers get whatever `roles` claim their verified token actually carries.
 */
export function resolveRolesFromAuthInfo(
    authMode: AuthMode,
    entraRoles: string[] | undefined,
    allRolesForThisServer: string[],
): string[] {
    if (authMode === "static-token") {
        return allRolesForThisServer;
    }
    return entraRoles ?? [];
}
