/**
 * Shared pagination slicing for JAMF and Intune list endpoints.
 *
 * Slicing only happens when the caller explicitly asks for a page — omitting
 * both page and pageSize returns the full array. This matters for internal
 * name-resolution helpers (resolveAppByName, resolvePolicyByName) that need
 * the complete filtered set to detect ambiguous/exact matches; only the
 * LLM-facing list tools pass explicit page/pageSize.
 */
export function paginate<T>(
    items: T[],
    page?: number,
    pageSize?: number
): { items: T[]; totalCount: number; page?: number; pageSize?: number } {
    const totalCount = items.length;

    if (page === undefined && pageSize === undefined) {
        return { items, totalCount };
    }

    const effectivePage = page ?? 0;
    const effectivePageSize = pageSize ?? 100;
    const start = effectivePage * effectivePageSize;

    return {
        items: items.slice(start, start + effectivePageSize),
        totalCount,
        page: effectivePage,
        pageSize: effectivePageSize
    };
}
