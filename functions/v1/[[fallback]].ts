/**
 * /v1/* — Deprecated catch-all handler (RCAN v1.x era)
 *
 * The RRF v1 API is deprecated and removed as of RCAN v2.0.
 * All clients must migrate to the v2 API which supports the full
 * RCAN v2.2 entity-type numbering system (RRN / RCN / RMN / RHN).
 *
 * Migration guide: https://robotregistryfoundation.org/api/
 */

export const onRequest: PagesFunction = async ({ request }) => {
  const originalPath = new URL(request.url).pathname;

  // Best-effort v1 → v2 path mapping for common GET endpoints
  const migration = getMigrationHint(originalPath);

  const body = {
    error: "API v1 is deprecated and removed",
    code: "API_VERSION_DEPRECATED",
    original_path: originalPath,
    rcan_era: "v1.x",
    action: "Migrate to RRF API v2 — supports RRN, RCN, RMN, RHN entity types (RCAN v2.2 §21)",
    docs: "https://robotregistryfoundation.org/api/",
    v2_base: "https://robotregistryfoundation.org/v2/",
    ...(migration ? { v2_equivalent: migration } : {}),
  };

  return new Response(JSON.stringify(body, null, 2), {
    status: 410,
    headers: {
      "Content-Type": "application/json",
      "Deprecation": "true",
      "Sunset": "2026-03-27",
      "Link": '<https://robotregistryfoundation.org/api/>; rel="successor-version"',
    },
  });
};

function getMigrationHint(path: string): string | null {
  // /v1/robots → /v2/registry?type=robot
  if (path.match(/^\/v1\/robots\/?$/)) return "/v2/registry?type=robot";
  // /v1/robots/:rrn → /v2/robots/:rrn
  const rrnMatch = path.match(/^\/v1\/robots\/(RRN-[0-9]{12})/);
  if (rrnMatch) return `/v2/robots/${rrnMatch[1]}`;
  // /v1/metrics → /v2/registry (entity_types_count has per-type counts)
  if (path.match(/^\/v1\/metrics\/?$/)) return "/v2/registry";
  // /v1/resolve/:rrn → /v2/robots/:rrn (federation resolver merged)
  const resolveMatch = path.match(/^\/v1\/resolve\/(RRN-[0-9]{12})/);
  if (resolveMatch) return `/v2/robots/${resolveMatch[1]}`;
  return null;
}
