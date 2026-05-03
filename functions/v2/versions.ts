/**
 * GET /v2/versions  (R1)
 * Plan 6 Task 5 — protocol-version registry.
 *
 * Surfaces the protocol versions known to RCAN. Static data sourced from
 * rcan-spec authoritative tables; RRF mirrors on next deploy.
 */

const PROTOCOL_VERSIONS = [
  { version: "3.2.0", status: "stable", released_at: "2026-04-24" },
  { version: "3.2.2", status: "stable", released_at: "2026-05-03" },
];

export const onRequest: PagesFunction = async ({ request }) => {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { "Content-Type": "application/json" },
    });
  }
  const body = {
    matrix_version: "1.0",
    protocol_versions: PROTOCOL_VERSIONS,
  };
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
    },
  });
};
