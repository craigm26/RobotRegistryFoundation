/**
 * GET /v2/p66-schemas  (R7)
 * Plan 6 Task 5 — Protocol-66 schema registry.
 *
 * Surfaces the named JSON schemas used for Protocol-66 packets (the safety
 * benchmark / FRIA / IFU artifacts in RCAN §22-26). Sourced from rcan-spec.
 */

const P66_SCHEMAS = [
  { id: "p66-core", version: "1.0", title: "Protocol-66 core invariants schema." },
  { id: "safety-benchmark", version: "1.0", title: "Safety-benchmark packet schema (RCAN §23)." },
  { id: "fria", version: "1.0", title: "Fundamental Rights Impact Assessment packet schema (RCAN §22)." },
  { id: "ifu", version: "1.0", title: "Instructions-for-Use packet schema (RCAN §24)." },
];

export const onRequest: PagesFunction = async ({ request }) => {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { "Content-Type": "application/json" },
    });
  }
  const body = {
    matrix_version: "1.0",
    schemas: P66_SCHEMAS,
  };
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
    },
  });
};
