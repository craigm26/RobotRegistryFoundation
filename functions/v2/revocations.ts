/**
 * GET /v2/revocations
 * RCAN v2.1 §2.9 — RRF revocation list.
 *
 * Returns the current revocation list for M2M_TRUSTED sessions.
 * Polled by robots every ≤ 60 s when any M2M_TRUSTED sessions are active.
 *
 * Response: { revoked_orchestrators: string[], revoked_jtis: string[], updated_at: string }
 *
 * Cache-Control: max-age=55 (safe for spec's ≤60s polling requirement)
 */

export interface Env {
  RRF_KV: KVNamespace;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored
    ? JSON.parse(stored) as { revoked_orchestrators: string[]; revoked_jtis: string[] }
    : { revoked_orchestrators: [] as string[], revoked_jtis: [] as string[] };

  const response = {
    revoked_orchestrators: list.revoked_orchestrators ?? [],
    revoked_jtis:          list.revoked_jtis ?? [],
    updated_at:            new Date().toISOString(),
  };

  return new Response(JSON.stringify(response), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=55",  // ≤60s per spec
    },
  });
};
