// functions/v2/run-bundles/log/[idx].ts
//
// GET /v2/run-bundles/log/{idx} — PUBLIC.
// Returns the signed transparency-log entry at the given monotonic index.

export interface Env { RRF_KV: KVNamespace }

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const idx = (params as { idx: string }).idx;
  if (!/^\d+$/.test(idx)) {
    return json({ error: "idx must be a non-negative integer" }, 400);
  }
  const padded = idx.padStart(12, "0");
  const raw = await env.RRF_KV.get(`run-bundle-log:${padded}`, "text");
  if (!raw) {
    return json({ error: `Log entry not found: ${idx}` }, 404);
  }
  return new Response(raw, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
