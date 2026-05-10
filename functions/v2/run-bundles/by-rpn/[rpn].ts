// functions/v2/run-bundles/by-rpn/[rpn].ts
//
// GET /v2/run-bundles/by-rpn/{rpn} — PUBLIC.
// Returns {run_ids: string[], count: number} for back-ref list.
// Per spec §7.3: absent key returns 200 with empty list (not 404).

export interface Env { RRF_KV: KVNamespace }

const ID_RE = /^RPN-\d{12}$/;
const KEY_PREFIX = "run-bundles-by-rpn:";

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const id = (params as { rpn: string }).rpn;
  if (!ID_RE.test(id)) {
    return json({ error: "Invalid RPN format" }, 400);
  }
  const raw = await env.RRF_KV.get(`${KEY_PREFIX}${id}`, "text");
  const run_ids = raw ? raw.split("\n").filter(Boolean) : [];
  return json({ run_ids, count: run_ids.length }, 200);
};
