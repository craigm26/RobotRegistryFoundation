// functions/v2/run-bundles/[run_id]/index.ts
//
// GET /v2/run-bundles/{run_id} — PUBLIC.
// Returns wrapper {record, transparency_log_index, logged_at, rrf_log_signature}.

export interface Env { RRF_KV: KVNamespace }

const RUN_ID_RE = /^runbundle_[0-9a-f]{12}$/;

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const runId = (params as { run_id: string }).run_id;
  if (!RUN_ID_RE.test(runId)) {
    return json({ error: "Invalid run_id format" }, 400);
  }
  const raw = await env.RRF_KV.get(`run-bundle:${runId}`, "text");
  if (!raw) {
    return json({ error: `Not found: ${runId}` }, 404);
  }
  return new Response(raw, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
