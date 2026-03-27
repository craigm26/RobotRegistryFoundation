/**
 * TEMPORARY one-shot admin endpoint — removes all robot/orchestrator KV keys.
 * REMOVE this file after deploy + use.
 */
interface Env {
  RRF_KV: KVNamespace;
  ADMIN_SECRET?: string;
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  // Require admin secret
  const authHeader = request.headers.get("Authorization") || "";
  const expectedSecret = env.ADMIN_SECRET || "rrf-admin-clear-2026";
  if (authHeader !== `Bearer ${expectedSecret}`) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const deleted: string[] = [];
  const kept: string[] = [];
  const errors: string[] = [];

  // List all keys
  let cursor: string | undefined;
  const allKeys: string[] = [];
  do {
    const list = await env.RRF_KV.list({ cursor, limit: 1000 });
    for (const key of list.keys) allKeys.push(key.name);
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  // Delete robot/orchestrator/sbom keys; keep root pubkey
  for (const key of allKeys) {
    if (key === "rrf:root:pubkey") {
      kept.push(key);
      continue;
    }
    try {
      await env.RRF_KV.delete(key);
      deleted.push(key);
    } catch (e) {
      errors.push(`${key}: ${e}`);
    }
  }

  return new Response(
    JSON.stringify({ deleted, kept, errors, total: allKeys.length }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
};
