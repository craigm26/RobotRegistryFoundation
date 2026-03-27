/**
 * TEMPORARY — DELETE after use
 * GET /admin/wipe?secret=clawd-wipe-2026
 * Deletes all KV keys and resets counters.
 */
export interface Env { RRF_KV: KVNamespace }

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  if (url.searchParams.get("secret") !== "clawd-wipe-2026") {
    return new Response(JSON.stringify({ error: "forbidden" }), { status: 403 });
  }

  const deleted: string[] = [];
  for (const prefix of ["robot:", "component:", "model:", "harness:", "counter:"]) {
    let cursor: string | undefined;
    do {
      const list: KVNamespaceListResult<unknown, string> = await env.RRF_KV.list({
        prefix, limit: 200, cursor
      });
      for (const key of list.keys) {
        await env.RRF_KV.delete(key.name);
        deleted.push(key.name);
      }
      cursor = list.list_complete ? undefined : (list as any).cursor;
    } while (cursor);
  }

  return new Response(JSON.stringify({ deleted, total: deleted.length }), {
    headers: { "Content-Type": "application/json" }
  });
};
