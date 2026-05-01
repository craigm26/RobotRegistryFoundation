/**
 * GET /v2/authorities — paginated list of registered RAN authorities.
 *
 * Query params:
 *   cursor?  pagination cursor from previous response
 *   limit?   max results (default 50, max 200)
 *
 * Returns: { entries[], next_cursor }
 */

import type { AuthorityRecord } from "../_lib/types.js";

export interface Env {
  RRF_KV: KVNamespace;
}

export const onRequestGet: PagesFunction<Env> = async ({ env, request }) => {
  const url = new URL(request.url);
  const cursor = url.searchParams.get("cursor") ?? undefined;
  const rawLimit = parseInt(url.searchParams.get("limit") ?? "50", 10);
  const limit = Math.min(isNaN(rawLimit) ? 50 : rawLimit, 200);

  const list = await env.RRF_KV.list({ prefix: "authority:RAN-", cursor, limit });

  const entries = [];
  for (const k of list.keys) {
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    const rec = JSON.parse(raw) as AuthorityRecord;
    // Return a summary — omit signing keys from list view
    entries.push({
      ran: rec.ran,
      organization: rec.organization,
      display_name: rec.display_name,
      purpose: rec.purpose,
      registered_at: rec.registered_at,
      status: rec.status,
    });
  }

  return new Response(
    JSON.stringify({
      entries,
      next_cursor: list.list_complete ? null : (list as any).cursor ?? null,
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=60",
      },
    },
  );
};
