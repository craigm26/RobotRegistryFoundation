/**
 * GET /v2/cert-intake/{cert_id}/proof
 *
 * Public (no auth). Returns the RRF-root-signed log entry for the cert_id.
 * Walks cert-intake-log:<idx> with paginated cursor (KV list returns ≤1000
 * keys per page; Plan 4 fix-loop pattern).
 *
 * Body NOT included — only the log entry, which contains the rig + witness +
 * RRF-root signatures and the index. Audit consumers can verify the
 * rrf_log_signature against the rrf:root:pubkey public key.
 */

import type { CertIntakeEntry } from "../../_lib/types.js";

export interface Env { RRF_KV: KVNamespace }

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const certId = params.cert_id as string | undefined;
  if (!certId || !certId.startsWith("cert_")) {
    return json({ error: "cert_id missing or malformed" }, 400);
  }

  let cursor: string | undefined;
  while (true) {
    const result: { keys: Array<{ name: string }>; list_complete: boolean; cursor?: string } =
      await env.RRF_KV.list({ prefix: "cert-intake-log:", cursor: cursor ?? undefined });
    for (const k of result.keys) {
      const raw = await env.RRF_KV.get(k.name, "text");
      if (!raw) continue;
      let entry: CertIntakeEntry;
      try { entry = JSON.parse(raw) as CertIntakeEntry; }
      catch { continue; }
      if (entry.cert_id === certId) {
        return json(entry);
      }
    }
    if (result.list_complete) break;
    cursor = result.cursor;
    if (!cursor) break;
  }

  return json({ error: `cert_id ${certId} not found in transparency log` }, 404);
};
