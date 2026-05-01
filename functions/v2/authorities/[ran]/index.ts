/**
 * GET  /v2/authorities/:ran — fetch a single AuthorityRecord by RAN.
 * DELETE /v2/authorities/:ran — admin-only revocation (sets status to 'revoked',
 *   preserves the record for transparency log). Identity registries must retain
 *   records; hard deletes are not permitted.
 */

import type { AuthorityRecord } from "../../_lib/types.js";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_ADMIN_TOKEN?: string;
}

const isRan = (s: string) => /^RAN-\d{12}$/.test(s);

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ params, env }) => {
  const ran = String(params.ran ?? "");
  if (!isRan(ran)) return json({ error: "invalid RAN format" }, 400);
  const raw = await env.RRF_KV.get(`authority:${ran}`, "text");
  if (!raw) return json({ error: "RAN not found" }, 404);
  return new Response(raw, {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
};

export const onRequestDelete: PagesFunction<Env> = async ({ params, env, request }) => {
  // Admin-token gated. Soft-delete: sets status to "revoked"; record persists.
  const auth = request.headers.get("Authorization") ?? "";
  if (!env.RRF_ADMIN_TOKEN || auth !== `Bearer ${env.RRF_ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }
  const ran = String(params.ran ?? "");
  if (!isRan(ran)) return json({ error: "invalid RAN format" }, 400);

  const raw = await env.RRF_KV.get(`authority:${ran}`);
  if (!raw) return json({ error: "RAN not found" }, 404);
  const rec = JSON.parse(raw) as AuthorityRecord;
  if (rec.status === "revoked") return json({ error: "already revoked", record: rec }, 409);

  // Allow operator to pass a reason via query param OR JSON body.
  const url = new URL(request.url);
  let reason = url.searchParams.get("reason") ?? undefined;
  if (!reason) {
    try {
      const body = await request.clone().json() as { reason?: string };
      reason = body?.reason;
    } catch { /* no body or non-JSON body — fine, reason stays undefined */ }
  }

  const updated: AuthorityRecord = {
    ...rec,
    status: "revoked",
    revoked_at: new Date().toISOString(),
    ...(reason ? { revocation_reason: reason } : {}),
  };
  await env.RRF_KV.put(`authority:${ran}`, JSON.stringify(updated));
  return json({ status: "revoked", record: updated }, 200);
};
