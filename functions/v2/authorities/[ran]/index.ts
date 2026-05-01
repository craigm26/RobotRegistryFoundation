/**
 * GET  /v2/authorities/:ran — fetch a single AuthorityRecord by RAN.
 * DELETE /v2/authorities/:ran — admin-only soft-delete (removes from KV).
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
  const auth = request.headers.get("Authorization") ?? "";
  if (!env.RRF_ADMIN_TOKEN || auth !== `Bearer ${env.RRF_ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }
  const ran = String(params.ran ?? "");
  if (!isRan(ran)) return json({ error: "invalid RAN format" }, 400);
  const raw = await env.RRF_KV.get(`authority:${ran}`, "text");
  if (!raw) return json({ error: "RAN not found" }, 404);
  await env.RRF_KV.delete(`authority:${ran}`);
  return json({ status: "deleted", ran }, 200);
};
