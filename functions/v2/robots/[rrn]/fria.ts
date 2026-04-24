/**
 * /v2/robots/:rrn/fria
 * RCAN 3.0 §22 — Fundamental Rights Impact Assessment intake.
 *
 * POST — robot submits a signed FRIA document.
 * GET  — Bearer-gated retrieval (FRIA may contain sensitive analysis).
 *
 * Binding: FRIA envelopes carry robot identity in `doc.system.rrn` (per
 * rcan-ts FriaDocument interface). We require `doc.system.rrn === URL rrn`
 * in addition to signature verification.
 *
 * KV: compliance:fria:{rrn} + compliance:fria:history:{rrn}:{ts}
 */

import { verifyComplianceSubmission } from "../../_lib/compliance-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const TEN_YEARS_SECS = 10 * 365 * 24 * 3600;
const RRN_RE = /^RRN-[0-9]{12}$/;
const FRIA_SCHEMA = "rcan-fria-v1";  // TODO: sweep into rcan-ts as FRIA_SCHEMA const

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  const rrn = params["rrn"] as string;

  if (!rrn || !RRN_RE.test(rrn)) return json({ error: "Invalid RRN format" }, 400);

  if (request.method === "GET")  return handleGet(request, env, rrn);
  if (request.method === "POST") return handlePost(request, env, rrn);
  return json({ error: "Method not allowed" }, 405);
};

async function handleGet(request: Request, env: Env, rrn: string): Promise<Response> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return json({ error: "Authorization required" }, 401);

  const stored = await env.RRF_KV.get(`compliance:fria:${rrn}`, "text");
  if (!stored) return json({ error: "FRIA not found", rrn }, 404);
  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "private, max-age=60" },
  });
}

async function handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  const result = await verifyComplianceSubmission(request, env, `robot:${rrn}`);
  if (!result.ok) return json({ error: result.error }, result.status);

  const doc = result.document;
  if (doc.schema !== FRIA_SCHEMA) {
    return json({ error: `Expected schema ${FRIA_SCHEMA}, got ${String(doc.schema)}` }, 400);
  }

  const system = doc.system as Record<string, unknown> | undefined;
  if (!system || typeof system !== "object") {
    return json({ error: "Document missing 'system' block" }, 400);
  }
  if (system.rrn !== rrn) {
    return json({ error: "Document system.rrn does not match URL rrn" }, 400);
  }

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now });
  await env.RRF_KV.put(`compliance:fria:${rrn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:fria:history:${rrn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rrn,
    submitted_at: now,
    fria_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/fria`,
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
