/**
 * /v2/robots/:rrn/ifu
 * RCAN 3.0 §24 — Instructions For Use (EU AI Act Art. 13(3)) intake.
 *
 * POST — robot submits a signed IFU document.
 * GET  — public retrieval of the current IFU for this robot.
 *
 * Binding: The §24 envelope carries no top-level rrn field. Binding to a
 * specific robot is via URL path + signature verification against
 * pq_signing_pub stored at robot:{URL-rrn}.
 *
 * KV: compliance:ifu:{rrn} + compliance:ifu:history:{rrn}:{ts}
 */

import { IFU_SCHEMA } from "rcan-ts";
import { verifyComplianceSubmission } from "../../_lib/compliance-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const TEN_YEARS_SECS = 10 * 365 * 24 * 3600;
const RRN_RE = /^RRN-[0-9]{12}$/;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  const rrn = params["rrn"] as string;

  if (!rrn || !RRN_RE.test(rrn)) return json({ error: "Invalid RRN format" }, 400);

  if (request.method === "GET")  return handleGet(env, rrn);
  if (request.method === "POST") return handlePost(request, env, rrn);
  return json({ error: "Method not allowed" }, 405);
};

async function handleGet(env: Env, rrn: string): Promise<Response> {
  const stored = await env.RRF_KV.get(`compliance:ifu:${rrn}`, "text");
  if (!stored) return json({ error: "IFU not found", rrn }, 404);
  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
}

async function handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  const result = await verifyComplianceSubmission(request, env, `robot:${rrn}`);
  if (!result.ok) return json({ error: result.error }, result.status);

  const doc = result.document;
  if (doc.schema !== IFU_SCHEMA) {
    return json({ error: `Expected schema ${IFU_SCHEMA}, got ${String(doc.schema)}` }, 400);
  }

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now });
  await env.RRF_KV.put(`compliance:ifu:${rrn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:ifu:history:${rrn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rrn,
    submitted_at: now,
    ifu_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/ifu`,
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
