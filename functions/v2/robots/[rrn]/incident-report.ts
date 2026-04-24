/**
 * /v2/robots/:rrn/incident-report
 * RCAN 3.0 §25 — EU AI Act Art. 72 post-market incident report intake.
 *
 * POST — robot submits a signed incident-report (snapshot of the producer's
 *        local incident log; re-submitting replaces the current).
 * GET  — Bearer-gated retrieval (reports may contain sensitive incident data).
 *
 * Binding: buildIncidentReport emits top-level `rrn`. We require
 * `doc.rrn === URL rrn` in addition to signature verification.
 *
 * KV: compliance:incident-report:{rrn} + compliance:incident-report:history:{rrn}:{ts}
 */

import { INCIDENT_REPORT_SCHEMA } from "rcan-ts";
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

  if (request.method === "GET")  return handleGet(request, env, rrn);
  if (request.method === "POST") return handlePost(request, env, rrn);
  return json({ error: "Method not allowed" }, 405);
};

async function handleGet(request: Request, env: Env, rrn: string): Promise<Response> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return json({ error: "Authorization required" }, 401);

  const stored = await env.RRF_KV.get(`compliance:incident-report:${rrn}`, "text");
  if (!stored) return json({ error: "Incident report not found", rrn }, 404);
  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "private, max-age=60" },
  });
}

async function handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  const result = await verifyComplianceSubmission(request, env, `robot:${rrn}`);
  if (!result.ok) return json({ error: result.error }, result.status);

  const doc = result.document;
  if (doc.schema !== INCIDENT_REPORT_SCHEMA) {
    return json({ error: `Expected schema ${INCIDENT_REPORT_SCHEMA}, got ${String(doc.schema)}` }, 400);
  }
  if (doc.rrn !== rrn) {
    return json({ error: "Document rrn does not match URL rrn" }, 400);
  }

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now });
  await env.RRF_KV.put(`compliance:incident-report:${rrn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:incident-report:history:${rrn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rrn,
    submitted_at: now,
    incident_report_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/incident-report`,
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
