/**
 * /v2/robots/:rrn/safety-benchmark
 * RCAN 3.0 §23 — Safety Benchmark intake.
 *
 * POST — robot submits a signed safety-benchmark document.
 * GET  — public retrieval of the current benchmark for this robot.
 *
 * Binding: The §23 envelope carries no top-level rrn field. Binding to a
 * specific robot is established by (1) the URL path rrn, and (2) the
 * cryptographic signature verified against the pq_signing_pub stored at
 * robot:{URL-rrn}. A submission signed by a different robot's key would
 * fail signature verification.
 *
 * KV: compliance:safety-benchmark:{rrn} + compliance:safety-benchmark:history:{rrn}:{ts}
 */

import { SAFETY_BENCHMARK_SCHEMA } from "rcan-ts";
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
  const stored = await env.RRF_KV.get(`compliance:safety-benchmark:${rrn}`, "text");
  if (!stored) return json({ error: "Safety benchmark not found", rrn }, 404);
  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
}

async function handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  const result = await verifyComplianceSubmission(request, env, `robot:${rrn}`);
  if (!result.ok) return json({ error: result.error }, result.status);

  const doc = result.document;
  if (doc.schema !== SAFETY_BENCHMARK_SCHEMA) {
    return json({ error: `Expected schema ${SAFETY_BENCHMARK_SCHEMA}, got ${String(doc.schema)}` }, 400);
  }

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now });
  await env.RRF_KV.put(`compliance:safety-benchmark:${rrn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:safety-benchmark:history:${rrn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rrn,
    submitted_at: now,
    safety_benchmark_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/safety-benchmark`,
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
