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
 *
 * EV cross-reference (RCAN Appendix C, informative): a submission MAY carry
 * `ev_tests_covered`, a list of the physical-assurance test IDs (EV-01..EV-09)
 * the benchmark claims to cover. It is part of the signed document, stored as
 * submitted, and echoed back labelled as self-reported. RRF does not run or
 * check the tests, and nothing here marks a robot as having passed them.
 */

import { SAFETY_BENCHMARK_SCHEMA } from "rcan-ts";
import { verifyComplianceSubmission } from "../../_lib/compliance-auth.js";
import { API_BASE } from "../../_lib/api-base.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const TEN_YEARS_SECS = 10 * 365 * 24 * 3600;
const RRN_RE = /^RRN-[0-9]{12}$/;
const EV_ID_RE = /^EV-0[1-9]$/;
export const EV_TESTS_URL =
  "https://github.com/RobotRegistryFoundation/rcan-spec/blob/master/tests/assurance/README.md";

/** Validate the optional ev_tests_covered list. Returns an error or null. */
export function validateEvTests(v: unknown): string | null {
  if (v === undefined) return null;
  if (!Array.isArray(v) || v.length === 0 || v.length > 9) {
    return "ev_tests_covered must be a non-empty array of EV test IDs (EV-01..EV-09)";
  }
  if (!v.every((x) => typeof x === "string" && EV_ID_RE.test(x))) {
    return "ev_tests_covered entries must be EV-01..EV-09";
  }
  if (new Set(v).size !== v.length) return "ev_tests_covered entries must be unique";
  return null;
}

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

  const evError = validateEvTests(doc.ev_tests_covered);
  if (evError) return json({ error: evError }, 400);

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now });
  await env.RRF_KV.put(`compliance:safety-benchmark:${rrn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:safety-benchmark:history:${rrn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rrn,
    submitted_at: now,
    safety_benchmark_url: `${API_BASE}/v2/robots/${rrn}/safety-benchmark`,
    ...(doc.ev_tests_covered !== undefined && {
      ev_tests_covered: doc.ev_tests_covered,
      ev_tests_basis: "self-reported by the submitter; RRF has not run or checked these tests",
      ev_tests_reference: EV_TESTS_URL,
    }),
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
