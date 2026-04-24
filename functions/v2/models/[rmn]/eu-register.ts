/**
 * /v2/models/:rmn/eu-register
 * RCAN 3.1 §26 — EU AI Act Art. 49 EU-Register entry intake.
 *
 * Art. 49 registration is scoped per AI system (per model), not per-robot.
 * URL carries the rmn (Robot Model Number). The submitting robot identifies
 * itself via `system.rrn` INSIDE THE SIGNED BODY; the server uses that field
 * to look up the robot's pq_signing_pub and verify the sig. No client-supplied
 * header is trusted for identity.
 *
 * POST — submitting robot posts a signed EU-register entry for a model.
 * GET  — public retrieval of the current entry for this model (Art. 49 transparency).
 *
 * Binding: doc.rmn === URL rmn. Submitter identity is bound to the signature
 * via doc.system.rrn (any client header is ignored).
 *
 * KV: compliance:eu-register:{rmn} + compliance:eu-register:history:{rmn}:{ts}
 */

import { EU_REGISTER_SCHEMA } from "rcan-ts";
import { verifyComplianceBody } from "../../_lib/compliance-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const TEN_YEARS_SECS = 10 * 365 * 24 * 3600;
const RRN_RE = /^RRN-[0-9]{12}$/;
const RMN_RE = /^RMN-[0-9]{12}$/;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  const rmn = params["rmn"] as string;

  if (!rmn || !RMN_RE.test(rmn)) return json({ error: "Invalid RMN format" }, 400);

  if (request.method === "GET")  return handleGet(env, rmn);
  if (request.method === "POST") return handlePost(request, env, rmn);
  return json({ error: "Method not allowed" }, 405);
};

async function handleGet(env: Env, rmn: string): Promise<Response> {
  const stored = await env.RRF_KV.get(`compliance:eu-register:${rmn}`, "text");
  if (!stored) return json({ error: "EU register entry not found", rmn }, 404);
  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
}

async function handlePost(request: Request, env: Env, rmn: string): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const system = body["system"] as Record<string, unknown> | undefined;
  const submitterRrn = system?.["rrn"];
  if (typeof submitterRrn !== "string") {
    return json({ error: "Signed doc missing system.rrn" }, 400);
  }
  if (!RRN_RE.test(submitterRrn)) {
    return json({ error: "Invalid system.rrn format" }, 400);
  }

  const result = await verifyComplianceBody(body, env, `robot:${submitterRrn}`);
  if (!result.ok) return json({ error: result.error }, result.status);

  const doc = result.document;
  if (doc.schema !== EU_REGISTER_SCHEMA) {
    return json({ error: `Expected schema ${EU_REGISTER_SCHEMA}, got ${String(doc.schema)}` }, 400);
  }
  if (doc.rmn !== rmn) {
    return json({ error: "Document rmn does not match URL rmn" }, 400);
  }

  const now = new Date().toISOString();
  const stored = JSON.stringify({ ...doc, _received_at: now, _submitted_by_rrn: submitterRrn });
  await env.RRF_KV.put(`compliance:eu-register:${rmn}`, stored, { expirationTtl: TEN_YEARS_SECS });
  await env.RRF_KV.put(`compliance:eu-register:history:${rmn}:${Date.now()}`, stored, { expirationTtl: TEN_YEARS_SECS });

  return json({
    ok: true,
    rmn,
    submitted_by_rrn: submitterRrn,
    submitted_at: now,
    eu_register_url: `https://api.rrf.rcan.dev/v2/models/${rmn}/eu-register`,
  }, 201);
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
