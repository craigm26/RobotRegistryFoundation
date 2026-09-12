/**
 * POST /v2/orchestrators/:id/consent
 * RCAN v2.1 §2.9 — Grant or deny orchestrator fleet access consent.
 *
 * WHAT IS ENFORCED (and nothing else): the request body must be an RCAN
 * hybrid-signed document (`sig.ml_dsa` + `sig.ed25519` + `sig.ed25519_pub`,
 * `pq_kid`) whose signature verifies against the `pq_signing_pub` already
 * registered for the RRN named IN the signed body. The consenting robot signs
 * its own consent; the registry checks nothing else. There is no CREATOR token
 * and no issuer for one, so no bearer string is accepted here.
 *
 * Body (signed): { rrn, grant: true|false, sig, pq_kid }
 *
 * When all fleet_rrns have consented → status: active, first token issued.
 * When any fleet owner denies → status: revoked immediately.
 */

import { verifyComplianceBody } from "../../_lib/compliance-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_SIGNING_KEY?: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const id = params["id"] as string;

  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  // No credential at all (including any bearer string) is a 401, not a 400:
  // this endpoint takes a signed body and nothing else.
  const sigField = body["sig"] as Record<string, unknown> | undefined;
  if (!sigField || typeof body["pq_kid"] !== "string") {
    return json({
      error: "Signed consent body required (sig + pq_kid); bearer tokens are not accepted",
    }, 401);
  }

  const rrn = body["rrn"] as string | undefined;
  const grant = body["grant"];
  if (!rrn || typeof grant !== "boolean") {
    return json({ error: "Missing required fields: rrn (string), grant (boolean)" }, 400);
  }

  // Verify against the key registered for the RRN named in the SIGNED body —
  // never a key supplied in the submission, never a client-supplied header.
  const auth = await verifyComplianceBody(body, env, `robot:${rrn}`);
  if (!auth.ok) {
    return json({ error: auth.error }, auth.status);
  }

  // Load orchestrator record
  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json({ error: "Orchestrator not found", id }, 404);
  }

  const record = JSON.parse(stored) as {
    id: string; rrn: string; orchestrator_key: string; fleet_rrns: string[];
    justification: string; status: string; consents: Record<string, boolean>;
    registered_at: string; activated_at?: string; revoked_at?: string;
  };

  if (!record.fleet_rrns.includes(rrn)) {
    return json({ error: `RRN '${rrn}' is not in this orchestrator's fleet_rrns` }, 403);
  }

  if (record.status === "revoked") {
    return json({ error: "Orchestrator is already revoked" }, 409);
  }

  // Record consent decision
  record.consents[rrn] = grant;

  if (!grant) {
    // Any denial immediately revokes
    record.status = "revoked";
    record.revoked_at = new Date().toISOString();
    await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record));
    // Add to revocation list
    await addToRevocationList(env, id);
    return json({
      ok:         true,
      status:     "revoked",
      message:    `Orchestrator '${id}' revoked — consent denied by '${rrn}'`,
      revoked_at: record.revoked_at,
    });
  }

  // Check if all fleet_rrns have now consented
  const allConsented = record.fleet_rrns.every((r) => record.consents[r] === true);
  if (allConsented) {
    record.status = "active";
    record.activated_at = new Date().toISOString();
  }

  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record));

  if (allConsented) {
    return json({
      ok:           true,
      status:       "active",
      orchestrator_id: id,
      message:      "All owners consented — orchestrator activated. Use GET /v2/orchestrators/:id/token to issue tokens.",
      activated_at: record.activated_at,
    });
  }

  const remaining = record.fleet_rrns.filter((r) => record.consents[r] !== true);
  return json({
    ok:             true,
    status:         "pending_consent",
    orchestrator_id: id,
    consented_by:   rrn,
    remaining_consent_from: remaining,
  });
};

async function addToRevocationList(env: Env, orchestratorId: string): Promise<void> {
  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored ? JSON.parse(stored) as { revoked_orchestrators: string[]; revoked_jtis: string[] }
    : { revoked_orchestrators: [] as string[], revoked_jtis: [] as string[] };

  if (!list.revoked_orchestrators.includes(orchestratorId)) {
    list.revoked_orchestrators.push(orchestratorId);
  }
  await env.RRF_KV.put("revocations", JSON.stringify(list));
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json" },
  });
}
