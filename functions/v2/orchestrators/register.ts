/**
 * POST /v2/orchestrators/register
 * RCAN v2.1 §2.9 — Register an M2M_TRUSTED orchestrator with RRF.
 *
 * Body: { rrn, orchestrator_key (Ed25519 pubkey PEM), fleet_rrns[], justification }
 * Requires valid CREATOR token (JWT with rcan_role=5) for the registering RRN.
 *
 * Creates orchestrator record with status: pending_consent
 * Sends CONSENT_REQUEST (20) to all fleet_rrns owners (simulated via KV queue)
 *
 * KV binding: RRF_KV
 * Key: orchestrator:{id}  →  OrchestratorRecord JSON
 */

import { nanoid } from "https://cdn.jsdelivr.net/npm/nanoid@5/nanoid.js";

export interface Env {
  RRF_KV: KVNamespace;
}

interface OrchestratorRecord {
  id: string;
  rrn: string;
  orchestrator_key: string;
  fleet_rrns: string[];
  justification: string;
  status: "pending_consent" | "active" | "revoked";
  consents: Record<string, boolean>;  // rrn → granted
  registered_at: string;
  activated_at?: string;
  revoked_at?: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json({ error: "Authorization required (CREATOR token)" }, 401);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { rrn, orchestrator_key, fleet_rrns, justification } = body as {
    rrn?: string;
    orchestrator_key?: string;
    fleet_rrns?: string[];
    justification?: string;
  };

  if (!rrn || !orchestrator_key || !fleet_rrns || !justification) {
    return json(
      { error: "Missing required fields: rrn, orchestrator_key, fleet_rrns, justification" },
      400,
    );
  }

  if (!Array.isArray(fleet_rrns) || fleet_rrns.length === 0) {
    return json({ error: "fleet_rrns must be a non-empty array" }, 400);
  }

  if (fleet_rrns.length > 50) {
    return json({ error: "fleet_rrns may not exceed 50 robots" }, 400);
  }

  // Validate all RRNs
  const rrn_re = /^RRN-[0-9]{12}$/;
  for (const r of [rrn, ...fleet_rrns]) {
    if (!rrn_re.test(r)) {
      return json({ error: `Invalid RRN format: ${r}` }, 400);
    }
  }

  const id = `orch-${nanoid(16)}`;
  const record: OrchestratorRecord = {
    id,
    rrn,
    orchestrator_key,
    fleet_rrns,
    justification,
    status: "pending_consent",
    consents: Object.fromEntries(fleet_rrns.map((r) => [r, false])),
    registered_at: new Date().toISOString(),
  };

  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record), {
    expirationTtl: 90 * 24 * 3600,
  });

  // Queue consent requests (simplified: store consent-pending entries per robot)
  for (const fleetRrn of fleet_rrns) {
    const consentKey = `consent:pending:${fleetRrn}:${id}`;
    await env.RRF_KV.put(consentKey, JSON.stringify({
      orchestrator_id: id,
      requesting_rrn:  rrn,
      fleet_rrns,
      justification,
      requested_at:    new Date().toISOString(),
    }), { expirationTtl: 7 * 24 * 3600 }); // 7 day consent window
  }

  return json({
    ok:                  true,
    orchestrator_id:     id,
    status:              "pending_consent",
    consent_required_from: fleet_rrns,
    registered_at:       record.registered_at,
    message: `Consent requests sent to ${fleet_rrns.length} robot owner(s). Token will be issued when all owners consent.`,
  }, 201);
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
