/**
 * POST /v2/orchestrators/register
 * RCAN v2.1 §2.9 — Register an M2M_TRUSTED orchestrator with RRF.
 *
 * WHAT IS ENFORCED (and nothing else): `Authorization: Bearer <RRF_ADMIN_TOKEN>`,
 * matching functions/v2/authorities/[ran]/index.ts. This is the interim custody
 * story while orchestrator onboarding has no self-service identity: only the
 * registry operator can create an orchestrator record. There is no CREATOR
 * token and no issuer for one — the earlier "JWT with rcan_role=5" claim
 * described a credential this registry cannot mint. Do not reintroduce it.
 *
 * Body: { rrn, orchestrator_key (Ed25519 SPKI PEM), fleet_rrns[], justification,
 *         deployed_by?, host? }
 * `deployed_by` and `host` are DECLARED by the registrant and are recorded as
 * such (see `declared_fields`); the registry verifies neither.
 *
 * `orchestrator_key` is the key the orchestrator later proves possession of at
 * GET /v2/orchestrators/:id/token, so it is the record's real credential.
 *
 * Creates orchestrator record with status: pending_consent. Activation requires
 * a signed consent from every fleet RRN (POST /v2/orchestrators/:id/consent).
 *
 * KV binding: RRF_KV
 * Key: orchestrator:{id}  →  OrchestratorRecord JSON
 */

import { nanoid } from "nanoid";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_ADMIN_TOKEN?: string;
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
  /** Self-declared by the registrant. Never verified by RRF. */
  deployed_by?: string;
  /** Self-declared by the registrant. Never verified by RRF. */
  host?: string;
  /** Which of the above were supplied by the registrant, labelled declared. */
  declared_fields?: string[];
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const authHeader = request.headers.get("Authorization") ?? "";
  if (!env.RRF_ADMIN_TOKEN || authHeader !== `Bearer ${env.RRF_ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { rrn, orchestrator_key, fleet_rrns, justification, deployed_by, host } = body as {
    rrn?: string;
    orchestrator_key?: string;
    fleet_rrns?: string[];
    justification?: string;
    deployed_by?: string;
    host?: string;
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
  // Declared-only provenance: recorded verbatim, labelled, never verified.
  const declared_fields: string[] = [];
  if (typeof deployed_by === "string" && deployed_by) declared_fields.push("deployed_by");
  if (typeof host === "string" && host) declared_fields.push("host");

  const record: OrchestratorRecord = {
    id,
    rrn,
    orchestrator_key,
    fleet_rrns,
    justification,
    status: "pending_consent",
    consents: Object.fromEntries(fleet_rrns.map((r) => [r, false])),
    registered_at: new Date().toISOString(),
    ...(declared_fields.includes("deployed_by") ? { deployed_by } : {}),
    ...(declared_fields.includes("host") ? { host } : {}),
    ...(declared_fields.length ? { declared_fields } : {}),
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
