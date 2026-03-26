/**
 * POST /v2/orchestrators/:id/consent
 * RCAN v2.1 §2.9 — Grant or deny orchestrator fleet access consent.
 *
 * Body: { rrn, grant: true|false }
 * Requires valid CREATOR token for the consenting RRN.
 *
 * When all fleet_rrns have consented → status: active, first token issued.
 * When any CREATOR denies → status: revoked immediately.
 */

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

  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json({ error: "Authorization required (CREATOR token)" }, 401);
  }

  let body: { rrn?: string; grant?: boolean };
  try {
    body = await request.json() as { rrn?: string; grant?: boolean };
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { rrn, grant } = body;
  if (!rrn || typeof grant !== "boolean") {
    return json({ error: "Missing required fields: rrn (string), grant (boolean)" }, 400);
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
