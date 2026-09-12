/**
 * DELETE /v2/orchestrators/:id
 * RCAN v2.1 §2.9 — Revoke an orchestrator.
 *
 * WHAT IS ENFORCED (and nothing else): `Authorization: Bearer <RRF_ADMIN_TOKEN>`,
 * matching functions/v2/authorities/[ran]/index.ts. This is the interim custody
 * story: only the registry operator can revoke. There is no CREATOR token and
 * no issuer for one — the earlier "any consenting CREATOR can call this" claim
 * described a credential that does not exist. A fleet owner who wants an
 * orchestrator stopped denies consent via POST /v2/orchestrators/:id/consent,
 * which revokes it with a signature the registry can actually check.
 *
 * Immediately adds orchestrator to the RRF revocation list.
 * Revoked entries are retained for 90 days (for revocation polling).
 *
 * Revocation is identity-layer only: RRF publishes the list, the robot polls
 * /v2/revocations and refuses locally. RRF enforces nothing.
 */

export interface Env {
  RRF_KV: KVNamespace;
  RRF_ADMIN_TOKEN?: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const id = params["id"] as string;

  if (request.method !== "DELETE") {
    return json({ error: "Method not allowed" }, 405);
  }

  const authHeader = request.headers.get("Authorization") ?? "";
  if (!env.RRF_ADMIN_TOKEN || authHeader !== `Bearer ${env.RRF_ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }

  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json({ error: "Orchestrator not found", id }, 404);
  }

  const record = JSON.parse(stored) as {
    id: string; status: string; fleet_rrns: string[]; revoked_at?: string;
  };

  if (record.status === "revoked") {
    return json({ error: "Orchestrator already revoked", id, revoked_at: record.revoked_at }, 409);
  }

  // Revoke
  record.status = "revoked";
  record.revoked_at = new Date().toISOString();
  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record), {
    expirationTtl: 90 * 24 * 3600,
  });

  // Add to global revocation list
  await addToRevocationList(env, id);

  return json({
    ok:         true,
    revoked:    id,
    revoked_at: record.revoked_at,
    message:    "Orchestrator revoked. Active sessions will be terminated within 60 seconds.",
  });
};

async function addToRevocationList(env: Env, orchestratorId: string): Promise<void> {
  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored
    ? JSON.parse(stored) as { revoked_orchestrators: string[]; revoked_jtis: string[] }
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
