/**
 * POST /v2/robots/register
 * RCAN v2.2 §21 — Register a whole robot and receive an RRN.
 *
 * Body (RobotRecord minus rrn/registered_at):
 *   name, manufacturer, model, firmware_version, rcan_version
 *   pq_signing_pub? (ML-DSA-65 base64), pq_kid?, ruri?, owner_uid?
 *
 * Returns: { rrn, registered_at, record_url }
 */

import { nextId, isValidId } from "../_lib/id.js";
import type { RobotRecord } from "../_lib/types.js";
import { verifyBody } from "rcan-ts";

export interface Env { RRF_KV: KVNamespace }

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const { name, manufacturer, model, firmware_version, rcan_version } = body as Record<string, string>;
  if (!name || !manufacturer || !model || !firmware_version || !rcan_version) {
    return err("Required: name, manufacturer, model, firmware_version, rcan_version", 400);
  }

  // v0.9.1: RCAN 3.0 §2.2 — signatures are mandatory, unsigned is rejected.
  const { pq_signing_pub, pq_kid, ruri, owner_uid, sig } = body as Record<string, any>;
  if (!pq_signing_pub || !pq_kid
      || !sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned registration not permitted (RCAN 3.0 §2.2)", 400);
  }

  // v1.10.0: operator-declared §21 sibling IDs (RCN/RMN/RHN).
  const rcn_ids = body.rcn_ids as string[] | undefined;
  const rmn     = body.rmn     as string | undefined;
  const rhn_ids = body.rhn_ids as string[] | undefined;

  const signedFields: Record<string, unknown> = {
    name, manufacturer, model, firmware_version, rcan_version,
    pq_signing_pub, pq_kid,
  };
  if (ruri)     signedFields.ruri     = ruri;
  if (owner_uid) signedFields.owner_uid = owner_uid;
  if (rcn_ids)  signedFields.rcn_ids  = rcn_ids;
  if (rmn)      signedFields.rmn      = rmn;
  if (rhn_ids)  signedFields.rhn_ids  = rhn_ids;

  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pq_signing_pub), c => c.charCodeAt(0));
    verified = await verifyBody({ ...signedFields, sig }, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  const rrn = await nextId(env.RRF_KV, "RRN");

  const record: RobotRecord = {
    rrn,
    name,
    manufacturer,
    model,
    firmware_version,
    rcan_version,
    pq_signing_pub,
    pq_kid,
    ruri,
    owner_uid,
    rcn_ids,
    rmn,
    rhn_ids,
    loa_enforcement: body.loa_enforcement !== false,  // default true
    registered_at:   new Date().toISOString(),
  };

  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10, // 10 years
  });

  return ok({ rrn, registered_at: record.registered_at,
    record_url: `https://robotregistryfoundation.org/v2/robots/${rrn}` }, 201);
};

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  // GET /v2/robots/register — list recently registered robots
  const list = await env.RRF_KV.list({ prefix: "robot:", limit: 100 });
  const robots = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.RRF_KV.get(k.name, "text");
      return val ? JSON.parse(val) : null;
    })
  );
  return ok({ robots: robots.filter(Boolean), total: robots.length });
};

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { "Content-Type": "application/json" } });
}
