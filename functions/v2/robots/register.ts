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

export interface Env { RRF_KV: KVNamespace }

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const { name, manufacturer, model, firmware_version, rcan_version } = body as Record<string, string>;
  if (!name || !manufacturer || !model || !firmware_version || !rcan_version) {
    return err("Required: name, manufacturer, model, firmware_version, rcan_version", 400);
  }

  const rrn = await nextId(env.RRF_KV, "RRN");

  const record: RobotRecord = {
    rrn,
    name,
    manufacturer,
    model,
    firmware_version,
    rcan_version,
    pq_signing_pub:  body.pq_signing_pub as string | undefined,
    pq_kid:          body.pq_kid as string | undefined,
    ruri:            body.ruri as string | undefined,
    owner_uid:       body.owner_uid as string | undefined,
    loa_enforcement: body.loa_enforcement !== false,  // default true
    registered_at:   new Date().toISOString(),
  };

  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10, // 10 years
  });

  return ok({ rrn, registered_at: record.registered_at,
    record_url: `https://robot-registry-foundation.pages.dev/v2/robots/${rrn}` }, 201);
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
