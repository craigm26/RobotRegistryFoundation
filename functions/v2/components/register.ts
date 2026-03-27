/**
 * POST /v2/components/register
 * RCAN v2.2 §21 — Register a hardware component and receive an RCN.
 *
 * Body: { parent_rrn, type, model, manufacturer, firmware_version?,
 *         serial_number?, capabilities?, specs? }
 *
 * Returns: { rcn, registered_at, record_url }
 */

import { nextId, isValidId } from "../_lib/id.js";
import type { ComponentRecord, ComponentType } from "../_lib/types.js";

export interface Env { RRF_KV: KVNamespace }

const VALID_TYPES: ComponentType[] = [
  "cpu", "npu", "gpu", "camera", "lidar", "imu",
  "actuator", "sensor", "battery", "communication", "other",
];

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const { parent_rrn, type, model, manufacturer } = body as Record<string, string>;

  if (!parent_rrn || !type || !model || !manufacturer) {
    return err("Required: parent_rrn, type, model, manufacturer", 400);
  }

  if (!isValidId(parent_rrn, "RRN")) {
    return err(`Invalid parent_rrn format: ${parent_rrn}`, 400);
  }

  if (!VALID_TYPES.includes(type as ComponentType)) {
    return err(`Invalid type. Must be one of: ${VALID_TYPES.join(", ")}`, 400);
  }

  // Verify parent robot exists
  const parentRobot = await env.RRF_KV.get(`robot:${parent_rrn}`, "text");
  if (!parentRobot) {
    return err(`Parent robot not found: ${parent_rrn}`, 404);
  }

  const rcn = await nextId(env.RRF_KV, "RCN");

  const record: ComponentRecord = {
    rcn,
    parent_rrn,
    type:              type as ComponentType,
    model,
    manufacturer,
    firmware_version:  body.firmware_version as string | undefined,
    serial_number:     body.serial_number as string | undefined,
    capabilities:      body.capabilities as string[] | undefined,
    specs:             body.specs as Record<string, unknown> | undefined,
    registered_at:     new Date().toISOString(),
  };

  await env.RRF_KV.put(`component:${rcn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });

  // Link component back to parent robot
  const parentRecord = JSON.parse(parentRobot);
  parentRecord.components = [...(parentRecord.components ?? []), rcn];
  parentRecord.updated_at = new Date().toISOString();
  await env.RRF_KV.put(`robot:${parent_rrn}`, JSON.stringify(parentRecord), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });

  return ok({ rcn, parent_rrn, registered_at: record.registered_at,
    record_url: `https://robot-registry-foundation.pages.dev/v2/components/${rcn}` }, 201);
};

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const list = await env.RRF_KV.list({ prefix: "component:", limit: 100 });
  const components = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.RRF_KV.get(k.name, "text");
      return val ? JSON.parse(val) : null;
    })
  );
  return ok({ components: components.filter(Boolean), total: components.length });
};

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { "Content-Type": "application/json" } });
}
