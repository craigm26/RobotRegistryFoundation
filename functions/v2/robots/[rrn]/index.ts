/**
 * GET /v2/robots/:rrn    — Look up a registered whole robot by its RRN.
 * PATCH /v2/robots/:rrn  — Two modes, both bearer-auth:
 *   1. Body has pq_signing_pub → upgrade an unsigned record with a PQ key.
 *   2. Body has whitelisted fields only → update them in place
 *      (PATCHABLE_FIELDS below).
 * DELETE /v2/robots/:rrn — Unregister a robot. Bearer api_key required.
 */

import { isValidId } from "../../_lib/id.js";
import { verifyBody } from "rcan-ts";

export interface Env { RRF_KV: KVNamespace }

const PATCHABLE_FIELDS = ["rcan_version", "firmware_version", "ruri"] as const;
type PatchableField = typeof PATCHABLE_FIELDS[number];

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json" },
  });
}
function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status, headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const rrn = params["rrn"] as string;

  if (!isValidId(rrn, "RRN")) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Robot not found", rrn }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=60" },
  });
};

export const onRequestPatch: PagesFunction<Env> = async ({ request, env, params }) => {
  const rrn = params.rrn as string;
  const auth = request.headers.get("Authorization");
  const apiKey = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!apiKey) return err("Missing bearer token", 401);

  const raw = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!raw) return err("Not found", 404);
  const record = JSON.parse(raw);
  if (record.api_key !== apiKey) return err("Unauthorized", 403);

  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  if (body.pq_signing_pub !== undefined) {
    return handleSigningKeyUpgrade(record, body, env, rrn);
  }
  return handleFieldUpdate(record, body, env, rrn);
};

async function handleSigningKeyUpgrade(
  record: Record<string, unknown>,
  body: Record<string, unknown>,
  env: Env,
  rrn: string,
): Promise<Response> {
  if (record.pq_signing_pub) {
    return err("Record already signed; key rotation not supported in v0.9.1", 409);
  }
  const pq_signing_pub = body.pq_signing_pub as string | undefined;
  const pq_kid = body.pq_kid as string | undefined;
  const sig = body.sig as { ml_dsa?: string; ed25519?: string; ed25519_pub?: string } | undefined;
  if (!pq_signing_pub || !pq_kid
      || !sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Missing pq_signing_pub / pq_kid / sig", 400);
  }
  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pq_signing_pub), c => c.charCodeAt(0));
    verified = await verifyBody(
      { rrn, pq_signing_pub, pq_kid, sig },
      pqPub,
    );
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  record.pq_signing_pub = pq_signing_pub;
  record.pq_kid = pq_kid;
  record.updated_at = new Date().toISOString();
  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record));
  return ok(record);
}

async function handleFieldUpdate(
  record: Record<string, unknown>,
  body: Record<string, unknown>,
  env: Env,
  rrn: string,
): Promise<Response> {
  const keys = Object.keys(body);
  if (keys.length === 0) {
    return err("PATCH body must include at least one whitelisted field", 400);
  }
  const allowed = new Set<string>(PATCHABLE_FIELDS);
  for (const k of keys) {
    if (!allowed.has(k)) {
      return err(`Field '${k}' is not in the patchable whitelist (${PATCHABLE_FIELDS.join(", ")})`, 400);
    }
    if (typeof body[k] !== "string") {
      return err(`Field '${k}' must be a string`, 400);
    }
  }
  for (const k of keys) {
    record[k as PatchableField] = body[k];
  }
  record.updated_at = new Date().toISOString();
  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record));
  return ok(record);
}

export const onRequestDelete: PagesFunction<Env> = async ({ request, env, params }) => {
  const rrn = params.rrn as string;

  if (!isValidId(rrn, "RRN")) return err("Invalid RRN format", 400);

  const auth = request.headers.get("Authorization");
  const apiKey = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!apiKey) return err("Missing bearer token", 401);

  const raw = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!raw) return err("Not found", 404);
  const record = JSON.parse(raw);
  if (record.api_key !== apiKey) return err("Unauthorized", 403);

  await env.RRF_KV.delete(`robot:${rrn}`);
  return new Response(null, { status: 204 });
};
