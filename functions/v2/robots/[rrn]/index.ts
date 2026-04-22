/**
 * GET /v2/robots/:rrn   — Look up a registered whole robot by its RRN.
 * PATCH /v2/robots/:rrn — Upgrade an unsigned record with a PQ signing key.
 */

import { isValidId } from "../../_lib/id.js";
import { canonicalJson, verifyHybrid } from "../../../_lib/verify.js";

export interface Env { RRF_KV: KVNamespace }

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

  // v0.9.1 scope: PATCH only upgrades null -> set.
  if (record.pq_signing_pub) {
    return err("Record already signed; key rotation not supported in v0.9.1", 409);
  }

  let body: {
    pq_signing_pub?: string; pq_kid?: string;
    sig?: { ml_dsa: string; ed25519: string; ed25519_pub: string };
  };
  try { body = await request.json() as typeof body; }
  catch { return err("Invalid JSON body", 400); }

  if (!body.pq_signing_pub || !body.pq_kid
      || !body.sig?.ml_dsa || !body.sig?.ed25519 || !body.sig?.ed25519_pub) {
    return err("Missing pq_signing_pub / pq_kid / sig", 400);
  }

  const message = canonicalJson({
    rrn, pq_signing_pub: body.pq_signing_pub, pq_kid: body.pq_kid,
  });
  const verified = await verifyHybrid(body.pq_signing_pub, body.sig, message);
  if (!verified) return err("Signature verification failed", 400);

  record.pq_signing_pub = body.pq_signing_pub;
  record.pq_kid = body.pq_kid;
  record.updated_at = new Date().toISOString();
  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record));
  return ok(record);
};
