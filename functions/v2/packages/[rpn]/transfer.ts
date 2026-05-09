/**
 * POST /v2/packages/[rpn]/transfer — owner-only key rotation.
 *
 * The CURRENT owner key signs the body. New publisher key replaces the
 * record's publisher block. Future writes (versions, revoke, transfer)
 * verify against the new key.
 *
 * Body: RCAN-signed { new_pq_signing_pub, new_pq_kid, new_ed25519_pub, sig }
 */

import { isValidId } from "../../_lib/id.js";
import type { PackageRecord } from "../../_lib/types.js";
import { verifyBody } from "rcan-ts";

export interface Env { RRF_KV: KVNamespace }

function err(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env, "rpn"> = async ({ request, env, params }) => {
  const rpn = params.rpn as string;
  if (!isValidId(rpn, "RPN")) return err("Malformed RPN", 400);

  const raw = await env.RRF_KV.get(`package:${rpn}`);
  if (!raw) return err(`No package with RPN ${rpn}`, 404);
  const record = JSON.parse(raw) as PackageRecord;

  if (record.status === "revoked") return err("Package is revoked; cannot transfer", 400);

  let body: Record<string, unknown>;
  try { body = (await request.json()) as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  // Signature presence check
  const sig = body.sig as Record<string, unknown> | undefined;
  if (!sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned request not permitted", 400);
  }

  const requiredFields = ["new_pq_signing_pub", "new_pq_kid", "new_ed25519_pub"] as const;
  for (const k of requiredFields) {
    if (!body[k]) return err(`Required: ${k}`, 400);
  }

  // Verify against the CURRENT stored publisher key.
  // Body is passed as-is so canonicalisation matches what was signed.
  // Security: pqPub comes from the stored record, not the request body.
  const pqPub = Uint8Array.from(atob(record.publisher.pq_signing_pub), c => c.charCodeAt(0));
  let verified = false;
  try {
    verified = await verifyBody(body, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  // Rotate the publisher block to the new key.
  record.publisher = {
    pq_signing_pub: body.new_pq_signing_pub as string,
    pq_kid: body.new_pq_kid as string,
    ed25519_pub: body.new_ed25519_pub as string,
  };
  await env.RRF_KV.put(`package:${rpn}`, JSON.stringify(record));

  return new Response(JSON.stringify(record), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
