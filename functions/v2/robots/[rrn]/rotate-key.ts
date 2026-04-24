import { isValidId } from "../../_lib/id.js";
import { verifyBody } from "rcan-ts";
import { isRevoked } from "../../_lib/revocation.js";

export interface Env { RRF_KV: KVNamespace }

/**
 * POST /v2/robots/:rrn/rotate-key
 *
 * Co-signed rotation: the request body carries TWO independently-signed envelopes
 * (`by_old_key`, `by_new_key`), each a self-contained verifyBody-compatible doc
 * over the canonical `{rrn, action:"rotate", new_pq_signing_pub, new_pq_kid}`.
 *
 * Known limitation: Cloudflare Workers KV has no CAS primitive in this project's
 * setup. Two concurrent rotate requests can both verify and both write — last-write
 * wins. Rotations are rare, user-initiated events; the `rotations[]` audit log will
 * reflect a collision post-facto. Optimistic versioning is deferred.
 */

function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status, headers: { "Content-Type": "application/json" },
  });
}

function agrees(a: any, b: any, keys: string[]): boolean {
  for (const k of keys) if (a?.[k] !== b?.[k]) return false;
  return true;
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env, params }) => {
  const rrn = params.rrn as string;
  if (!isValidId(rrn, "RRN")) return err("Invalid RRN format", 400);

  let body: any;
  try { body = await request.json(); }
  catch { return err("Invalid JSON body", 400); }

  const byOld = body?.by_old_key;
  const byNew = body?.by_new_key;
  if (!byOld || typeof byOld !== "object" || !byNew || typeof byNew !== "object") {
    return err("Missing by_old_key or by_new_key envelopes", 400);
  }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) return err("Not found", 404);

  if (await isRevoked(env, rrn)) return err("Record is revoked", 403);

  const record = JSON.parse(stored);
  const currentPubB64 = record.pq_signing_pub;
  if (typeof currentPubB64 !== "string") return err("Record has no registered key", 400);

  // Agreement: both envelopes declare the same canonical rotation fields,
  // and that canonical binds to the URL RRN + action "rotate".
  if (!agrees(byOld, byNew, ["rrn", "action", "new_pq_signing_pub", "new_pq_kid"])) {
    return err("Envelopes disagree on canonical rotation fields", 400);
  }
  if (byOld.rrn !== rrn) return err("Envelope rrn does not match URL", 400);
  if (byOld.action !== "rotate") return err("Envelope action must be rotate", 400);

  const newPubB64 = byOld.new_pq_signing_pub;
  const newKid = byOld.new_pq_kid;
  if (typeof newPubB64 !== "string" || typeof newKid !== "string") {
    return err("new_pq_signing_pub and new_pq_kid must be strings", 400);
  }
  if (newPubB64 === currentPubB64) return err("Rotation requires a different key", 400);

  // Consistency: the new envelope must be signed BY the declared new key
  // (i.e. its inner pq_signing_pub field equals new_pq_signing_pub).
  if (byNew.pq_signing_pub !== newPubB64) {
    return err("by_new_key.pq_signing_pub must match declared new_pq_signing_pub", 400);
  }

  // Verify both envelopes.
  let oldOk = false, newOk = false;
  try {
    const oldPub = Uint8Array.from(atob(currentPubB64), c => c.charCodeAt(0));
    oldOk = await verifyBody(byOld, oldPub);
  } catch { /* oldOk stays false */ }
  if (!oldOk) return err("by_old_key signature verification failed", 401);

  try {
    const newPub = Uint8Array.from(atob(newPubB64), c => c.charCodeAt(0));
    newOk = await verifyBody(byNew, newPub);
  } catch { /* newOk stays false */ }
  if (!newOk) return err("by_new_key signature verification failed", 401);

  // Apply rotation.
  const now = new Date().toISOString();
  record.rotations = Array.isArray(record.rotations) ? record.rotations : [];
  record.rotations.push({ rotated_at: now, old_pq_kid: record.pq_kid, new_pq_kid: newKid });
  record.pq_signing_pub = newPubB64;
  record.pq_kid = newKid;
  record.updated_at = now;
  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record));
  return new Response(JSON.stringify(record), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
};
