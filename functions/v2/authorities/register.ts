/**
 * POST /v2/authorities/register
 * RCAN 3.0 §2.2 — Register a Robot Authority Number (RAN).
 *
 * RAN identifies non-robot, non-component, non-model entities that need durable
 * hybrid keys: aggregators, release-signing tools, attestation services,
 * policy authorities.
 *
 * Body: { organization, display_name, purpose, signing_pub, pq_signing_pub,
 *         pq_kid, signing_alg, sig: { ml_dsa, ed25519, ed25519_pub } }
 *
 * Returns: { ran, status, registered_at }
 */

import type { AuthorityRecord, AuthorityPurpose } from "../_lib/types.js";
import { verifyBody } from "rcan-ts";

export interface Env {
  RRF_KV: KVNamespace;
}

const ALLOWED_PURPOSES: AuthorityPurpose[] = [
  "compatibility-matrix-aggregate",
  "release-signing",
  "attestation",
  "policy",
  "other",
];

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env> = async ({ env, request }) => {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  // Required field check
  const required = [
    "organization",
    "display_name",
    "purpose",
    "signing_pub",
    "pq_signing_pub",
    "pq_kid",
    "signing_alg",
    "sig",
  ] as const;
  for (const k of required) {
    if (body[k] === undefined || body[k] === null) {
      return json({ error: `${k} required` }, 400);
    }
  }

  // signing_alg must be exactly ["Ed25519", "ML-DSA-65"]
  if (
    !Array.isArray(body.signing_alg) ||
    body.signing_alg[0] !== "Ed25519" ||
    body.signing_alg[1] !== "ML-DSA-65"
  ) {
    return json({ error: 'signing_alg must be ["Ed25519", "ML-DSA-65"]' }, 400);
  }

  // Validate purpose
  if (!ALLOWED_PURPOSES.includes(body.purpose as AuthorityPurpose)) {
    return json(
      { error: `purpose must be one of ${ALLOWED_PURPOSES.join("|")}` },
      400,
    );
  }

  // sig fields must all be present
  const sig = body.sig as Record<string, unknown> | undefined;
  if (!sig || !sig.ml_dsa || !sig.ed25519 || !sig.ed25519_pub) {
    return json({ error: "sig.ml_dsa, sig.ed25519, sig.ed25519_pub all required" }, 400);
  }

  // Validate that sig.ed25519_pub matches signing_pub (proves possession)
  if (sig.ed25519_pub !== body.signing_pub) {
    return json(
      { error: "ed25519_pub in sig must match signing_pub field" },
      400,
    );
  }

  // §2.2 hybrid signature verification via rcan-ts verifyBody
  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(body.pq_signing_pub as string), (c) =>
      c.charCodeAt(0),
    );
    verified = await verifyBody(body as any, pqPub);
  } catch {
    /* verified stays false */
  }
  if (!verified) {
    return json({ error: "Signature verification failed (§2.2)" }, 400);
  }

  // pq_kid uniqueness within RAN namespace
  const list = await env.RRF_KV.list({ prefix: "authority:" });
  for (const k of list.keys) {
    // Skip counter key if it matches the prefix (it won't, but be safe)
    if (!k.name.startsWith("authority:RAN-")) continue;
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    const rec = JSON.parse(raw) as AuthorityRecord;
    if (rec.pq_kid === body.pq_kid) {
      return json({ error: "pq_kid duplicate within RAN namespace" }, 409);
    }
  }

  // Sequential RAN assignment (counter:ran mirrors counter:rrn, counter:rcn, etc.)
  const counterStr = await env.RRF_KV.get("counter:ran", "text");
  const next = (counterStr ? parseInt(counterStr, 10) : 0) + 1;
  const ran = `RAN-${String(next).padStart(12, "0")}` as `RAN-${string}`;

  const record: AuthorityRecord = {
    ran,
    organization: body.organization as string,
    display_name: body.display_name as string,
    purpose: body.purpose as AuthorityPurpose,
    signing_pub: body.signing_pub as string,
    pq_signing_pub: body.pq_signing_pub as string,
    pq_kid: body.pq_kid as string,
    signing_alg: ["Ed25519", "ML-DSA-65"],
    registered_at: new Date().toISOString(),
    status: "active",
  };

  await env.RRF_KV.put(`authority:${ran}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });
  await env.RRF_KV.put("counter:ran", String(next));

  return json({ ran, status: "active", registered_at: record.registered_at }, 201);
};
