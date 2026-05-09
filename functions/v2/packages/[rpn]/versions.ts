/**
 * POST /v2/packages/[rpn]/versions — owner-only append a new version.
 *
 * Body: RCAN-signed { version, artifact_hash?, sig } using the package's
 * registered publisher key.
 *
 * Returns 200 + updated record, or 404/409/400 as appropriate.
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

  if (record.status === "revoked") return err("Package is revoked; cannot append version", 400);

  let body: Record<string, unknown>;
  try { body = (await request.json()) as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  // Signature presence check
  const sig = body.sig as Record<string, unknown> | undefined;
  if (!sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned request not permitted", 400);
  }

  if (!body.version) return err("Required: version", 400);

  // Verify against the stored publisher key (NOT any key in the body).
  // Pass the body as-is so canonicalisation sees exactly what was signed.
  // Security: the second arg (pqPub) comes from the stored record, so an
  // attacker cannot substitute their own public key.
  const pqPub = Uint8Array.from(atob(record.publisher.pq_signing_pub), c => c.charCodeAt(0));
  let verified = false;
  try {
    verified = await verifyBody(body, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  const version = body.version as string;
  if (record.versions.some((v) => v.version === version)) {
    return err(`Version ${version} already exists`, 409);
  }

  record.versions.push({
    version,
    released_at: new Date().toISOString(),
    artifact_hash: body.artifact_hash as string | undefined,
  });
  await env.RRF_KV.put(`package:${rpn}`, JSON.stringify(record));

  return new Response(JSON.stringify(record), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
