import { isValidId } from "../../_lib/id.js";
import { verifyBody } from "rcan-ts";
import { isRevoked, markRevoked } from "../../_lib/revocation.js";

export interface Env { RRF_KV: KVNamespace }

function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status, headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env, params }) => {
  const rrn = params.rrn as string;
  if (!isValidId(rrn, "RRN")) return err("Invalid RRN format", 400);

  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) return err("Not found", 404);
  const record = JSON.parse(stored);

  const pqPubB64 = record.pq_signing_pub;
  if (typeof pqPubB64 !== "string") return err("Record has no registered key", 400);

  // Verify signature BEFORE checking action binding, so tampering is caught as 401 not 400
  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pqPubB64), c => c.charCodeAt(0));
    verified = await verifyBody(body, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 401);

  if (body.rrn !== rrn || body.action !== "revoke") {
    return err("Body must bind rrn and action:revoke", 400);
  }

  if (await isRevoked(env, rrn)) return err("Already revoked", 409);

  const reason = typeof body.reason === "string" ? body.reason : "unspecified";
  await markRevoked(env, rrn, reason);
  return new Response(null, { status: 204 });
};
