/**
 * POST /v2/robots/:rrn/apikey-requests
 *
 * Issues (or re-issues) a bearer apikey for an existing RRN. The operator
 * authenticates via signature on the request body, verified against the
 * pq_signing_pub stored in the robot record at registration. No bearer
 * token is required — the apikey is what we don't have.
 *
 * Wire shape (rcan-apikey-request-v1): see CLI request-apikey docs.
 *
 * Replay protection: generated_at must fall inside a +/-10 min window from
 * server clock. No nonce store (would be inconsistent with sibling
 * compliance endpoints; cross-cutting upgrade if needed).
 *
 * KV: reads + writes robot:{rrn}. Updates api_key, api_key_issued_at,
 * api_key_reissue_count fields on the record.
 */

import { verifyComplianceBody } from "../../_lib/compliance-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const REQUEST_SCHEMA = "rcan-apikey-request-v1";
const RRN_RE = /^RRN-[0-9]{12}$/;
const FRESHNESS_WINDOW_MS = 10 * 60 * 1000;
const APIKEY_BYTES = 32;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  const rrn = params["rrn"] as string;

  if (!rrn || !RRN_RE.test(rrn)) return json({ error: "Invalid RRN format" }, 400);
  if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  if (body.schema !== REQUEST_SCHEMA) {
    return json({ error: `Expected schema ${REQUEST_SCHEMA}, got ${String(body.schema)}` }, 400);
  }
  if (body.rrn !== rrn) {
    return json({ error: "Body rrn does not match URL rrn" }, 400);
  }
  if (body.operation === "new") {
    return json({ error: "operation 'new' (multi-key) not supported in v1; use 'reissue'" }, 400);
  }
  if (body.operation !== "reissue") {
    return json({ error: `operation must be 'reissue', got ${String(body.operation)}` }, 400);
  }
  if (typeof body.nonce !== "string" || body.nonce.length === 0) {
    return json({ error: "nonce is required" }, 400);
  }
  const generatedAt = body.generated_at;
  if (typeof generatedAt !== "string") {
    return json({ error: "generated_at is required" }, 400);
  }
  const ts = Date.parse(generatedAt);
  if (Number.isNaN(ts)) {
    return json({ error: "generated_at is not a valid ISO 8601 timestamp" }, 400);
  }
  const skew = Math.abs(Date.now() - ts);
  if (skew > FRESHNESS_WINDOW_MS) {
    return json({ error: "generated_at outside +/-10 min freshness window" }, 400);
  }

  const verified = await verifyComplianceBody(body, env, `robot:${rrn}`);
  if (!verified.ok) return json({ error: verified.error }, verified.status);

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) return json({ error: "Robot record vanished mid-request" }, 500);

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return json({ error: "Corrupt robot record" }, 500);
  }

  const priorKey = typeof record.api_key === "string" && (record.api_key as string).length > 0;
  const newKey = mintApiKey();
  const issuedAt = new Date().toISOString();
  const priorCount = typeof record.api_key_reissue_count === "number"
    ? (record.api_key_reissue_count as number)
    : 0;
  const newCount = priorCount + 1;

  record.api_key = newKey;
  record.api_key_issued_at = issuedAt;
  record.api_key_reissue_count = newCount;

  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10, // 10 years, same as register.ts
  });

  return json({
    rrn,
    api_key: newKey,
    issued_at: issuedAt,
    operation: "reissue",
    prior_key_exists: priorKey,
    api_key_reissue_count: newCount,
  }, 201);
};

function mintApiKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(APIKEY_BYTES));
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `rrf_${b64}`;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
