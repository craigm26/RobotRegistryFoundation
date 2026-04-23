/**
 * POST /v2/models/register
 * RCAN 3.0 §21 + §2.2 — Register an AI model, receive an RMN.
 *
 * v1.9.0: unsigned registration is rejected per RCAN 3.0 §2.2. Body MUST
 * include pq_signing_pub, pq_kid, and sig{ml_dsa, ed25519, ed25519_pub}
 * over the canonical signed-fields block (all provided fields except sig).
 *
 * Body: { name, version, model_family, architecture?, parameter_count_b?,
 *         quantization?, license?, provider?, provider_model_id?,
 *         repo_url?, rcan_compatible?, compatible_harness_ids?, owner_uid?,
 *         pq_signing_pub, pq_kid, sig }
 *
 * Returns: { rmn, registered_at, record_url }
 */

import { nextId } from "../_lib/id.js";
import type { ModelRecord, ModelFamily, ModelQuantization } from "../_lib/types.js";
import { verifyBody } from "rcan-ts";

export interface Env { RRF_KV: KVNamespace }

const VALID_FAMILIES: ModelFamily[] = [
  "vision", "language", "multimodal", "vla", "embedding",
  "reward", "world_model", "diffusion", "other",
];

const VALID_QUANT: ModelQuantization[] = [
  "fp32", "fp16", "bf16", "int8", "int4", "gguf", "bnb4", "other",
];

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const { name, version, model_family } = body as Record<string, string>;

  if (!name || !version || !model_family) {
    return err("Required: name, version, model_family", 400);
  }

  if (!VALID_FAMILIES.includes(model_family as ModelFamily)) {
    return err(`Invalid model_family. Must be one of: ${VALID_FAMILIES.join(", ")}`, 400);
  }

  const quant = body.quantization as string | undefined;
  if (quant && !VALID_QUANT.includes(quant as ModelQuantization)) {
    return err(`Invalid quantization. Must be one of: ${VALID_QUANT.join(", ")}`, 400);
  }

  // v1.9.0: RCAN 3.0 §2.2 — signatures mandatory, unsigned rejected.
  const { pq_signing_pub, pq_kid, sig } = body as Record<string, any>;
  if (!pq_signing_pub || !pq_kid
      || !sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned registration not permitted (RCAN 3.0 §2.2)", 400);
  }

  const signedFields: Record<string, unknown> = {
    name, version, model_family,
    pq_signing_pub, pq_kid,
  };
  if (body.architecture)          signedFields.architecture          = body.architecture;
  if (body.parameter_count_b !== undefined) signedFields.parameter_count_b = body.parameter_count_b;
  if (body.quantization)          signedFields.quantization          = body.quantization;
  if (body.license)               signedFields.license               = body.license;
  if (body.provider)              signedFields.provider              = body.provider;
  if (body.provider_model_id)     signedFields.provider_model_id     = body.provider_model_id;
  if (body.repo_url)              signedFields.repo_url              = body.repo_url;
  if (body.rcan_compatible !== undefined) signedFields.rcan_compatible = body.rcan_compatible;
  if (body.compatible_harness_ids) signedFields.compatible_harness_ids = body.compatible_harness_ids;
  if (body.owner_uid)             signedFields.owner_uid             = body.owner_uid;

  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pq_signing_pub), c => c.charCodeAt(0));
    verified = await verifyBody({ ...signedFields, sig }, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  const rmn = await nextId(env.RRF_KV, "RMN");

  const record: ModelRecord = {
    rmn,
    name,
    version,
    model_family:       model_family as ModelFamily,
    architecture:       body.architecture as string | undefined,
    parameter_count_b:  typeof body.parameter_count_b === "number"
                          ? body.parameter_count_b : undefined,
    quantization:       quant as ModelQuantization | undefined,
    license:            body.license as string | undefined,
    provider:           body.provider as string | undefined,
    provider_model_id:  body.provider_model_id as string | undefined,
    repo_url:           body.repo_url as string | undefined,
    rcan_compatible:    body.rcan_compatible !== false,
    compatible_harness_ids: body.compatible_harness_ids as string[] | undefined,
    owner_uid:          body.owner_uid as string | undefined,
    pq_signing_pub,
    pq_kid,
    registered_at:      new Date().toISOString(),
  };

  await env.RRF_KV.put(`model:${rmn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });

  return ok({ rmn, registered_at: record.registered_at,
    record_url: `https://robotregistryfoundation.org/v2/models/${rmn}` }, 201);
};

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const list = await env.RRF_KV.list({ prefix: "model:", limit: 100 });
  const models = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.RRF_KV.get(k.name, "text");
      return val ? JSON.parse(val) : null;
    })
  );
  return ok({ models: models.filter(Boolean), total: models.length });
};

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { "Content-Type": "application/json" } });
}
