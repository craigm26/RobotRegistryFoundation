/**
 * Verify a cert-intake POST body's rig + witness signatures.
 *
 * Flow:
 *   1. Validate sig blobs (kid + sig strings present).
 *   2. Validate ran_at is finite number; convert to ISO string for window-check.
 *   3. Resolve rig_signature.kid via cert-rig-resolve.
 *   4. Resolve witness_signature.kid via cert-witness-resolve.
 *   5. Cross-check witness.rig_id === rig.rig_id (scope check).
 *   6. Reconstruct canonical_json(body - {rig_signature, witness_signature}).
 *   7. Web Crypto Ed25519 SPKI direct verify of rig sig.
 *   8. Web Crypto Ed25519 SPKI direct verify of witness sig.
 *   9. Return {ok, rig, witness} or structured error.
 *
 * Web Crypto Ed25519 SPKI direct verify pattern: same as Plan 4 deviation B6
 * (functions/v2/_lib/jwt-verify.ts). Bypasses rcan-ts.verifyBody which assumes
 * pq-injected fields.
 */

import { canonicalJson } from "rcan-ts";
import type { RigKidMapping, WitnessKidMapping } from "./types.js";
import { resolveRigKid } from "./cert-rig-resolve.js";
import { resolveWitnessKid } from "./cert-witness-resolve.js";

export type VerifyHilOk = { ok: true; rig: RigKidMapping; witness: WitnessKidMapping };
export type VerifyHilErr = { ok: false; status: number; error: string };
export type VerifyHilResult = VerifyHilOk | VerifyHilErr;

const RAW_ED25519_PUB_LEN = 32;
const SPKI_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function b64decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function rawPubToSpki(rawPub: Uint8Array): Uint8Array {
  if (rawPub.length !== RAW_ED25519_PUB_LEN) {
    throw new Error(`Ed25519 raw pubkey must be ${RAW_ED25519_PUB_LEN} bytes; got ${rawPub.length}`);
  }
  const spki = new Uint8Array(SPKI_ED25519_PREFIX.length + RAW_ED25519_PUB_LEN);
  spki.set(SPKI_ED25519_PREFIX, 0);
  spki.set(rawPub, SPKI_ED25519_PREFIX.length);
  return spki;
}

async function verifyEd25519(pubB64: string, msg: Uint8Array, sigB64: string): Promise<boolean> {
  const rawPub = b64decode(pubB64);
  const spki = rawPubToSpki(rawPub);
  const key = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const sig = b64decode(sigB64);
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    sig,
    msg,
  );
}

export async function verifyHilEvidence(
  env: { RRF_KV: KVNamespace },
  payload: Record<string, unknown>,
): Promise<VerifyHilResult> {
  const rigSig = payload["rig_signature"];
  const witnessSig = payload["witness_signature"];
  if (!rigSig || typeof rigSig !== "object" || !witnessSig || typeof witnessSig !== "object") {
    return { ok: false, status: 400, error: "rig_signature and witness_signature both required" };
  }
  const rigKid = (rigSig as { kid?: unknown }).kid;
  const rigSigB64 = (rigSig as { sig?: unknown }).sig;
  const witnessKid = (witnessSig as { kid?: unknown }).kid;
  const witnessSigB64 = (witnessSig as { sig?: unknown }).sig;
  if (typeof rigKid !== "string" || typeof rigSigB64 !== "string" ||
      typeof witnessKid !== "string" || typeof witnessSigB64 !== "string") {
    return { ok: false, status: 400, error: "rig_signature and witness_signature must each have string kid + sig" };
  }

  const ranAt = payload["ran_at"];
  if (typeof ranAt !== "number" || !Number.isFinite(ranAt)) {
    return { ok: false, status: 400, error: "ran_at missing or not a finite number" };
  }
  const ranAtIso = new Date(ranAt * 1000).toISOString();

  const rig = await resolveRigKid(env, rigKid, ranAtIso);
  if (!rig) {
    return { ok: false, status: 403, error: `rig kid ${rigKid} not registered or outside validity window for ran_at ${ranAtIso}` };
  }
  const witness = await resolveWitnessKid(env, witnessKid, ranAtIso);
  if (!witness) {
    return { ok: false, status: 403, error: `witness kid ${witnessKid} not registered or outside validity window for ran_at ${ranAtIso}` };
  }
  if (witness.rig_id !== rig.rig_id) {
    return { ok: false, status: 403, error: `witness ${witnessKid} is paired with rig ${witness.rig_id}, not ${rig.rig_id} (scope mismatch)` };
  }

  const core: Record<string, unknown> = { ...payload };
  delete core["rig_signature"];
  delete core["witness_signature"];
  const msg = canonicalJson(core);

  const rigOk = await verifyEd25519(rig.signing_pub, msg, rigSigB64);
  if (!rigOk) {
    return { ok: false, status: 401, error: `rig signature did not verify against registered pub for kid ${rigKid}` };
  }
  const witnessOk = await verifyEd25519(witness.signing_pub, msg, witnessSigB64);
  if (!witnessOk) {
    return { ok: false, status: 401, error: `witness signature did not verify against registered pub for kid ${witnessKid}` };
  }

  return { ok: true, rig, witness };
}
