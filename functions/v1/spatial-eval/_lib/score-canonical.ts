/**
 * Canonical bytes for ML-DSA signing/verification of a spatial-eval Score JSON.
 *
 * Both `rcan_signature` (robot's self-attestation) and `rrf_signature`
 * (RRF's counter-signature) are cleared before serialization. The robot
 * signs the score with rrf_signature=null at sign time; RRF signs the
 * exact same canonical bytes (still both cleared) at counter-sign time.
 * That symmetry means a registry-attested score still self-verifies under
 * the robot's keypair without modification.
 *
 * Cross-checked byte-for-byte against Python's
 * `robot_md.spatial_eval.sign.payload_bytes` — both use rcan-ts/rcan-py
 * canonicalJson semantics: recursive sort_keys + no whitespace.
 */

import { canonicalJson } from "rcan-ts";

export function payloadBytes(score: Record<string, unknown>): Uint8Array {
  const cleared: Record<string, unknown> = {
    ...score,
    rcan_signature: null,
    rrf_signature: null,
  };
  const out = canonicalJson(cleared);
  if (typeof out === "string") return new TextEncoder().encode(out);
  return out as Uint8Array;
}
