/**
 * RRF counter-signature on a verified spatial-eval Score JSON.
 *
 * Loads the RRF spatial-eval ML-DSA-65 private key from
 * `env.RRF_SPATIAL_EVAL_PQ_PRIV` (Cloudflare Workers Secret, base64-encoded),
 * computes ML-DSA over the score's canonical payloadBytes (with both
 * signatures cleared — same form the robot signed), and inserts the
 * resulting base64 into `score.rrf_signature`.
 *
 * Returns the counter-signed score. Throws if the secret is missing or
 * malformed — the handler should turn that into a 500.
 */

import { signMlDsa } from "rcan-ts";
import { payloadBytes } from "./score-canonical.js";

export interface SignEnv {
  RRF_SPATIAL_EVAL_PQ_PRIV?: string;
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function counterSignScore(
  score: Record<string, unknown>,
  env: SignEnv,
): Record<string, unknown> {
  const privB64 = env.RRF_SPATIAL_EVAL_PQ_PRIV;
  if (!privB64) {
    throw new Error("RRF_SPATIAL_EVAL_PQ_PRIV secret is not set");
  }
  // Wrangler's `secret put` over piped stdin captures any trailing
  // newline into the stored value. atob() rejects that whitespace, so
  // trim before decoding. Defensive against any whitespace in the
  // base64 payload, regardless of how the secret was loaded.
  const priv = fromBase64(privB64.trim());
  const sig = signMlDsa(priv, payloadBytes(score));
  return { ...score, rrf_signature: toBase64(sig) };
}
