/**
 * Test-only helpers for §27 spatial-eval endpoints. Mirrors
 * functions/v2/_lib/test-helpers.ts but for the simpler ML-DSA-only
 * Score JSON envelope (no Ed25519 hybrid wrapper).
 */

import { generateMlDsaKeypair, signMlDsa } from "rcan-ts";
import { payloadBytes } from "./score-canonical.js";

export interface ScoreTestKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function makeScoreTestKeypair(): ScoreTestKeypair {
  return generateMlDsaKeypair();
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** Sign a Score JSON with the robot's keypair and return the score with
 * `rcan_signature` populated. Mirrors `robot_md.spatial_eval.sign.sign_score`. */
export function signScore(
  score: Record<string, unknown>,
  kp: ScoreTestKeypair,
): Record<string, unknown> {
  const sig = signMlDsa(kp.privateKey, payloadBytes(score));
  return { ...score, rcan_signature: toBase64(sig) };
}

/** Build a robot record matching what §21 stores after `register`. */
export function makeRobotRecord(rrn: string, kp: ScoreTestKeypair): string {
  return JSON.stringify({
    rrn,
    name: "test",
    manufacturer: "test",
    model: "test",
    firmware_version: "1.0",
    rcan_version: "3.0",
    pq_signing_pub: toBase64(kp.publicKey),
    pq_kid: "testkid1",
    registered_at: "2026-04-30T00:00:00Z",
  });
}

/** Minimal valid Score JSON — populated for happy-path tests. */
export function makeScore(rrn: string, runId: string = "run-1"): Record<string, unknown> {
  return {
    spec_version: "1.0.0",
    rrn,
    run_id: runId,
    timestamp: "2026-04-30T18:00:00Z",
    tracks: {
      probe: {
        baseline_claude: { O1: { score: 0.87, n: 30, passed: 26 } },
        robot_declared: { O1: { score: 0.84, n: 30, passed: 25 } },
        delta_per_unit: { O1: -0.03 },
      },
      execute: { O1: { passed: 7, n: 10, evidence_sha256: "abc" } },
    },
    aggregate: { probe_baseline: 0.87, probe_declared: 0.84, execute: 0.7 },
    rcan_signature: null,
    rrf_signature: null,
    evidence_root: "sha256:e1",
  };
}

/** A v1.0.0 RRF keypair fixture for tests that need to verify RRF's
 * counter-signature. Produced fresh per test; do not use in production. */
export function makeRrfTestEnv(rrfPriv: Uint8Array): { RRF_SPATIAL_EVAL_PQ_PRIV: string } {
  return { RRF_SPATIAL_EVAL_PQ_PRIV: toBase64(rrfPriv) };
}
