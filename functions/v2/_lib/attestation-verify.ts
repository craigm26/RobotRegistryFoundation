/**
 * Signed-attestation + RURI verifier for the manufacturer_verified tier.
 *
 * Given an attestation body (produced by the manufacturer via signBody over
 * {rrn, manufacturer, model, timestamp_iso}) and the robot's registered
 * pq_signing_pub, this verifier:
 *   1. Cross-checks rrn/model against the robot's registered record.
 *   2. Bounds the timestamp (1-year max age, 60s future skew cap).
 *   3. Verifies the ML-DSA+Ed25519 hybrid signature.
 *   4. Fetches ${ruri}/.well-known/rcan-manifest.json and confirms its rrn.
 *
 * Fail-never: every path returns VerifyAttestationOutcome.
 *
 * Evidence: SHA-256 hex digest of the canonical attestation core + the RURI
 * manifest URL that matched. Intended for audit storage in identity_binding.
 */

import { verifyBody } from "rcan-ts";

const ONE_YEAR_MS = 365 * 24 * 3600 * 1000;
const FUTURE_SKEW_MS = 60 * 1000;
const MAX_MANIFEST_BYTES = 65536;

export interface VerifyAttestationInput {
  attestation: Record<string, unknown>;
  ruri: string;
  pqPubB64: string;
  expectedRrn: string;
  expectedModel: string;
  fetchFn?: typeof fetch;
  nowMs?: number;
}

export interface VerifyAttestationOk {
  ok: true;
  evidence: { attestation_digest: string; ruri_matched: string };
}
export interface VerifyAttestationErr { ok: false; error: string }
export type VerifyAttestationOutcome = VerifyAttestationOk | VerifyAttestationErr;

async function digestHex(bytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function canonicalCoreBytes(a: Record<string, unknown>): Uint8Array {
  // Stable ordering, fixed field set — do not include sig/pq_signing_pub.
  const core = {
    rrn: a.rrn,
    manufacturer: a.manufacturer,
    model: a.model,
    timestamp_iso: a.timestamp_iso,
    pq_kid: a.pq_kid,
  };
  return new TextEncoder().encode(JSON.stringify(core));
}

export async function verifyAttestation(
  input: VerifyAttestationInput,
): Promise<VerifyAttestationOutcome> {
  const { attestation, ruri, pqPubB64, expectedRrn, expectedModel } = input;
  const fetchFn = input.fetchFn ?? fetch;
  const now = input.nowMs ?? Date.now();

  if (attestation.rrn !== expectedRrn) return { ok: false, error: "attestation rrn mismatch" };
  if (attestation.model !== expectedModel) return { ok: false, error: "attestation model mismatch" };

  const tsRaw = attestation.timestamp_iso;
  if (typeof tsRaw !== "string") return { ok: false, error: "invalid timestamp_iso" };
  const issued = Date.parse(tsRaw);
  if (!Number.isFinite(issued)) return { ok: false, error: "invalid timestamp_iso" };
  if (now - issued > ONE_YEAR_MS) return { ok: false, error: "attestation expired (> 1 year stale)" };
  if (issued - now > FUTURE_SKEW_MS) return { ok: false, error: "attestation timestamp in the future (skew exceeds 60s)" };

  let sigOk = false;
  try {
    const pqPub = Uint8Array.from(atob(pqPubB64), (c) => c.charCodeAt(0));
    sigOk = await verifyBody(attestation, pqPub);
  } catch { /* sigOk stays false */ }
  if (!sigOk) return { ok: false, error: "attestation sig verification failed" };

  const manifestUrl = `${ruri.replace(/\/+$/, "")}/.well-known/rcan-manifest.json`;
  let manifestBody: string;
  try {
    const res = await fetchFn(manifestUrl, { headers: { "Accept": "application/json" } });
    if (!res.ok) return { ok: false, error: `RURI manifest returned ${res.status}` };
    const clHeader = res.headers.get("content-length");
    if (clHeader && Number(clHeader) > MAX_MANIFEST_BYTES) {
      return { ok: false, error: "RURI manifest too large" };
    }
    manifestBody = await res.text();
    if (manifestBody.length > MAX_MANIFEST_BYTES) {
      return { ok: false, error: "RURI manifest too large" };
    }
  } catch (e: any) {
    return { ok: false, error: `RURI unreachable: ${e?.message ?? "unknown"}` };
  }

  let manifest: { rrn?: unknown };
  try { manifest = JSON.parse(manifestBody); }
  catch { return { ok: false, error: "RURI manifest is not valid JSON" }; }
  if (manifest.rrn !== expectedRrn) return { ok: false, error: "RURI manifest rrn mismatch" };

  const digest = await digestHex(canonicalCoreBytes(attestation));
  return { ok: true, evidence: { attestation_digest: digest, ruri_matched: manifestUrl } };
}
