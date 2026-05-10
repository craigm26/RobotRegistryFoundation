// functions/v2/_lib/fixtures/generate-run-bundle-fixtures.ts
//
// One-shot fixture generator. Run with:
//   cd functions/v2/_lib/fixtures && npx tsx generate-run-bundle-fixtures.ts
//
// Generates 3 fixtures: full (with rrn+rpn), gateway-only (no advisory), tampered.
// Uses an ephemeral test keypair generated at runtime. The pubkey is echoed
// at the top of each fixture as `_test_metadata.gateway_ran_pubkey_b64` so test
// setup can stage it in mocked KV.
//
// NOTE: `_test_metadata` is NOT included in the signed canonical bytes.
// Downstream tests must call stripTestMetadata() before passing to any
// handler or verifier (see Task 5 test helpers).

import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  canonicalJson,
  generateMlDsaKeypair,
  signHybrid,
  verifyHybrid,
  type HybridSignature,
} from "rcan-ts";
import { computeRunId } from "../canonical-run-id.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function b64Decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ---------------------------------------------------------------------------
// Sign a body (WITHOUT _test_metadata present).
// 1. Compute run_id from body (excludes sig + run_id already).
// 2. Attach run_id to body.
// 3. canonicalJson(body with run_id, minus sig) → signed bytes.
// 4. signHybrid → {profile, ed25519Sig, mlDsaSig}.
// 5. Encode to base64 and attach as sig field.
// ---------------------------------------------------------------------------
async function signBody(
  body: Record<string, unknown>,
  ed25519Priv: Uint8Array,
  mlDsaPriv: Uint8Array,
): Promise<Record<string, unknown>> {
  // Step 1: compute run_id (body must NOT have _test_metadata, sig, or run_id)
  const run_id = await computeRunId(body);

  // Step 2: add run_id
  const bodyWithId = { ...body, run_id };

  // Step 3: canonical bytes over body-with-run_id (excluding sig)
  // sig is not present yet, but strip defensively
  const { sig: _drop, ...rest } = bodyWithId;
  void _drop;
  const canonBytes = canonicalJson(rest as Record<string, unknown>);

  // Step 4: sign (sync)
  const hybridSig: HybridSignature = signHybrid(ed25519Priv, mlDsaPriv, canonBytes);

  // Step 5: encode as base64 sig block
  const sigField = {
    ml_dsa: b64Encode(hybridSig.mlDsaSig),
    ed25519: b64Encode(hybridSig.ed25519Sig),
    ed25519_pub: b64Encode(ed25519.getPublicKey(ed25519Priv)),
  };

  return { ...bodyWithId, sig: sigField };
}

// ---------------------------------------------------------------------------
// Verify a signed fixture (strips sig + _test_metadata before canonicalizing)
// ---------------------------------------------------------------------------
function verifyFixture(
  fixture: Record<string, unknown>,
  ed25519Pub: Uint8Array,
  mlDsaPub: Uint8Array,
): boolean {
  const { sig, _test_metadata: _tm, ...rest } = fixture as Record<string, unknown> & {
    sig: Record<string, string>;
    _test_metadata: unknown;
  };
  const canonBytes = canonicalJson(rest as Record<string, unknown>);
  const hybridSig: HybridSignature = {
    profile: "pqc-hybrid-v1",
    ed25519Sig: b64Decode(sig.ed25519),
    mlDsaSig: b64Decode(sig.ml_dsa),
  };
  try {
    return verifyHybrid(ed25519Pub, mlDsaPub, canonBytes, hybridSig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  // Generate ephemeral test keypairs.
  // These are used ONLY in test fixtures. DO NOT use in production.
  const mlDsaKp = generateMlDsaKeypair();
  const ed25519Priv = ed25519.utils.randomSecretKey();
  const ed25519Pub = ed25519.getPublicKey(ed25519Priv);

  const pqSigningPub = b64Encode(mlDsaKp.publicKey);
  const ed25519PubB64 = b64Encode(ed25519Pub);

  // Common required fields (no _test_metadata, no sig, no run_id)
  const baseBody: Record<string, unknown> = {
    schema_version: "1.0",
    gateway_ran: "RAN-000000000019",
    started_at: "2026-05-09T20:00:00Z",
    finished_at: "2026-05-09T20:00:01Z",
    outcome_kind: "no_op",
    outcome_detail: "test fixture",
    skill_manifest_sha256: "a".repeat(64),
    actuator_name: "robot-md-example-actuator",
    tier: "L0",
    pq_signing_pub: pqSigningPub,
    pq_kid: "test-key-1",
    ed25519_pub: ed25519PubB64,
  };

  // ------- Fixture 1: full (rrn + rpn + advisory) -------
  const fullBody: Record<string, unknown> = {
    ...baseBody,
    rrn: "RRN-000000000001",
    rpn: "RPN-000000000001",
    manifest_path: "skills/wave/SKILL.md",
  };
  const fullSigned = await signBody(fullBody, ed25519Priv, mlDsaKp.privateKey);
  const full = {
    ...fullSigned,
    _test_metadata: {
      gateway_ran_pubkey_b64: pqSigningPub,
    },
  };

  // ------- Fixture 2: gateway-only (no rrn, no rpn) -------
  const gwOnlySigned = await signBody(baseBody, ed25519Priv, mlDsaKp.privateKey);
  const gatewayOnly = {
    ...gwOnlySigned,
    _test_metadata: {
      gateway_ran_pubkey_b64: pqSigningPub,
    },
  };

  // ------- Fixture 3: tampered — corrupt first 4 chars of ml_dsa sig -------
  // The string length must stay the same so tests can check "same length, wrong content".
  const fullSig = full.sig as Record<string, string>;
  const tamperedMlDsa =
    fullSig.ml_dsa.slice(0, 4) === "AAAA"
      ? "BBBB" + fullSig.ml_dsa.slice(4)  // guard: if already AAAA, use BBBB
      : "AAAA" + fullSig.ml_dsa.slice(4);
  const tampered: Record<string, unknown> = {
    ...full,
    sig: { ...fullSig, ml_dsa: tamperedMlDsa },
  };

  // ------- Inline verification -------
  console.log("Verifying full fixture...");
  const fullOk = verifyFixture(full, ed25519Pub, mlDsaKp.publicKey);
  if (!fullOk) throw new Error("FAIL: full fixture did not verify");
  console.log("  full: OK");

  console.log("Verifying gateway-only fixture...");
  const gwOk = verifyFixture(gatewayOnly, ed25519Pub, mlDsaKp.publicKey);
  if (!gwOk) throw new Error("FAIL: gateway-only fixture did not verify");
  console.log("  gateway-only: OK");

  console.log("Verifying tampered fixture should FAIL...");
  const tamperedOk = verifyFixture(tampered, ed25519Pub, mlDsaKp.publicKey);
  if (tamperedOk) throw new Error("FAIL: tampered fixture verified (should not have)");
  console.log("  tampered: correctly rejected");

  // ------- Write fixtures -------
  const dir = resolve(__dirname);
  mkdirSync(dir, { recursive: true });

  writeFileSync(resolve(dir, "run-bundle-full.json"), JSON.stringify(full, null, 2));
  writeFileSync(resolve(dir, "run-bundle-gateway-only.json"), JSON.stringify(gatewayOnly, null, 2));
  writeFileSync(resolve(dir, "run-bundle-tampered.json"), JSON.stringify(tampered, null, 2));

  // ------- Report -------
  const mlDsaFirst12Hex = (b64: string) =>
    Buffer.from(b64Decode(b64).slice(0, 6)).toString("hex");

  console.log("\nwrote 3 fixtures");
  console.log(`  run-bundle-full.json         run_id=${full.run_id} has-rrn=true  ml_dsa[0:6]=${mlDsaFirst12Hex(fullSig.ml_dsa)}`);
  console.log(`  run-bundle-gateway-only.json run_id=${gatewayOnly.run_id} has-rrn=false ml_dsa[0:6]=${mlDsaFirst12Hex((gatewayOnly.sig as Record<string,string>).ml_dsa)}`);
  console.log(`  run-bundle-tampered.json     run_id=${tampered.run_id} has-rrn=true  ml_dsa[0:6]=${mlDsaFirst12Hex(tamperedMlDsa)} (CORRUPTED)`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
