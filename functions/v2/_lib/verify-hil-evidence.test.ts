import { describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { canonicalJson } from "rcan-ts";
import { verifyHilEvidence } from "./verify-hil-evidence.js";

function b64(u8: Uint8Array): string {
  return Buffer.from(u8).toString("base64");
}

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(async ({ prefix }: { prefix: string }) => ({
        keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
        list_complete: true,
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

function makeBody(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "1.0",
    property_id: "SF-001",
    rig: "bob",
    robot_class: "so-arm101",
    ran_at: 1777939200.0, // 2026-05-05T00:00:00Z — after valid_from 2026-05-04
    iterations: 10,
    results: [{ iteration: 1, latency_ms: 47, pass: true }],
    all_pass: true,
    ...overrides,
  };
}

function signAndAttach(body: Record<string, unknown>, rigPriv: Uint8Array, witnessPriv: Uint8Array, rigKid: string, witnessKid: string) {
  const core = { ...body };
  delete (core as { rig_signature?: unknown }).rig_signature;
  delete (core as { witness_signature?: unknown }).witness_signature;
  const msg = new TextEncoder().encode(canonicalJson(core));
  const rigSig = ed25519.sign(msg, rigPriv);
  const witnessSig = ed25519.sign(msg, witnessPriv);
  return {
    ...body,
    rig_signature: { kid: rigKid, alg: "Ed25519", sig: b64(rigSig) },
    witness_signature: { kid: witnessKid, alg: "Ed25519", sig: b64(witnessSig) },
  };
}

describe("verifyHilEvidence", () => {
  it("returns ok with rig + witness records on a fresh, well-formed body", async () => {
    const rigPriv = crypto.getRandomValues(new Uint8Array(32));
    const rigPub = ed25519.getPublicKey(rigPriv);
    const witnessPriv = crypto.getRandomValues(new Uint8Array(32));
    const witnessPub = ed25519.getPublicKey(witnessPriv);
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify({
        rig_id: "bob",
        rrn: "RRN-000000000002",
        signing_pub: b64(rigPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
      "cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z": JSON.stringify({
        witness_id: "craigm",
        rig_id: "bob",
        signing_pub: b64(witnessPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
    });
    const body = signAndAttach(makeBody(), rigPriv, witnessPriv, "bob-rig-2026", "witness-bob-craigm");
    const result = await verifyHilEvidence(env, body);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.rig.rrn).toBe("RRN-000000000002");
      expect(result.witness.rig_id).toBe("bob");
    }
  });

  it("returns ok=false 403 when rig kid is not registered", async () => {
    const env = makeEnv({});
    const body = makeBody({
      rig_signature: { kid: "ghost", alg: "Ed25519", sig: "AA==" },
      witness_signature: { kid: "ghost-witness", alg: "Ed25519", sig: "AA==" },
    });
    const result = await verifyHilEvidence(env, body);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.error).toMatch(/rig.*kid.*not.*registered/i);
    }
  });

  it("returns ok=false 401 when rig sig does not verify", async () => {
    const rigPriv = crypto.getRandomValues(new Uint8Array(32));
    const witnessPriv = crypto.getRandomValues(new Uint8Array(32));
    const witnessPub = ed25519.getPublicKey(witnessPriv);
    // Register rig with a *different* pub than the one signing.
    const otherPub = ed25519.getPublicKey(crypto.getRandomValues(new Uint8Array(32)));
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify({
        rig_id: "bob",
        rrn: "RRN-000000000002",
        signing_pub: b64(otherPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
      "cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z": JSON.stringify({
        witness_id: "craigm",
        rig_id: "bob",
        signing_pub: b64(witnessPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
    });
    const body = signAndAttach(makeBody(), rigPriv, witnessPriv, "bob-rig-2026", "witness-bob-craigm");
    const result = await verifyHilEvidence(env, body);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(401);
      expect(result.error).toMatch(/rig.*signature/i);
    }
  });

  it("returns ok=false 403 when witness.rig_id does not match rig.rig_id (scope mismatch)", async () => {
    const rigPriv = crypto.getRandomValues(new Uint8Array(32));
    const rigPub = ed25519.getPublicKey(rigPriv);
    const witnessPriv = crypto.getRandomValues(new Uint8Array(32));
    const witnessPub = ed25519.getPublicKey(witnessPriv);
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify({
        rig_id: "bob",
        rrn: "RRN-000000000002",
        signing_pub: b64(rigPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
      "cert-witness:witness-foo-bar:2026-05-04T00:00:00Z": JSON.stringify({
        witness_id: "bar",
        rig_id: "foo",  // pairs with a *different* rig
        signing_pub: b64(witnessPub),
        valid_from: "2026-05-04T00:00:00Z",
        registered_at: "2026-05-04T00:00:00Z",
      }),
    });
    const body = signAndAttach(makeBody(), rigPriv, witnessPriv, "bob-rig-2026", "witness-foo-bar");
    const result = await verifyHilEvidence(env, body);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.error).toMatch(/scope|rig_id|pairing/i);
    }
  });
});
