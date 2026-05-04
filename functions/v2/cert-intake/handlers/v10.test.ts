import { describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { canonicalJson } from "rcan-ts";
import { handleV10 } from "./v10.js";

function b64(u8: Uint8Array): string { return Buffer.from(u8).toString("base64"); }
function b64buf(b: ArrayBuffer): string { return Buffer.from(new Uint8Array(b)).toString("base64"); }

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    env: {
      RRF_KV: {
        get: vi.fn(async (k: string) => store[k] ?? null),
        put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
        list: vi.fn(async ({ prefix }: { prefix: string }) => ({
          keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
          list_complete: true,
        })),
        delete: vi.fn(),
      } as unknown as KVNamespace,
    },
    store,
  };
}

async function setupRigAndWitness(store: Record<string, string>) {
  const rigPriv = crypto.getRandomValues(new Uint8Array(32));
  const rigPub = ed25519.getPublicKey(rigPriv);
  const witnessPriv = crypto.getRandomValues(new Uint8Array(32));
  const witnessPub = ed25519.getPublicKey(witnessPriv);
  store["cert-rig:bob-rig-2026:2026-05-04T00:00:00Z"] = JSON.stringify({
    rig_id: "bob", rrn: "RRN-000000000002", signing_pub: b64(rigPub),
    valid_from: "2026-05-04T00:00:00Z", registered_at: "2026-05-04T00:00:00Z",
  });
  store["cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z"] = JSON.stringify({
    witness_id: "craigm", rig_id: "bob", signing_pub: b64(witnessPub),
    valid_from: "2026-05-04T00:00:00Z", registered_at: "2026-05-04T00:00:00Z",
  });
  // Plan 4's RRF root signing key — PKCS8, matching signLogEntry's importKey contract.
  const rootKp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rootPrivDer = await crypto.subtle.exportKey("pkcs8", (rootKp as CryptoKeyPair).privateKey);
  const rootPubDer = await crypto.subtle.exportKey("spki", (rootKp as CryptoKeyPair).publicKey);
  store["rrf:root:privkey"] = b64buf(rootPrivDer);
  store["rrf:root:pubkey"] = `-----BEGIN PUBLIC KEY-----\n${b64buf(rootPubDer)}\n-----END PUBLIC KEY-----\n`;
  return { rigPriv, witnessPriv };
}

function makeBody(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "1.0",
    property_id: "SF-001",
    rig: "bob",
    robot_class: "so-arm101",
    ran_at: 1777939200.0,  // 2026-05-05T00:00:00Z
    iterations: 10,
    results: [{ iteration: 1, latency_ms: 47, pass: true }],
    all_pass: true,
    ...overrides,
  };
}

function signAndAttach(body: Record<string, unknown>, rigPriv: Uint8Array, witnessPriv: Uint8Array) {
  const core = { ...body };
  const msg = new TextEncoder().encode(canonicalJson(core));
  return {
    ...body,
    rig_signature:     { kid: "bob-rig-2026",        alg: "Ed25519", sig: b64(ed25519.sign(msg, rigPriv)) },
    witness_signature: { kid: "witness-bob-craigm", alg: "Ed25519", sig: b64(ed25519.sign(msg, witnessPriv)) },
  };
}

describe("cert-intake handlers/v10", () => {
  it("returns 201 with cert_id, rrn, transparency_log_index, logged_at, proof_url on happy path", async () => {
    const { env, store } = makeEnv();
    const { rigPriv, witnessPriv } = await setupRigAndWitness(store);
    const body = signAndAttach(makeBody(), rigPriv, witnessPriv);
    const res = await handleV10(body as Record<string, unknown>, env);
    expect(res.status).toBe(201);
    const json = await res.json() as Record<string, unknown>;
    expect((json.cert_id as string).startsWith("cert_")).toBe(true);
    expect(json.rrn).toBe("RRN-000000000002");
    expect(json.transparency_log_index).toBe(1);
    expect(typeof json.logged_at).toBe("string");
    expect(json.proof_url).toBe(`/v2/cert-intake/${json.cert_id}/proof`);
    // KV side effects.
    expect(store["counter:cert-log"]).toBe("1");
    expect(store[`cert-intake:${json.cert_id}`]).toBeDefined();
    expect(store["cert-intake-log:000000000001"]).toBeDefined();
  });

  it("returns 409 on second POST with identical body (idempotency)", async () => {
    const { env, store } = makeEnv();
    const { rigPriv, witnessPriv } = await setupRigAndWitness(store);
    const body = signAndAttach(makeBody(), rigPriv, witnessPriv);
    const first = await handleV10(body as Record<string, unknown>, env);
    expect(first.status).toBe(201);
    const second = await handleV10(body as Record<string, unknown>, env);
    expect(second.status).toBe(409);
  });

  it("returns 400 when property_id missing", async () => {
    const { env, store } = makeEnv();
    const { rigPriv, witnessPriv } = await setupRigAndWitness(store);
    const body = signAndAttach(makeBody({ property_id: undefined }), rigPriv, witnessPriv);
    delete (body as { property_id?: unknown }).property_id;
    const res = await handleV10(body as Record<string, unknown>, env);
    expect(res.status).toBe(400);
  });

  it("returns 401 when rig sig is wrong", async () => {
    const { env, store } = makeEnv();
    const { rigPriv: _unused, witnessPriv } = await setupRigAndWitness(store);
    const wrongPriv = crypto.getRandomValues(new Uint8Array(32));
    const body = signAndAttach(makeBody(), wrongPriv, witnessPriv);
    const res = await handleV10(body as Record<string, unknown>, env);
    expect(res.status).toBe(401);
  });
});
