import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { handleV10 } from "./v10.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fxFull = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/run-bundle-full.json"), "utf8"),
);
const fxGatewayOnly = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/run-bundle-gateway-only.json"), "utf8"),
);

/** Generate a fresh Ed25519 keypair for log signing. */
async function mkRootKey(): Promise<{ priv_b64: string }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privDer = await crypto.subtle.exportKey("pkcs8", (kp as CryptoKeyPair).privateKey);
  const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return { priv_b64: b64(privDer) };
}

/**
 * Build a mock env seeded with:
 *   - authority:RAN-000000000019 containing pq_signing_pub + signing_pub from the fixture
 *   - rrf:root:privkey as a real Ed25519 PKCS8 base64
 */
async function makeEnv(seedFx: any = fxFull) {
  const root = await mkRootKey();
  const store: Record<string, string> = {
    "authority:RAN-000000000019": JSON.stringify({
      ran: "RAN-000000000019",
      pq_signing_pub: seedFx._test_metadata.gateway_ran_pubkey_b64,
      signing_pub: seedFx.ed25519_pub,
      status: "active",
    }),
    "rrf:root:privkey": root.priv_b64,
  };
  return {
    __store: store,
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

function stripTestMetadata(fx: any): Record<string, unknown> {
  const { _test_metadata: _drop, ...rest } = fx;
  return rest;
}

describe("handleV10 (run-bundles)", () => {
  it("happy path with rrn+rpn writes 6 KV keys + returns 201", async () => {
    const env = await makeEnv(fxFull);
    const res = await handleV10(stripTestMetadata(fxFull), env as any);
    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.run_id).toMatch(/^runbundle_[0-9a-f]{12}$/);
    expect(body.transparency_log_index).toBe(1);
    // 6 writes: counter, log entry, canonical record, by-gateway-ran, by-rrn, by-rpn
    expect((env.RRF_KV.put as any).mock.calls.length).toBe(6);
  });

  it("happy path gateway-only writes 4 KV keys (no by-rrn / by-rpn)", async () => {
    const env = await makeEnv(fxGatewayOnly);
    const res = await handleV10(stripTestMetadata(fxGatewayOnly), env as any);
    expect(res.status).toBe(201);
    const writeKeys = (env.RRF_KV.put as any).mock.calls.map((c: any[]) => c[0]);
    // 4 writes: counter, log entry, canonical record, by-gateway-ran
    expect(writeKeys.length).toBe(4);
    expect(writeKeys.some((k: string) => k.startsWith("run-bundles-by-rrn:"))).toBe(false);
    expect(writeKeys.some((k: string) => k.startsWith("run-bundles-by-rpn:"))).toBe(false);
    expect(writeKeys.some((k: string) => k.startsWith("run-bundles-by-gateway-ran:"))).toBe(true);
  });

  it("400 on missing required field", async () => {
    const env = await makeEnv();
    const { actuator_name: _drop, ...incomplete } = stripTestMetadata(fxFull);
    const res = await handleV10(incomplete, env as any);
    expect(res.status).toBe(400);
  });

  it("400 when run_id doesn't match recomputed hash", async () => {
    const env = await makeEnv();
    const tampered = { ...stripTestMetadata(fxFull), run_id: "runbundle_aaaaaaaaaaaa" };
    const res = await handleV10(tampered, env as any);
    expect(res.status).toBe(400);
  });

  it("404 when gateway_ran not registered in KV", async () => {
    const env = await makeEnv();
    delete (env as any).__store["authority:RAN-000000000019"];
    const res = await handleV10(stripTestMetadata(fxFull), env as any);
    expect(res.status).toBe(404);
  });

  it("409 on duplicate POST (idempotency by run_id)", async () => {
    const env = await makeEnv(fxFull);
    await handleV10(stripTestMetadata(fxFull), env as any);
    const res = await handleV10(stripTestMetadata(fxFull), env as any);
    expect(res.status).toBe(409);
  });
});
