// functions/v2/authorities/register.test.ts
//
// Covers the per-organization daily minting cap on POST /v2/authorities/register.
// Authentication is deliberately absent on this endpoint (open, self-attested
// registration); the cap is the control, so it is what gets tested.
import { describe, it, expect, vi } from "vitest";
import { onRequestPost, MINT_CAP_PER_ORG_PER_DAY } from "./register.js";
import { signBody } from "rcan-ts";
import { makeTestKeypair } from "../_lib/test-helpers.js";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
      list: vi.fn(async (opts: { prefix?: string } = {}) => ({
        keys: Object.keys(store)
          .filter((k) => k.startsWith(opts?.prefix ?? ""))
          .map((name) => ({ name })),
        list_complete: true,
      })),
    } as unknown as KVNamespace,
    __store: store,
  };
}

async function signedRegistration(organization: string) {
  const kp = await makeTestKeypair();
  const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
  return signBody(
    kp.mlDsa,
    {
      organization,
      display_name: "Test authority",
      purpose: "attestation",
      signing_pub: b64(kp.ed25519Public),
      signing_alg: ["Ed25519", "ML-DSA-65"],
    } as any,
    { ed25519Secret: kp.ed25519Secret, ed25519Public: kp.ed25519Public },
  );
}

const post = (env: unknown, body: unknown) =>
  onRequestPost({
    env,
    request: new Request("https://x/v2/authorities/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  } as any);

const today = () => new Date().toISOString().slice(0, 10);

describe("POST /v2/authorities/register — per-organization daily minting cap", () => {
  it("publishes a cap of 25 per organization per UTC day", () => {
    expect(MINT_CAP_PER_ORG_PER_DAY).toBe(25);
  });

  it("the 26th registration for one organization in a day returns 429", async () => {
    const ORG = "One Org Minting Everything";
    const env = makeEnv();
    for (let i = 0; i < MINT_CAP_PER_ORG_PER_DAY; i++) {
      const res = await post(env, await signedRegistration(ORG));
      expect(res.status).toBe(201);
    }
    const capped = await post(env, await signedRegistration(ORG));
    expect(capped.status).toBe(429);
    const body = await capped.json() as any;
    expect(body.cap).toBe(MINT_CAP_PER_ORG_PER_DAY);
    expect(body.organization).toBe(ORG);
    expect(body.minted_today).toBe(MINT_CAP_PER_ORG_PER_DAY);
  }, 120_000);

  it("the cap is per organization: a different org is unaffected", async () => {
    const env = makeEnv({ [`mint-count:Org A:${today()}`]: String(MINT_CAP_PER_ORG_PER_DAY) });
    const capped = await post(env, await signedRegistration("Org A"));
    expect(capped.status).toBe(429);
    const other = await post(env, await signedRegistration("Org B"));
    expect(other.status).toBe(201);
  }, 30_000);

  it("counts a successful mint and appends a readable mint event", async () => {
    const env = makeEnv();
    const res = await post(env, await signedRegistration("Org C"));
    expect(res.status).toBe(201);
    const { ran } = await res.json() as any;
    expect((env as any).__store[`mint-count:Org C:${today()}`]).toBe("1");
    const events = JSON.parse((env as any).__store[`authority-mint-events:${today()}`]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ ran, organization: "Org C" });
    expect(typeof events[0].registered_at).toBe("string");
  }, 30_000);

  it("a rejected registration does not burn the organization's quota", async () => {
    const env = makeEnv();
    const bad = await post(env, { organization: "Org D", display_name: "x" });
    expect(bad.status).toBe(400);
    expect((env as any).__store[`mint-count:Org D:${today()}`]).toBeUndefined();
    expect((env as any).__store[`authority-mint-events:${today()}`]).toBeUndefined();
  });

  it("a body that fails signature verification does not burn quota either", async () => {
    const env = makeEnv();
    const signed = await signedRegistration("Org E") as Record<string, unknown>;
    signed.display_name = "tampered after signing";
    const res = await post(env, signed);
    expect(res.status).toBe(400);
    expect((env as any).__store[`mint-count:Org E:${today()}`]).toBeUndefined();
  }, 30_000);

  it("yesterday's counter does not cap today", async () => {
    const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
    const env = makeEnv({ [`mint-count:Org F:${yesterday}`]: String(MINT_CAP_PER_ORG_PER_DAY) });
    const res = await post(env, await signedRegistration("Org F"));
    expect(res.status).toBe(201);
  }, 30_000);
});
