import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyRunBundleHybrid } from "./verify-run-bundle-hybrid.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const fxFull = JSON.parse(
  readFileSync(join(__dirname, "fixtures/run-bundle-full.json"), "utf-8"),
) as Record<string, unknown>;

const fxTampered = JSON.parse(
  readFileSync(join(__dirname, "fixtures/run-bundle-tampered.json"), "utf-8"),
) as Record<string, unknown>;

/** Drop _test_metadata before passing to the verifier (it was grafted on post-signing). */
function stripTestMetadata(body: Record<string, unknown>): Record<string, unknown> {
  const { _test_metadata: _drop, ...rest } = body;
  void _drop;
  return rest;
}

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    __store: store,
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(async ({ prefix }: { prefix: string }) => ({
        keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

/**
 * Build a RAN record that matches the fixture's keys.
 *
 * - pq_signing_pub comes from _test_metadata.gateway_ran_pubkey_b64 (the ML-DSA key
 *   the gateway used when signing the fixture).
 * - signing_pub comes from fxFull.ed25519_pub (the Ed25519 key embedded in the body,
 *   which must also be registered on the gateway's RAN).
 */
function makeRanRecord(overrides: Record<string, unknown> = {}): string {
  const meta = fxFull._test_metadata as { gateway_ran_pubkey_b64: string };
  const record = {
    ran: "RAN-000000000019",
    pq_signing_pub: meta.gateway_ran_pubkey_b64,
    signing_pub: fxFull.ed25519_pub as string,
    status: "active",
    ...overrides,
  };
  return JSON.stringify(record);
}

describe("verifyRunBundleHybrid", () => {
  it("happy path: valid full fixture verifies with ok=true and correct ran", async () => {
    const env = makeEnv();
    env.__store["authority:RAN-000000000019"] = makeRanRecord();

    const result = await verifyRunBundleHybrid(env, stripTestMetadata(fxFull));

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ran).toBe("RAN-000000000019");
    }
  });

  it("RAN not found: returns ok=false with status 404", async () => {
    const env = makeEnv(); // no authority record staged

    const result = await verifyRunBundleHybrid(env, stripTestMetadata(fxFull));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(404);
    }
  });

  it("key mismatch: returns ok=false with status 403", async () => {
    const env = makeEnv();
    // Stage a RAN record with a DIFFERENT pq_signing_pub
    env.__store["authority:RAN-000000000019"] = makeRanRecord({
      pq_signing_pub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });

    const result = await verifyRunBundleHybrid(env, stripTestMetadata(fxFull));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
    }
  });

  it("tampered fixture: returns ok=false with status 400", async () => {
    const env = makeEnv();
    env.__store["authority:RAN-000000000019"] = makeRanRecord();

    // The tampered fixture has the correct pq_signing_pub (key-match passes)
    // but the ml_dsa sig is corrupted — verifyHybrid should return false → 400.
    const result = await verifyRunBundleHybrid(env, stripTestMetadata(fxTampered));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
    }
  });
});
