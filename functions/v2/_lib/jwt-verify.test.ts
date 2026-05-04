import { describe, it, expect, vi } from "vitest";
import { verifyM2mTrustedJwt } from "./jwt-verify.js";

function makeEnv(initial: Record<string, string> = {}, rootPubkey?: string) {
  const store: Record<string, string> = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    } as unknown as KVNamespace,
    ...(rootPubkey !== undefined ? { RRF_ROOT_PUBKEY: rootPubkey } : {}),
  };
}

describe("verifyM2mTrustedJwt", () => {
  it("rejects with 401 when Authorization header is missing", async () => {
    const env = makeEnv();
    const req = new Request("https://rrf.rcan.dev/v2/compliance-bundle", {
      method: "POST",
    });
    const r = await verifyM2mTrustedJwt(env, req, "RRN-000000000001");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/Bearer/);
    }
  });

  it("rejects with 401 when Authorization scheme is not Bearer", async () => {
    const env = makeEnv();
    const req = new Request("https://rrf.rcan.dev/v2/compliance-bundle", {
      method:  "POST",
      headers: { Authorization: "Basic dXNlcjpwYXNz" },
    });
    const r = await verifyM2mTrustedJwt(env, req, "RRN-000000000001");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/Bearer/);
    }
  });

  it("returns 401 or 500 when RRF root pubkey is not provisioned", async () => {
    // No KV entry, no env fallback. Token shape doesn't matter — but we provide
    // a syntactically valid 3-part JWT so failure is from missing pubkey, not
    // from token parsing.
    const env = makeEnv();
    const fakeJwt = [
      btoa(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).replace(/=/g, ""),
      btoa(JSON.stringify({ iss: "rrf.rcan.dev", rrf_sig: "AAAA" })).replace(/=/g, ""),
      "AAAA",
    ].join(".");
    const req = new Request("https://rrf.rcan.dev/v2/compliance-bundle", {
      method:  "POST",
      headers: { Authorization: `Bearer ${fakeJwt}` },
    });
    const r = await verifyM2mTrustedJwt(env, req, "RRN-000000000001");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect([401, 500]).toContain(r.status);
    }
  });

  it("rejects malformed JWTs (not 3 parts) with 401", async () => {
    const env = makeEnv();
    const req = new Request("https://rrf.rcan.dev/v2/compliance-bundle", {
      method:  "POST",
      headers: { Authorization: "Bearer not-a-jwt" },
    });
    const r = await verifyM2mTrustedJwt(env, req, "RRN-000000000001");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/3 parts|Invalid JWT/);
    }
  });

  it("rejects when JWT signature does not verify against the configured pubkey", async () => {
    // Provide a real-shaped (but unrelated) Ed25519 SPKI public key so the import
    // succeeds; the signature itself will then fail to verify against arbitrary bytes.
    const realSpkiB64 =
      "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
    const env = makeEnv({
      "rrf:root:pubkey": `-----BEGIN PUBLIC KEY-----\n${realSpkiB64}\n-----END PUBLIC KEY-----\n`,
    });
    const fakeJwt = [
      btoa(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).replace(/=/g, ""),
      btoa(JSON.stringify({
        iss:         "rrf.rcan.dev",
        exp:         Math.floor(Date.now() / 1000) + 3600,
        rcan_scopes: ["fleet.trusted"],
        fleet_rrns:  ["RRN-000000000001"],
        rrf_sig:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      })).replace(/=/g, ""),
      "AAAA",
    ].join(".");
    const req = new Request("https://rrf.rcan.dev/v2/compliance-bundle", {
      method:  "POST",
      headers: { Authorization: `Bearer ${fakeJwt}` },
    });
    const r = await verifyM2mTrustedJwt(env, req, "RRN-000000000001");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/signature verification failed/i);
    }
  });
});
