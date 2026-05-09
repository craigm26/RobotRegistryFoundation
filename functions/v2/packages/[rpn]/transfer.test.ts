import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./transfer.js";
import { signBodyWithFixtureKp, fixturePublisher } from "./_test-helpers.js";
import { signBody, generateMlDsaKeypair } from "rcan-ts";

// Dummy new publisher block used in transfer tests.
const NEW_PUBLISHER = {
  new_pq_signing_pub: "NEWKEYPUB==",
  new_pq_kid: "publisher-2026-06",
  new_ed25519_pub: "NEWED25519==",
};

function makeEnv() {
  const record = {
    rpn: "RPN-000000000001",
    package_type: "actuator",
    name: "feetech-arm",
    versions: [{ version: "1.0.0", released_at: "2026-05-09T00:00:00Z" }],
    publisher: fixturePublisher,
    registered_at: "2026-05-09T00:00:00Z",
    status: "active",
  };
  const store: Record<string, string> = {
    "package:RPN-000000000001": JSON.stringify(record),
  };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    },
    __store: store,
  };
}

async function signedTransferPost(
  newKey: { new_pq_signing_pub: string; new_pq_kid: string; new_ed25519_pub: string },
): Promise<Request> {
  const body = await signBodyWithFixtureKp(newKey);
  return new Request("https://x/v2/packages/RPN-000000000001/transfer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/packages/[rpn]/transfer", () => {
  it("404 when RPN doesn't exist", async () => {
    const env = makeEnv();
    delete env.__store["package:RPN-000000000001"];
    const req = await signedTransferPost(NEW_PUBLISHER);
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(404);
  });

  it("rejects unsigned body (400)", async () => {
    const env = makeEnv();
    const req = new Request("https://x/v2/packages/RPN-000000000001/transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(NEW_PUBLISHER),
    });
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });

  it("rejects sig from non-current-owner (400)", async () => {
    const env = makeEnv();
    // Generate a random fresh ML-DSA keypair — its pubkey doesn't match the stored record.
    const altKp = generateMlDsaKeypair();
    // Use a dummy ed25519 pair (self-signing with webcrypto would require async setup;
    // reuse fixture's ed25519 secret — what matters is ML-DSA pubkey mismatch).
    const { readFileSync } = await import("node:fs");
    const { resolve, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const __dir = dirname(fileURLToPath(import.meta.url));
    const fx = JSON.parse(readFileSync(resolve(__dir, "../../../_lib/fixtures/package-fixture.json"), "utf8"));
    function b64Decode(b64: string): Uint8Array {
      return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    }
    // Sign with the alt (unregistered) ML-DSA key.
    const fakeBody = await signBody(
      altKp,
      NEW_PUBLISHER,
      {
        ed25519Secret: b64Decode(fx.keypair.ed25519_sec_b64),
        ed25519Public: b64Decode(fx.keypair.ed25519_pub_b64),
      },
    );
    const req = new Request("https://x/v2/packages/RPN-000000000001/transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fakeBody),
    });
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });

  it("rotates publisher key on success (200)", async () => {
    const env = makeEnv();
    const req = await signedTransferPost(NEW_PUBLISHER);
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(200);
    const stored = JSON.parse(env.__store["package:RPN-000000000001"]);
    expect(stored.publisher.pq_signing_pub).toBe("NEWKEYPUB==");
    expect(stored.publisher.pq_kid).toBe("publisher-2026-06");
    expect(stored.publisher.ed25519_pub).toBe("NEWED25519==");
  });

  it("400 on revoked package", async () => {
    const env = makeEnv();
    const rec = JSON.parse(env.__store["package:RPN-000000000001"]);
    rec.status = "revoked";
    env.__store["package:RPN-000000000001"] = JSON.stringify(rec);
    const req = await signedTransferPost(NEW_PUBLISHER);
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });
});
