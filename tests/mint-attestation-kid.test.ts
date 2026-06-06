import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "../functions/v2/authorities/register.js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolve } from "node:path";

const PY = "/home/craigm26/rcan-py/.venv/bin/python";
const SCRIPT = resolve(__dirname, "..", "scripts", "mint-attestation-kid.py");

// KV mock mirrors functions/v2/keys/[kid].test.ts and tests/api/v2/authorities.test.ts.
function makeEnv() {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(async (o: { prefix?: string }) => ({
        keys: Object.keys(store).filter((k) => k.startsWith(o?.prefix ?? "")).map((name) => ({ name })),
        list_complete: true,
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

function runMint(outDir: string): Record<string, unknown> {
  execFileSync(PY, [SCRIPT, "--organization", "OpenCastor", "--display-name",
    "Bob gateway attestation signer", "--out-dir", outDir], { encoding: "utf-8" });
  return JSON.parse(readFileSync(join(outDir, "mint-manifest.json"), "utf-8"));
}

describe("mint-attestation-kid.py", () => {
  it("writes the gateway PEM, ML-DSA archive, and a mint-manifest", () => {
    const dir = mkdtempSync(join(tmpdir(), "mint-"));
    const manifest = runMint(dir);
    expect(existsSync(join(dir, "attestation-ed25519-private.pem"))).toBe(true);
    expect(existsSync(join(dir, "attestation-mldsa65-private.pem"))).toBe(true);
    expect(manifest.organization).toBe("OpenCastor");
    expect(manifest.signing_alg).toEqual(["Ed25519", "ML-DSA-65"]);
    expect(typeof manifest.pq_kid).toBe("string");
    expect((manifest.pq_kid as string)).toMatch(/^[0-9a-f]{8}$/);
    // raw pub decodes to 32, pq pub to 1952 — the byte lengths RRF enforces.
    expect(Buffer.from(manifest.signing_pub_b64 as string, "base64").length).toBe(32);
    expect(Buffer.from(manifest.pq_signing_pub_b64 as string, "base64").length).toBe(1952);
  });

  it("emits a hybrid body that passes the real register.ts verifyBody (PoP + Python↔TS interop, 201)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mint-"));
    const manifest = runMint(dir);
    const body = manifest.registration_body as Record<string, unknown>;
    // Shape required by register.ts (verified §2.2): sig.{ml_dsa,ed25519,ed25519_pub},
    // signing_alg exact tuple, sig.ed25519_pub === signing_pub.
    const sig = body.sig as Record<string, string>;
    expect(sig.ml_dsa && sig.ed25519 && sig.ed25519_pub).toBeTruthy();
    expect(sig.ed25519_pub).toBe(body.signing_pub);
    expect(body.signing_alg).toEqual(["Ed25519", "ML-DSA-65"]);
    expect(body.purpose).toBe("attestation");
    const res = await onRequestPost({
      request: new Request("https://x/v2/authorities/register", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      }),
      env: makeEnv(),
    } as any);
    expect(res.status).toBe(201);
  });
});
