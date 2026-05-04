import { describe, it, expect, vi } from "vitest";
import { signLogEntry } from "./rrf-log-sign.js";
import { canonicalJson } from "rcan-ts";

function makeEnv(initial: Record<string, string> = {}) {
  const store = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(), list: vi.fn(), delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

async function mkRootKey(): Promise<{ priv_b64: string; pub_pem: string }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privDer = await crypto.subtle.exportKey("pkcs8", (kp as CryptoKeyPair).privateKey);
  const pubDer = await crypto.subtle.exportKey("spki", (kp as CryptoKeyPair).publicKey);
  const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return {
    priv_b64: b64(privDer),
    pub_pem: `-----BEGIN PUBLIC KEY-----\n${b64(pubDer)}\n-----END PUBLIC KEY-----\n`,
  };
}

describe("signLogEntry", () => {
  it("produces a valid Ed25519 signature over canonical entry bytes", async () => {
    const root = await mkRootKey();
    const env = makeEnv({
      "rrf:root:privkey": root.priv_b64,
      "rrf:root:pubkey": root.pub_pem,
    });
    const entry = {
      bundle_id: "bundle_test",
      rrn: "RRN-000000000002",
      transparency_log_index: 42,
    };
    const sig = await signLogEntry(env, entry);
    expect(sig.kid).toBe("rrf-root");
    expect(sig.alg).toBe("Ed25519");
    expect(sig.sig).toMatch(/^[A-Za-z0-9+/=]+$/);

    // Verify the signature against the entry's canonical bytes.
    const pub = await crypto.subtle.importKey(
      "spki",
      Uint8Array.from(atob(root.pub_pem.split("\n").slice(1, -2).join("")), c => c.charCodeAt(0)),
      { name: "Ed25519" }, false, ["verify"],
    );
    const sigBytes = Uint8Array.from(atob(sig.sig), c => c.charCodeAt(0));
    const canon = canonicalJson(entry);
    const ok = await crypto.subtle.verify("Ed25519", pub, sigBytes, canon);
    expect(ok).toBe(true);
  });

  it("throws when rrf:root:privkey is not configured", async () => {
    const env = makeEnv();
    await expect(signLogEntry(env, { bundle_id: "x" })).rejects.toThrow(/privkey not configured/i);
  });
});
