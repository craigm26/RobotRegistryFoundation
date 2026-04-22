import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
import { canonicalJson, verifyHybrid } from "./verify.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(resolve(__dirname, "fixtures/hybrid-fixture.json"), "utf8"));

function b64(s: string): Uint8Array { return Uint8Array.from(Buffer.from(s, "base64")); }

describe("canonicalJson", () => {
  it("matches Python's json.dumps(sort_keys=True, separators=',':')", () => {
    const ours = canonicalJson(fx.body);
    const expected = b64(fx.canonical_bytes_b64);
    expect(Buffer.compare(Buffer.from(ours), Buffer.from(expected))).toBe(0);
  });

  it("sorts nested object keys", () => {
    const bytes = canonicalJson({ b: 2, a: { z: 1, y: 2 } });
    expect(new TextDecoder().decode(bytes)).toBe('{"a":{"y":2,"z":1},"b":2}');
  });
});

describe("verifyHybrid", () => {
  it("accepts a valid Python-signed payload", async () => {
    const ok = await verifyHybrid(fx.pq_signing_pub, fx.sig, canonicalJson(fx.body));
    expect(ok).toBe(true);
  });

  it("rejects when ml_dsa signature is tampered", async () => {
    const tampered = { ...fx.sig, ml_dsa: "AAAA" + fx.sig.ml_dsa.slice(4) };
    const ok = await verifyHybrid(fx.pq_signing_pub, tampered, canonicalJson(fx.body));
    expect(ok).toBe(false);
  });

  it("rejects when ed25519 signature is tampered", async () => {
    const tampered = { ...fx.sig, ed25519: "AAAA" + fx.sig.ed25519.slice(4) };
    const ok = await verifyHybrid(fx.pq_signing_pub, tampered, canonicalJson(fx.body));
    expect(ok).toBe(false);
  });

  it("rejects when message bytes are tampered", async () => {
    const bad = canonicalJson({ ...fx.body, manufacturer: "evil" });
    const ok = await verifyHybrid(fx.pq_signing_pub, fx.sig, bad);
    expect(ok).toBe(false);
  });
});
