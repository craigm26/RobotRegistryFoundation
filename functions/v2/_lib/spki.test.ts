import { describe, it, expect } from "vitest";
import { ed25519RawToPem, PEM_HEADER, PEM_FOOTER } from "./spki.js";

describe("ed25519RawToPem", () => {
  it("wraps 32 zero bytes in valid SPKI PEM", () => {
    const raw = new Uint8Array(32);  // all zeros
    const pem = ed25519RawToPem(raw);
    expect(pem.startsWith(PEM_HEADER)).toBe(true);
    expect(pem.trimEnd().endsWith(PEM_FOOTER)).toBe(true);
    // The DER body is 12-byte prefix + 32 bytes raw = 44 bytes total.
    // Base64-encoded: ceil(44/3)*4 = 60 chars (no padding needed since 44 is divisible by 4? Actually 44 % 3 = 2, so b64 = "...==")
    const body = pem.slice(PEM_HEADER.length, pem.indexOf(PEM_FOOTER)).trim();
    const der = Buffer.from(body, "base64");
    expect(der.length).toBe(44);
    // First 12 bytes are the fixed Ed25519 SPKI DER prefix
    expect(Array.from(der.slice(0, 12))).toEqual([
      0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    // Remaining 32 bytes are the raw key (all zeros in this test)
    expect(Array.from(der.slice(12))).toEqual(new Array(32).fill(0));
  });

  it("rejects raw keys that are not exactly 32 bytes", () => {
    expect(() => ed25519RawToPem(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => ed25519RawToPem(new Uint8Array(33))).toThrow(/32 bytes/);
    expect(() => ed25519RawToPem(new Uint8Array(0))).toThrow(/32 bytes/);
  });

  it("known-vector: round-trips a real Ed25519 pubkey through the wrapper", async () => {
    // Generate a real keypair via Web Crypto, export raw, wrap, then re-import via load_pem-like parse
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const spkiDer = await crypto.subtle.exportKey("spki", (kp as CryptoKeyPair).publicKey);
    const rawBytes = new Uint8Array(spkiDer).slice(12);  // strip the 12-byte SPKI prefix Web Crypto gives us
    expect(rawBytes.length).toBe(32);

    const pem = ed25519RawToPem(rawBytes);
    // Parse the PEM body back to DER and confirm it matches what Web Crypto exported
    const body = pem.slice(PEM_HEADER.length, pem.indexOf(PEM_FOOTER)).trim();
    const reDer = Buffer.from(body, "base64");
    expect(Array.from(reDer)).toEqual(Array.from(new Uint8Array(spkiDer)));
  });
});
