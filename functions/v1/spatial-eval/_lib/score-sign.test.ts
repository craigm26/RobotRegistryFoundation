import { describe, it, expect } from "vitest";
import { generateMlDsaKeypair, verifyMlDsa } from "rcan-ts";
import { counterSignScore } from "./score-sign.js";
import { payloadBytes } from "./score-canonical.js";

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

const MIN_SCORE = {
  spec_version: "1.0.0",
  rrn: "RRN-000000000002",
  run_id: "r-1",
  rcan_signature: "rcan-sig",
  rrf_signature: null,
};

describe("counterSignScore", () => {
  it("signs and produces a verifiable rrf_signature", () => {
    const kp = generateMlDsaKeypair();
    const env = { RRF_SPATIAL_EVAL_PQ_PRIV: toBase64(kp.privateKey) };
    const out = counterSignScore({ ...MIN_SCORE }, env);
    const sig = Uint8Array.from(atob(out.rrf_signature as string), (c) =>
      c.charCodeAt(0),
    );
    expect(verifyMlDsa(kp.publicKey, payloadBytes(out), sig)).toBe(true);
  });

  it("trims a trailing newline from the secret before decoding", () => {
    // Reproduces the production bug where `cat priv.txt | wrangler secret put`
    // captured a trailing \n, which atob() then rejected.
    const kp = generateMlDsaKeypair();
    const env = { RRF_SPATIAL_EVAL_PQ_PRIV: toBase64(kp.privateKey) + "\n" };
    expect(() => counterSignScore({ ...MIN_SCORE }, env)).not.toThrow();
  });

  it("trims surrounding whitespace generally", () => {
    const kp = generateMlDsaKeypair();
    const env = {
      RRF_SPATIAL_EVAL_PQ_PRIV: "  \n\t" + toBase64(kp.privateKey) + "\r\n  ",
    };
    expect(() => counterSignScore({ ...MIN_SCORE }, env)).not.toThrow();
  });

  it("throws when the secret is unset", () => {
    expect(() => counterSignScore({ ...MIN_SCORE }, {})).toThrow(
      /RRF_SPATIAL_EVAL_PQ_PRIV secret is not set/,
    );
  });
});
