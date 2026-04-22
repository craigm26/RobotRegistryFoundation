import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

export type HybridSig = {
  ml_dsa: string;       // base64 ML-DSA-65 signature
  ed25519: string;      // base64 Ed25519 signature (64 bytes raw)
  ed25519_pub: string;  // base64 Ed25519 public key (32 bytes raw)
};

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

export function canonicalJson(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortKeys(obj)));
}

function b64(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64"));
}

export async function verifyHybrid(
  ml_dsa_pub_b64: string,
  sig: HybridSig,
  message: Uint8Array,
): Promise<boolean> {
  try {
    // ML-DSA-65 via @noble/post-quantum — IMPORTANT: verify(sig, msg, pubkey) order
    const mlDsaOk = ml_dsa65.verify(b64(sig.ml_dsa), message, b64(ml_dsa_pub_b64));
    if (!mlDsaOk) return false;

    // Ed25519 via WebCrypto (Node's webcrypto or Cloudflare Workers)
    const subtle = (globalThis.crypto ?? (await import("node:crypto")).webcrypto).subtle;
    const edKey = await subtle.importKey(
      "raw", b64(sig.ed25519_pub), { name: "Ed25519" }, false, ["verify"],
    );
    const edOk = await subtle.verify(
      "Ed25519", edKey, b64(sig.ed25519), message,
    );
    return edOk;
  } catch {
    return false;
  }
}
