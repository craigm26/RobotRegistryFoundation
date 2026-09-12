/**
 * Test-only helpers for the orchestrator routes. Do NOT import from production
 * handler code. KV mock shape copied from
 * functions/v2/robots/[rrn]/verify-tier.test.ts:9-20.
 */

import { vi } from "vitest";

export function makeEnv(init: Record<string, string> = {}, extra: Record<string, unknown> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
      list: vi.fn(async ({ prefix = "" }: { prefix?: string } = {}) => ({
        keys: Object.keys(store)
          .filter((k) => k.startsWith(prefix))
          .map((name) => ({ name })),
        list_complete: true,
      })),
    } as unknown as KVNamespace,
    __store: store,
    ...extra,
  };
}

export const b64url = (bytes: Uint8Array | ArrayBuffer): string => {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...u8))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

export interface EdKeypair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** SPKI DER, base64 (no PEM framing). */
  spkiB64: string;
  /** SPKI PEM. */
  pem: string;
  /** PKCS8 DER, base64 — the RRF_SIGNING_KEY wire format. */
  pkcs8B64: string;
  /** Raw 32-byte Ed25519 public key (tail of the SPKI DER). */
  rawPublic: Uint8Array;
}

export async function makeEdKeypair(): Promise<EdKeypair> {
  const kp = await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  ) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const spkiB64 = btoa(String.fromCharCode(...spki));
  return {
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
    spkiB64,
    pem: `-----BEGIN PUBLIC KEY-----\n${spkiB64}\n-----END PUBLIC KEY-----\n`,
    pkcs8B64: btoa(String.fromCharCode(...pkcs8)),
    rawPublic: spki.slice(spki.length - 32),
  };
}

/**
 * Build the proof-of-possession headers that
 * functions/v2/_lib/orchestrator-auth.ts requires.
 */
export async function proofHeaders(
  id: string,
  kp: EdKeypair,
  opts: { timestamp?: string; nonce?: string } = {},
): Promise<Record<string, string>> {
  const nonce = opts.nonce ?? b64url(crypto.getRandomValues(new Uint8Array(24)));
  const timestamp = opts.timestamp ?? new Date().toISOString();
  const sig = await crypto.subtle.sign(
    "Ed25519", kp.privateKey, new TextEncoder().encode(`${id}:${nonce}:${timestamp}`),
  );
  return {
    "Authorization":    `Signature ${b64url(sig)}`,
    "X-RRF-Nonce":      nonce,
    "X-RRF-Timestamp":  timestamp,
  };
}

export function orchestratorRecord(
  id: string,
  orchestratorKeyPem: string,
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    id,
    rrn: "RRN-000000000001",
    orchestrator_key: orchestratorKeyPem,
    fleet_rrns: ["RRN-000000000001"],
    justification: "test",
    status: "active",
    consents: { "RRN-000000000001": true },
    registered_at: "2026-09-01T00:00:00Z",
    ...overrides,
  });
}
