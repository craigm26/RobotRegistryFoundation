// functions/v2/_lib/attestation-verify.test.ts
import { describe, it, expect, vi } from "vitest";
import { verifyAttestation } from "./attestation-verify.js";
import { makeTestKeypair, signComplianceBody } from "./test-helpers.js";

const RRN = "RRN-000000000042";
const MODEL = "turtlebot3_burger";
const RURI = "https://robotis.com";
const NOW_MS = Date.parse("2026-04-25T00:00:00Z");

function pubB64(kp: any): string {
  return btoa(String.fromCharCode(...kp.mlDsa.publicKey));
}

async function buildAttestation(kp: any, overrides: Record<string, unknown> = {}) {
  const body = {
    rrn: RRN, manufacturer: "ROBOTIS", model: MODEL,
    timestamp_iso: "2026-04-24T12:00:00Z",
    ...overrides,
  };
  return await signComplianceBody(body, kp);
}

function okManifestFetch(rrn: string) {
  return vi.fn(async () => new Response(JSON.stringify({ rrn }), { status: 200 }));
}

describe("verifyAttestation", () => {
  it("accepts a valid attestation + matching RURI manifest", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp);
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.evidence.attestation_digest).toMatch(/^[0-9a-f]{64}$/);
      expect(res.evidence.ruri_matched).toBe(`${RURI}/.well-known/rcan-manifest.json`);
    }
  });

  it("rejects tampered attestation (sig no longer verifies)", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp);
    // Tamper AFTER signing; sig now covers different bytes than the body.
    (att as any).manufacturer = "evil-inc";
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/sig/i);
  });

  it("rejects when attestation.rrn does not match expectedRrn", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp, { rrn: "RRN-000000000999" });
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/rrn/i);
  });

  it("rejects when attestation.model does not match expectedModel", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp, { model: "some-other-model" });
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/model/i);
  });

  it("rejects an attestation older than 1 year", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp, { timestamp_iso: "2024-01-01T00:00:00Z" });
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/expire|stale|old/i);
  });

  it("rejects an attestation timestamped in the future (> 60s skew)", async () => {
    const kp = await makeTestKeypair();
    const futureIso = new Date(NOW_MS + 120_000).toISOString();
    const att = await buildAttestation(kp, { timestamp_iso: futureIso });
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch(RRN),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/future|skew/i);
  });

  it("rejects when RURI manifest is unreachable (fetch throws)", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp);
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: vi.fn(async () => { throw new TypeError("fetch failed"); }),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/unreachable/i);
  });

  it("rejects when RURI manifest rrn does not match", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp);
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: okManifestFetch("RRN-000000000999"),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/manifest/i);
  });

  it("rejects when RURI returns non-200", async () => {
    const kp = await makeTestKeypair();
    const att = await buildAttestation(kp);
    const res = await verifyAttestation({
      attestation: att as any, ruri: RURI, pqPubB64: pubB64(kp),
      expectedRrn: RRN, expectedModel: MODEL,
      fetchFn: vi.fn(async () => new Response("", { status: 404 })),
      nowMs: NOW_MS,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/manifest|404/i);
  });
});
