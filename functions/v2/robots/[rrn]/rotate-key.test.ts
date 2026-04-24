import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./rotate-key.js";
import { makeTestKeypair, makeRobotRecord, signComplianceBody, type TestKeypair } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000042";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
      list: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function req(body: unknown, urlRrn: string = RRN): Request {
  return new Request(`https://x/v2/robots/${urlRrn}/rotate-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function buildRotateRequest(oldKp: TestKeypair, newKp: TestKeypair, urlRrn: string = RRN) {
  // Canonical body each signer commits to (before signBody adds pq_signing_pub / pq_kid).
  // Sign TWICE with the SAME canonical doc; each signer contributes their own identity fields.
  const canonical = {
    rrn: urlRrn,
    action: "rotate" as const,
    new_pq_signing_pub: btoa(String.fromCharCode(...newKp.mlDsa.publicKey)),
    new_pq_kid: "testkid-new",  // signer-picked label; server does not verify this matches anything.
  };
  const by_old_key = await signComplianceBody(canonical, oldKp);
  const by_new_key = await signComplianceBody(canonical, newKp);
  return { by_old_key, by_new_key };
}

describe("POST /v2/robots/[rrn]/rotate-key", () => {
  it("400 on invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: req({}, "bad"), env, params: { rrn: "bad" } } as any);
    expect(res.status).toBe(400);
  });

  it("404 when record does not exist", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const env = makeEnv();
    const body = await buildRotateRequest(oldKp, newKp);
    const res = await onRequestPost({ request: req(body), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });

  it("403 when record is revoked", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const env = makeEnv({
      [`robot:${RRN}`]: makeRobotRecord(RRN, oldKp),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-04-24T00:00:00Z", reason: "test" }),
    });
    const body = await buildRotateRequest(oldKp, newKp);
    const res = await onRequestPost({ request: req(body), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(403);
  });

  it("400 when envelopes disagree on new_pq_signing_pub", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const otherKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, oldKp) });
    const by_old_key = await signComplianceBody({
      rrn: RRN, action: "rotate",
      new_pq_signing_pub: btoa(String.fromCharCode(...newKp.mlDsa.publicKey)),
      new_pq_kid: "testkid-new",
    }, oldKp);
    const by_new_key = await signComplianceBody({
      rrn: RRN, action: "rotate",
      new_pq_signing_pub: btoa(String.fromCharCode(...otherKp.mlDsa.publicKey)),  // DIFFERENT
      new_pq_kid: "testkid-new",
    }, otherKp);
    const res = await onRequestPost({ request: req({ by_old_key, by_new_key }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 when new_pq_signing_pub equals current record key", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const body = await buildRotateRequest(kp, kp);
    const res = await onRequestPost({ request: req(body), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("401 when by_old_key is signed by a non-current key", async () => {
    const realCurrent = await makeTestKeypair();
    const attackerKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, realCurrent) });
    const body = await buildRotateRequest(attackerKp, newKp);  // by_old_key signed by attacker, not realCurrent
    const res = await onRequestPost({ request: req(body), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 when by_new_key is signed by something other than the declared new key", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const otherKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, oldKp) });
    const by_old_key = await signComplianceBody({
      rrn: RRN, action: "rotate",
      new_pq_signing_pub: btoa(String.fromCharCode(...newKp.mlDsa.publicKey)),
      new_pq_kid: "testkid-new",
    }, oldKp);
    // by_new_key declares newKp but is actually signed by otherKp — signComplianceBody will stamp
    // otherKp's pq_signing_pub into the envelope, which won't equal the declared new_pq_signing_pub.
    const by_new_key = await signComplianceBody({
      rrn: RRN, action: "rotate",
      new_pq_signing_pub: btoa(String.fromCharCode(...newKp.mlDsa.publicKey)),
      new_pq_kid: "testkid-new",
    }, otherKp);
    const res = await onRequestPost({ request: req({ by_old_key, by_new_key }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 when either envelope is missing", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, oldKp) });
    const { by_old_key } = await buildRotateRequest(oldKp, newKp);
    const res = await onRequestPost({ request: req({ by_old_key }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("rotates on valid co-signed request (200) and appends to rotations[]", async () => {
    const oldKp = await makeTestKeypair();
    const newKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, oldKp) });
    const body = await buildRotateRequest(oldKp, newKp);
    const res = await onRequestPost({ request: req(body), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    const updated = await res.json();
    const newPubB64 = btoa(String.fromCharCode(...newKp.mlDsa.publicKey));
    expect(updated.pq_signing_pub).toBe(newPubB64);
    expect(updated.pq_kid).toBe("testkid-new");
    expect(Array.isArray(updated.rotations)).toBe(true);
    expect(updated.rotations).toHaveLength(1);
    expect(updated.rotations[0].new_pq_kid).toBe("testkid-new");
    expect(updated.updated_at).toBeTypeOf("string");
  });

  it("appends (not overwrites) rotations[] across multiple rotations", async () => {
    const k0 = await makeTestKeypair();
    const k1 = await makeTestKeypair();
    const k2 = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, k0) });
    await onRequestPost({ request: req(await buildRotateRequest(k0, k1)), env, params: { rrn: RRN } } as any);
    // After rotate 1, record's pq_signing_pub is now k1's pub. Next rotate's buildRotateRequest
    // signs by_old_key with k1 (the new current) and by_new_key with k2.
    await onRequestPost({ request: req(await buildRotateRequest(k1, k2)), env, params: { rrn: RRN } } as any);
    const final = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(final.rotations).toHaveLength(2);
    expect(final.pq_signing_pub).toBe(btoa(String.fromCharCode(...k2.mlDsa.publicKey)));
  });
});
