// functions/v2/robots/[rrn]/verify-tier.test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./verify-tier.js";
import { makeTestKeypair, makeRobotRecord, signComplianceBody } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000042";
const DOMAIN = "robotis.com";
const RURI = "https://robotis.com";

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

function req(body: unknown): Request {
  return new Request(`https://x/v2/robots/${RRN}/verify-tier`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Option C: stamp pq_kid to match signBody's output for this keypair.
// makeRobotRecord hardcodes pq_kid:"testkid1" which diverges from what
// kidFromPub(kp.mlDsa.publicKey) produces. We fix that by signing a probe
// body and reading the stamped pq_kid back — consistent with signBody's own
// algorithm without coupling to the internal SHA-256 truncation.
async function makeRecordWithModel(kp: Awaited<ReturnType<typeof makeTestKeypair>>, model: string): Promise<string> {
  const rec = JSON.parse(makeRobotRecord(RRN, kp));
  rec.model = model;
  const sample = await signComplianceBody({ probe: true }, kp);
  rec.pq_kid = sample.pq_kid as string;
  return JSON.stringify(rec);
}

describe("POST /v2/robots/[rrn]/verify-tier", () => {
  it("rejects target_tier=community (maintainer-curated, not promotable via API)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "community", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });

  it("400 when target_tier is unknown", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "wizard_tier", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });

  it("promotes to manufacturer_claimed when DNS verifies", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = {
      dns: vi.fn(async () => ({ ok: true, evidence: `rrn=${RRN};model=turtlebot3_burger` })),
      attestation: vi.fn(),
    };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(200);
    const responseBody = await res.json();
    expect(responseBody.api_key).toBeUndefined();
    expect(responseBody.verification_status).toBe("manufacturer_claimed");
    const updated = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(updated.verification_status).toBe("manufacturer_claimed");
    expect(updated.identity_binding).toMatchObject({ type: "dns-txt", value: DOMAIN });
    expect(typeof updated.identity_binding.verified_at).toBe("string");
    expect(verifiers.dns).toHaveBeenCalledWith(DOMAIN, RRN, "turtlebot3_burger");
    expect(verifiers.attestation).not.toHaveBeenCalled();
  });

  it("400 when DNS verifier fails", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = {
      dns: vi.fn(async () => ({ ok: false, error: "TXT record not found" })),
      attestation: vi.fn(),
    };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });

  it("promotes to manufacturer_verified when DNS + attestation both verify", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    // Build the attestation via signComplianceBody so .pq_kid matches record.pq_kid.
    const attestation = await signComplianceBody(
      { rrn: RRN, manufacturer: "ROBOTIS", model: "turtlebot3_burger", timestamp_iso: "2026-04-24T00:00:00Z" },
      kp,
    );
    const signed = await signComplianceBody(
      {
        rrn: RRN, action: "verify-tier", target_tier: "manufacturer_verified",
        binding: { type: "dns-txt", value: DOMAIN },
        ruri: RURI, attestation,
      },
      kp,
    );
    const verifiers = {
      dns: vi.fn(async () => ({ ok: true, evidence: `rrn=${RRN};model=turtlebot3_burger` })),
      attestation: vi.fn(async () => ({
        ok: true,
        evidence: { attestation_digest: "deadbeef", ruri_matched: `${RURI}/.well-known/rcan-manifest.json` },
      })),
    };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(200);
    const updated = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(updated.verification_status).toBe("manufacturer_verified");
    expect(verifiers.dns).toHaveBeenCalled();
    expect(verifiers.attestation).toHaveBeenCalled();
    expect(updated.identity_binding.verifier_evidence).toContain(`attestation=deadbeef`);
    expect(updated.identity_binding.verifier_evidence).toContain(`dns=`);
    expect(updated.identity_binding.verifier_evidence).toContain(`ruri=${RURI}`);
  });

  it("400 on downgrade attempt (current=manufacturer_verified, target=manufacturer_claimed)", async () => {
    const kp = await makeTestKeypair();
    const record = JSON.parse(await makeRecordWithModel(kp, "turtlebot3_burger"));
    record.verification_status = "manufacturer_verified";
    const env = makeEnv({ [`robot:${RRN}`]: JSON.stringify(record) });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });

  it("403 when record is revoked", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({
      [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger"),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-04-24T00:00:00Z", reason: "test" }),
    });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(403);
  });

  it("401 when outer sig does not verify under record's key", async () => {
    const kp = await makeTestKeypair();
    const attackerKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      attackerKp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(401);
  });

  it("400 when manufacturer_verified request is missing ruri or attestation", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_verified", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });

  it("409 when record has an unrecognized verification_status (legacy tier)", async () => {
    const kp = await makeTestKeypair();
    const record = JSON.parse(await makeRecordWithModel(kp, "turtlebot3_burger"));
    record.verification_status = "certified";  // legacy tier from older enum
    const env = makeEnv({ [`robot:${RRN}`]: JSON.stringify(record) });
    const signed = await signComplianceBody(
      { rrn: RRN, action: "verify-tier", target_tier: "manufacturer_claimed", binding: { type: "dns-txt", value: DOMAIN } },
      kp,
    );
    const verifiers = { dns: vi.fn(), attestation: vi.fn() };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(409);
  });

  it("400 when manufacturer_verified attestation.pq_kid does not match record.pq_kid", async () => {
    const kp = await makeTestKeypair();
    const otherKp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: await makeRecordWithModel(kp, "turtlebot3_burger") });
    // Attestation signed by otherKp, so its pq_kid will differ from record's pq_kid.
    const attestation = await signComplianceBody(
      { rrn: RRN, manufacturer: "ROBOTIS", model: "turtlebot3_burger", timestamp_iso: "2026-04-24T00:00:00Z" },
      otherKp,
    );
    const signed = await signComplianceBody(
      {
        rrn: RRN, action: "verify-tier", target_tier: "manufacturer_verified",
        binding: { type: "dns-txt", value: DOMAIN },
        ruri: RURI, attestation,
      },
      kp,
    );
    const verifiers = {
      dns: vi.fn(async () => ({ ok: true, evidence: `rrn=${RRN};model=turtlebot3_burger` })),
      attestation: vi.fn(async () => ({ ok: true, evidence: { attestation_digest: "x", ruri_matched: RURI } })),
    };
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN }, verifiers } as any);
    expect(res.status).toBe(400);
  });
});
