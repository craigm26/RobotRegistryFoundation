// functions/v2/orchestrators/[id]/token.test.ts
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { onRequest, buildSignedJWT } from "./token.js";
import { verifyM2mTrustedJwt } from "../../_lib/jwt-verify.js";
import {
  makeEnv, makeEdKeypair, proofHeaders, orchestratorRecord, b64url,
} from "../_orch-test-helpers.js";

const ID = "orch-testtesttest01";
const RRN = "RRN-000000000001";

function req(headers: Record<string, string> = {}): Request {
  return new Request(`https://x/v2/orchestrators/${ID}/token`, { method: "GET", headers });
}

const call = (env: unknown, request: Request) =>
  onRequest({ request, env, params: { id: ID } } as any);

describe("GET /v2/orchestrators/[id]/token — authentication", () => {
  it("401s a junk bearer on an id that exists (not 200)", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const res = await call(env, req({ Authorization: "Bearer junk" }));
    expect(res.status).toBe(401);
  });

  it("401s a junk bearer on an id that does NOT exist (not 404 — no existence oracle)", async () => {
    const signKp = await makeEdKeypair();
    const env = makeEnv({}, { RRF_SIGNING_KEY: signKp.pkcs8B64 });
    const res = await call(env, req({ Authorization: "Bearer junk" }));
    expect(res.status).toBe(401);
    expect((await res.json() as any).error).not.toMatch(/not found/i);
  });

  it("401s a valid proof for a DIFFERENT key than the record stores", async () => {
    const orchKp = await makeEdKeypair();
    const attackerKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const res = await call(env, req(await proofHeaders(ID, attackerKp)));
    expect(res.status).toBe(401);
  });

  it("401s a proof whose timestamp is outside the 300 s window", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const stale = new Date(Date.now() - 3600_000).toISOString();
    const res = await call(env, req(await proofHeaders(ID, orchKp, { timestamp: stale })));
    expect(res.status).toBe(401);
  });

  it("401s a proof with a short nonce", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const shortNonce = b64url(crypto.getRandomValues(new Uint8Array(8)));
    const res = await call(env, req(await proofHeaders(ID, orchKp, { nonce: shortNonce })));
    expect(res.status).toBe(401);
  });

  it("401s a signature bound to a different orchestrator id", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const res = await call(env, req(await proofHeaders("orch-someotherid00", orchKp)));
    expect(res.status).toBe(401);
  });

  it("403s a non-active orchestrator even with a valid proof", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      { [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem, { status: "pending_consent" }) },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );
    const res = await call(env, req(await proofHeaders(ID, orchKp)));
    expect(res.status).toBe(403);
  });
});

describe("GET /v2/orchestrators/[id]/token — fail closed without a signing key", () => {
  it("503s when RRF_SIGNING_KEY is unset, and mints nothing", async () => {
    const orchKp = await makeEdKeypair();
    const env = makeEnv({ [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) });
    const res = await call(env, req(await proofHeaders(ID, orchKp)));
    expect(res.status).toBe(503);
    const body = await res.json() as any;
    expect(body.error).toMatch(/not configured/i);
    expect(body.token).toBeUndefined();
  });

  it("buildSignedJWT throws rather than emit an unsigned token", async () => {
    await expect(buildSignedJWT({ sub: "x" }, "")).rejects.toThrow(/RRF_SIGNING_KEY is required/);
  });
});

describe("GET /v2/orchestrators/[id]/token — the minted token is a standard JWS", () => {
  it("verifies with an independent @noble/curves ed25519 over `${seg1}.${seg2}` AND with verifyM2mTrustedJwt", async () => {
    const orchKp = await makeEdKeypair();
    const signKp = await makeEdKeypair();
    const env = makeEnv(
      {
        [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem),
        "rrf:root:pubkey": signKp.pem,
      },
      { RRF_SIGNING_KEY: signKp.pkcs8B64 },
    );

    const res = await call(env, req(await proofHeaders(ID, orchKp)));
    expect(res.status).toBe(200);
    const out = await res.json() as any;
    const token = out.token as string;

    const [seg1, seg2, seg3] = token.split(".");
    expect(seg3).toBeTruthy();

    // 1. Independent verifier: @noble/curves, raw Ed25519 pubkey, signing input
    //    is exactly the first two segments as transmitted.
    const fromB64Url = (s: string) => {
      const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
      return Uint8Array.from(atob(b64 + pad), (c) => c.charCodeAt(0));
    };
    const nobleOk = ed25519.verify(
      fromB64Url(seg3),
      new TextEncoder().encode(`${seg1}.${seg2}`),
      signKp.rawPublic,
    );
    expect(nobleOk).toBe(true);

    // 2. The registry's own verifier accepts the same token.
    const verifyRes = await verifyM2mTrustedJwt(
      env as any,
      new Request("https://x/v2/compliance-bundle/b1", {
        headers: { Authorization: `Bearer ${token}` },
      }),
      RRN,
    );
    expect(verifyRes.ok).toBe(true);

    // 3. The signature no longer hides inside the signed payload.
    const payload = JSON.parse(new TextDecoder().decode(fromB64Url(seg2)));
    expect(payload.rrf_sig).toBeUndefined();
    expect(payload.rcan_role).toBe("m2m_trusted");
    expect(payload.iss).toBe("rrf.rcan.dev");

    // 4. Tampering with the payload breaks both verifiers.
    const tampered = { ...payload, fleet_rrns: ["RRN-999999999999"] };
    const tamperedSeg2 = btoa(JSON.stringify(tampered))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const tamperedRes = await verifyM2mTrustedJwt(
      env as any,
      new Request("https://x/v2/compliance-bundle/b1", {
        headers: { Authorization: `Bearer ${seg1}.${tamperedSeg2}.${seg3}` },
      }),
      RRN,
    );
    expect(tamperedRes.ok).toBe(false);
  });
});
