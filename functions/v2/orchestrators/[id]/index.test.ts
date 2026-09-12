// functions/v2/orchestrators/[id]/index.test.ts
import { describe, it, expect } from "vitest";
import { onRequest } from "./index.js";
import { makeEnv, makeEdKeypair, orchestratorRecord } from "../_orch-test-helpers.js";

const ID = "orch-testtesttest03";
const ADMIN = "admin-token-under-test";

function req(auth?: string): Request {
  return new Request(`https://x/v2/orchestrators/${ID}`, {
    method: "DELETE",
    headers: auth ? { Authorization: auth } : {},
  });
}

const call = (env: unknown, request: Request) =>
  onRequest({ request, env, params: { id: ID } } as any);

async function envWithRecord(extra: Record<string, unknown> = {}) {
  const orchKp = await makeEdKeypair();
  return makeEnv({ [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem) }, extra);
}

describe("DELETE /v2/orchestrators/[id]", () => {
  it("401s a junk bearer (not 200, not 404) and revokes nothing", async () => {
    const env = await envWithRecord({ RRF_ADMIN_TOKEN: ADMIN });
    const res = await call(env, req("Bearer junk"));
    expect(res.status).toBe(401);
    const stored = JSON.parse((env as any).__store[`orchestrator:${ID}`]);
    expect(stored.status).toBe("active");
  });

  it("401s with no Authorization header", async () => {
    const env = await envWithRecord({ RRF_ADMIN_TOKEN: ADMIN });
    const res = await call(env, req());
    expect(res.status).toBe(401);
  });

  it("401s when RRF_ADMIN_TOKEN is unbound", async () => {
    const env = await envWithRecord();
    const res = await call(env, req(`Bearer ${ADMIN}`));
    expect(res.status).toBe(401);
  });

  it("401s a junk bearer on an id that does not exist (no existence oracle)", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await call(env, req("Bearer junk"));
    expect(res.status).toBe(401);
  });

  it("revokes with the admin token and publishes to the revocation list", async () => {
    const env = await envWithRecord({ RRF_ADMIN_TOKEN: ADMIN });
    const res = await call(env, req(`Bearer ${ADMIN}`));
    expect(res.status).toBe(200);
    const stored = JSON.parse((env as any).__store[`orchestrator:${ID}`]);
    expect(stored.status).toBe("revoked");
    const revocations = JSON.parse((env as any).__store["revocations"]);
    expect(revocations.revoked_orchestrators).toContain(ID);
  });
});
