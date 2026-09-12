// functions/v2/orchestrators/register.test.ts
import { describe, it, expect } from "vitest";
import { onRequest } from "./register.js";
import { makeEnv, makeEdKeypair } from "./_orch-test-helpers.js";

const ADMIN = "admin-token-under-test";

function req(body: unknown, auth?: string): Request {
  return new Request("https://x/v2/orchestrators/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(auth ? { Authorization: auth } : {}),
    },
    body: JSON.stringify(body),
  });
}

async function validBody() {
  const kp = await makeEdKeypair();
  return {
    rrn: "RRN-000000000001",
    orchestrator_key: kp.pem,
    fleet_rrns: ["RRN-000000000002"],
    justification: "fleet coordination",
  };
}

describe("POST /v2/orchestrators/register", () => {
  it("401s a junk bearer (not 201, not 404)", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await onRequest({ request: req(await validBody(), "Bearer junk"), env } as any);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect((env as any).__store).toEqual({});
  });

  it("401s when no Authorization header is present", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await onRequest({ request: req(await validBody()), env } as any);
    expect(res.status).toBe(401);
  });

  it("401s when RRF_ADMIN_TOKEN is unbound, even with a well-formed bearer", async () => {
    // Fail closed: an unbound admin token must not mean "anything goes".
    const env = makeEnv({});
    const res = await onRequest({ request: req(await validBody(), "Bearer junk"), env } as any);
    expect(res.status).toBe(401);
  });

  it("401 is decided before the body is validated", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await onRequest({ request: req({}, "Bearer junk"), env } as any);
    expect(res.status).toBe(401);
  });

  it("accepts the admin token and records deployed_by/host as declared", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const body = { ...(await validBody()), deployed_by: "ops@example.org", host: "orch-1.example.org" };
    const res = await onRequest({ request: req(body, `Bearer ${ADMIN}`), env } as any);
    expect(res.status).toBe(201);
    const out = await res.json() as any;
    const stored = JSON.parse((env as any).__store[`orchestrator:${out.orchestrator_id}`]);
    expect(stored.status).toBe("pending_consent");
    expect(stored.deployed_by).toBe("ops@example.org");
    expect(stored.host).toBe("orch-1.example.org");
    expect(stored.declared_fields).toEqual(["deployed_by", "host"]);
  });

  it("omits declared_fields entirely when nothing was declared", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await onRequest({ request: req(await validBody(), `Bearer ${ADMIN}`), env } as any);
    expect(res.status).toBe(201);
    const out = await res.json() as any;
    const stored = JSON.parse((env as any).__store[`orchestrator:${out.orchestrator_id}`]);
    expect(stored.declared_fields).toBeUndefined();
    expect(stored.deployed_by).toBeUndefined();
  });

  it("still 400s a bad body once authenticated", async () => {
    const env = makeEnv({}, { RRF_ADMIN_TOKEN: ADMIN });
    const res = await onRequest({ request: req({ rrn: "nope" }, `Bearer ${ADMIN}`), env } as any);
    expect(res.status).toBe(400);
  });
});
