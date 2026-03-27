var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// v2/orchestrators/[id]/consent.ts
var onRequest = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  const id = params["id"];
  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json({ error: "Authorization required (CREATOR token)" }, 401);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }
  const { rrn, grant } = body;
  if (!rrn || typeof grant !== "boolean") {
    return json({ error: "Missing required fields: rrn (string), grant (boolean)" }, 400);
  }
  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json({ error: "Orchestrator not found", id }, 404);
  }
  const record = JSON.parse(stored);
  if (!record.fleet_rrns.includes(rrn)) {
    return json({ error: `RRN '${rrn}' is not in this orchestrator's fleet_rrns` }, 403);
  }
  if (record.status === "revoked") {
    return json({ error: "Orchestrator is already revoked" }, 409);
  }
  record.consents[rrn] = grant;
  if (!grant) {
    record.status = "revoked";
    record.revoked_at = (/* @__PURE__ */ new Date()).toISOString();
    await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record));
    await addToRevocationList(env, id);
    return json({
      ok: true,
      status: "revoked",
      message: `Orchestrator '${id}' revoked \u2014 consent denied by '${rrn}'`,
      revoked_at: record.revoked_at
    });
  }
  const allConsented = record.fleet_rrns.every((r) => record.consents[r] === true);
  if (allConsented) {
    record.status = "active";
    record.activated_at = (/* @__PURE__ */ new Date()).toISOString();
  }
  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record));
  if (allConsented) {
    return json({
      ok: true,
      status: "active",
      orchestrator_id: id,
      message: "All owners consented \u2014 orchestrator activated. Use GET /v2/orchestrators/:id/token to issue tokens.",
      activated_at: record.activated_at
    });
  }
  const remaining = record.fleet_rrns.filter((r) => record.consents[r] !== true);
  return json({
    ok: true,
    status: "pending_consent",
    orchestrator_id: id,
    consented_by: rrn,
    remaining_consent_from: remaining
  });
}, "onRequest");
async function addToRevocationList(env, orchestratorId) {
  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored ? JSON.parse(stored) : { revoked_orchestrators: [], revoked_jtis: [] };
  if (!list.revoked_orchestrators.includes(orchestratorId)) {
    list.revoked_orchestrators.push(orchestratorId);
  }
  await env.RRF_KV.put("revocations", JSON.stringify(list));
}
__name(addToRevocationList, "addToRevocationList");
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
__name(json, "json");

// v2/orchestrators/[id]/token.ts
var onRequest2 = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  const id = params["id"];
  if (request.method !== "GET") {
    return json2({ error: "Method not allowed" }, 405);
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json2({ error: "Authorization required" }, 401);
  }
  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json2({ error: "Orchestrator not found", id }, 404);
  }
  const record = JSON.parse(stored);
  if (record.status !== "active") {
    return json2({
      error: `Orchestrator status is '${record.status}' \u2014 token only issued for active orchestrators`,
      status: record.status
    }, 403);
  }
  const now = Math.floor(Date.now() / 1e3);
  const exp = now + 86400;
  const payload = {
    sub: id,
    iss: "rrf.rcan.dev",
    iat: now,
    exp,
    rcan_role: "m2m_trusted",
    rcan_scopes: ["fleet.trusted"],
    fleet_rrns: record.fleet_rrns,
    rrf_sig: ""
    // will be filled in after signing
  };
  const token = await buildSignedJWT(payload, env.RRF_SIGNING_KEY);
  return json2({
    ok: true,
    token,
    exp,
    fleet_rrns: record.fleet_rrns,
    iss: "rrf.rcan.dev",
    note: "Token valid for 24h. Re-issue before expiry."
  });
}, "onRequest");
async function buildSignedJWT(payload, signingKey) {
  const header = { alg: "EdDSA", typ: "JWT" };
  const b64url = /* @__PURE__ */ __name((s) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""), "b64url");
  const encode = /* @__PURE__ */ __name((obj) => b64url(JSON.stringify(obj)), "encode");
  const { rrf_sig: _, ...payloadWithoutSig } = payload;
  const signingInput = `${encode(header)}.${encode(payloadWithoutSig)}`;
  let sig;
  if (signingKey) {
    const b64std = signingKey.replace(/-/g, "+").replace(/_/g, "/");
    const b64padded = b64std + "==".slice(0, (4 - b64std.length % 4) % 4);
    const keyBytes = Uint8Array.from(atob(b64padded), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    const encoder = new TextEncoder();
    const sigBuffer = await crypto.subtle.sign("Ed25519", key, encoder.encode(signingInput));
    sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  } else {
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest("SHA-256", encoder.encode(signingInput));
    sig = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  const finalPayload = { ...payloadWithoutSig, rrf_sig: sig };
  return `${encode(header)}.${encode(finalPayload)}.${sig}`;
}
__name(buildSignedJWT, "buildSignedJWT");
function json2(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
__name(json2, "json");

// v2/robots/[rrn]/firmware-manifest.ts
var onRequest3 = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  const rrn = params["rrn"];
  if (!rrn || !rrn.match(/^RRN-[0-9]{12}$/)) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (request.method === "GET") {
    return handleGet(env, rrn);
  }
  if (request.method === "POST") {
    return handlePost(request, env, rrn);
  }
  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { "Content-Type": "application/json" }
  });
}, "onRequest");
async function handleGet(env, rrn) {
  const key = `firmware:manifest:${rrn}`;
  const stored = await env.RRF_KV.get(key, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Firmware manifest not found", rrn }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  return new Response(stored, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300"
    }
  });
}
__name(handleGet, "handleGet");
async function handlePost(request, env, rrn) {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Authorization required" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let manifest;
  try {
    manifest = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (!manifest.rrn || !manifest.firmware_version || !manifest.build_hash || !manifest.signature) {
    return new Response(
      JSON.stringify({
        error: "Missing required fields: rrn, firmware_version, build_hash, signature"
      }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  if (manifest.rrn !== rrn) {
    return new Response(
      JSON.stringify({ error: "Manifest rrn does not match URL rrn" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  if (typeof manifest.build_hash !== "string" || !manifest.build_hash.startsWith("sha256:")) {
    return new Response(
      JSON.stringify({ error: "build_hash must start with 'sha256:'" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const key = `firmware:manifest:${rrn}`;
  const stored = JSON.stringify({
    ...manifest,
    submitted_at: (/* @__PURE__ */ new Date()).toISOString()
  });
  await env.RRF_KV.put(key, stored, { expirationTtl: 365 * 24 * 3600 });
  const historyKey = `firmware:history:${rrn}:${Date.now()}`;
  await env.RRF_KV.put(historyKey, stored, { expirationTtl: 365 * 24 * 3600 * 3 });
  return new Response(
    JSON.stringify({
      ok: true,
      rrn,
      submitted_at: (/* @__PURE__ */ new Date()).toISOString(),
      manifest_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/firmware-manifest`
    }),
    { status: 201, headers: { "Content-Type": "application/json" } }
  );
}
__name(handlePost, "handlePost");

// v2/robots/[rrn]/sbom.ts
var onRequest4 = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  const rrn = params["rrn"];
  if (!rrn || !rrn.match(/^RRN-[0-9]{12}$/)) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (request.method === "GET") return handleGet2(env, rrn);
  if (request.method === "POST") return handlePost2(request, env, rrn);
  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { "Content-Type": "application/json" }
  });
}, "onRequest");
async function handleGet2(env, rrn) {
  const key = `sbom:${rrn}`;
  const stored = await env.RRF_KV.get(key, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "SBOM not found", rrn }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }
  return new Response(stored, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300"
    }
  });
}
__name(handleGet2, "handleGet");
async function handlePost2(request, env, rrn) {
  try {
    return await _handlePost(request, env, rrn);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return new Response(JSON.stringify({ error: "Internal error", detail: msg }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
__name(handlePost2, "handlePost");
async function _handlePost(request, env, rrn) {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Authorization required" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  let sbom;
  try {
    sbom = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  if (sbom.bomFormat !== "CycloneDX") {
    return new Response(JSON.stringify({ error: "bomFormat must be 'CycloneDX'" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  const rcanExt = sbom["x-rcan"];
  if (!rcanExt || rcanExt.rrn !== rrn) {
    return new Response(
      JSON.stringify({ error: "x-rcan.rrn must match URL rrn" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const canonicalJson = JSON.stringify({ ...sbom, rrf_countersig: void 0 });
  const countersig = await signWithRRFKey(canonicalJson, env.RRF_SIGNING_KEY);
  const countersignedSbom = {
    ...sbom,
    "x-rcan": {
      ...rcanExt,
      rrf_countersig: countersig,
      rrf_countersigned_at: (/* @__PURE__ */ new Date()).toISOString()
    },
    rrf_submitted_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  const stored = JSON.stringify(countersignedSbom);
  await env.RRF_KV.put(`sbom:${rrn}`, stored, { expirationTtl: 365 * 24 * 3600 });
  await env.RRF_KV.put(`sbom:history:${rrn}:${Date.now()}`, stored, {
    expirationTtl: 365 * 24 * 3600 * 3
  });
  return new Response(
    JSON.stringify({
      ok: true,
      rrn,
      rrf_countersig: countersig,
      sbom_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/sbom`,
      countersigned_at: (/* @__PURE__ */ new Date()).toISOString()
    }),
    { status: 201, headers: { "Content-Type": "application/json" } }
  );
}
__name(_handlePost, "_handlePost");
async function signWithRRFKey(data, signingKey) {
  if (!signingKey) {
    const encoder2 = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder2.encode(data));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  const b64std = signingKey.replace(/-/g, "+").replace(/_/g, "/");
  const b64padded = b64std + "==".slice(0, (4 - b64std.length % 4) % 4);
  const keyBytes = Uint8Array.from(atob(b64padded), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const encoder = new TextEncoder();
  const sig = await crypto.subtle.sign("Ed25519", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
__name(signWithRRFKey, "signWithRRFKey");

// ../node_modules/nanoid/url-alphabet/index.js
var urlAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

// ../node_modules/nanoid/index.browser.js
var nanoid = /* @__PURE__ */ __name((size = 21) => {
  let id = "";
  let bytes = crypto.getRandomValues(new Uint8Array(size |= 0));
  while (size--) {
    id += urlAlphabet[bytes[size] & 63];
  }
  return id;
}, "nanoid");

// v2/orchestrators/register.ts
var onRequest5 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  if (request.method !== "POST") {
    return json3({ error: "Method not allowed" }, 405);
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json3({ error: "Authorization required (CREATOR token)" }, 401);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json3({ error: "Invalid JSON body" }, 400);
  }
  const { rrn, orchestrator_key, fleet_rrns, justification } = body;
  if (!rrn || !orchestrator_key || !fleet_rrns || !justification) {
    return json3(
      { error: "Missing required fields: rrn, orchestrator_key, fleet_rrns, justification" },
      400
    );
  }
  if (!Array.isArray(fleet_rrns) || fleet_rrns.length === 0) {
    return json3({ error: "fleet_rrns must be a non-empty array" }, 400);
  }
  if (fleet_rrns.length > 50) {
    return json3({ error: "fleet_rrns may not exceed 50 robots" }, 400);
  }
  const rrn_re = /^RRN-[0-9]{12}$/;
  for (const r of [rrn, ...fleet_rrns]) {
    if (!rrn_re.test(r)) {
      return json3({ error: `Invalid RRN format: ${r}` }, 400);
    }
  }
  const id = `orch-${nanoid(16)}`;
  const record = {
    id,
    rrn,
    orchestrator_key,
    fleet_rrns,
    justification,
    status: "pending_consent",
    consents: Object.fromEntries(fleet_rrns.map((r) => [r, false])),
    registered_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record), {
    expirationTtl: 90 * 24 * 3600
  });
  for (const fleetRrn of fleet_rrns) {
    const consentKey = `consent:pending:${fleetRrn}:${id}`;
    await env.RRF_KV.put(consentKey, JSON.stringify({
      orchestrator_id: id,
      requesting_rrn: rrn,
      fleet_rrns,
      justification,
      requested_at: (/* @__PURE__ */ new Date()).toISOString()
    }), { expirationTtl: 7 * 24 * 3600 });
  }
  return json3({
    ok: true,
    orchestrator_id: id,
    status: "pending_consent",
    consent_required_from: fleet_rrns,
    registered_at: record.registered_at,
    message: `Consent requests sent to ${fleet_rrns.length} robot owner(s). Token will be issued when all owners consent.`
  }, 201);
}, "onRequest");
function json3(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
__name(json3, "json");

// v2/orchestrators/[id]/index.ts
var onRequest6 = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  const id = params["id"];
  if (request.method !== "DELETE") {
    return json4({ error: "Method not allowed" }, 405);
  }
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json4({ error: "Authorization required" }, 401);
  }
  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json4({ error: "Orchestrator not found", id }, 404);
  }
  const record = JSON.parse(stored);
  if (record.status === "revoked") {
    return json4({ error: "Orchestrator already revoked", id, revoked_at: record.revoked_at }, 409);
  }
  record.status = "revoked";
  record.revoked_at = (/* @__PURE__ */ new Date()).toISOString();
  await env.RRF_KV.put(`orchestrator:${id}`, JSON.stringify(record), {
    expirationTtl: 90 * 24 * 3600
  });
  await addToRevocationList2(env, id);
  return json4({
    ok: true,
    revoked: id,
    revoked_at: record.revoked_at,
    message: "Orchestrator revoked. Active sessions will be terminated within 60 seconds."
  });
}, "onRequest");
async function addToRevocationList2(env, orchestratorId) {
  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored ? JSON.parse(stored) : { revoked_orchestrators: [], revoked_jtis: [] };
  if (!list.revoked_orchestrators.includes(orchestratorId)) {
    list.revoked_orchestrators.push(orchestratorId);
  }
  await env.RRF_KV.put("revocations", JSON.stringify(list));
}
__name(addToRevocationList2, "addToRevocationList");
function json4(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}
__name(json4, "json");

// .well-known/rrf-root-pubkey.pem.ts
var onRequest7 = /* @__PURE__ */ __name(async (context) => {
  const { env } = context;
  let pem = await env.RRF_KV.get("rrf:root:pubkey", "text");
  if (!pem && env.RRF_ROOT_PUBKEY) {
    const b64 = env.RRF_ROOT_PUBKEY.trim();
    pem = `-----BEGIN PUBLIC KEY-----
${b64}
-----END PUBLIC KEY-----
`;
  }
  if (!pem) {
    return new Response("RRF root key not provisioned", {
      status: 503,
      headers: { "Content-Type": "text/plain", "Cache-Control": "no-cache" }
    });
  }
  return new Response(pem, {
    headers: {
      "Content-Type": "application/x-pem-file",
      "Cache-Control": "public, max-age=3600"
    }
  });
}, "onRequest");

// v2/revocations.ts
var onRequest8 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" }
    });
  }
  const stored = await env.RRF_KV.get("revocations", "text");
  const list = stored ? JSON.parse(stored) : { revoked_orchestrators: [], revoked_jtis: [] };
  const response = {
    revoked_orchestrators: list.revoked_orchestrators ?? [],
    revoked_jtis: list.revoked_jtis ?? [],
    updated_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  return new Response(JSON.stringify(response), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=55"
      // ≤60s per spec
    }
  });
}, "onRequest");

// ../.wrangler/tmp/pages-ndmmBM/functionsRoutes-0.21378140819557934.mjs
var routes = [
  {
    routePath: "/v2/orchestrators/:id/consent",
    mountPath: "/v2/orchestrators/:id",
    method: "",
    middlewares: [],
    modules: [onRequest]
  },
  {
    routePath: "/v2/orchestrators/:id/token",
    mountPath: "/v2/orchestrators/:id",
    method: "",
    middlewares: [],
    modules: [onRequest2]
  },
  {
    routePath: "/v2/robots/:rrn/firmware-manifest",
    mountPath: "/v2/robots/:rrn",
    method: "",
    middlewares: [],
    modules: [onRequest3]
  },
  {
    routePath: "/v2/robots/:rrn/sbom",
    mountPath: "/v2/robots/:rrn",
    method: "",
    middlewares: [],
    modules: [onRequest4]
  },
  {
    routePath: "/v2/orchestrators/register",
    mountPath: "/v2/orchestrators",
    method: "",
    middlewares: [],
    modules: [onRequest5]
  },
  {
    routePath: "/v2/orchestrators/:id",
    mountPath: "/v2/orchestrators/:id",
    method: "",
    middlewares: [],
    modules: [onRequest6]
  },
  {
    routePath: "/.well-known/rrf-root-pubkey.pem",
    mountPath: "/.well-known",
    method: "",
    middlewares: [],
    modules: [onRequest7]
  },
  {
    routePath: "/v2/revocations",
    mountPath: "/v2",
    method: "",
    middlewares: [],
    modules: [onRequest8]
  }
];

// ../../.npm/_npx/32026684e21afda6/node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../../.npm/_npx/32026684e21afda6/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: /* @__PURE__ */ __name(() => {
            isFailOpen = true;
          }, "passThroughOnException")
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    }, "next");
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_worker_default as default
};
