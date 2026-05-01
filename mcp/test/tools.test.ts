import { describe, it, expect, vi } from "vitest";
import { RrfClient, RrfHttpError } from "../src/client.js";
import { TOOL_DEFS, callTool } from "../src/tools.js";

function makeFakeFetch(
  routes: Record<string, { status?: number; body: unknown }>,
): typeof fetch {
  return vi.fn(async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    const path = new URL(u).pathname + (new URL(u).search || "");
    const route = routes[path];
    if (!route) {
      return new Response(JSON.stringify({ error: "no fixture" }), { status: 404 });
    }
    return new Response(JSON.stringify(route.body), {
      status: route.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

describe("TOOL_DEFS", () => {
  it("exposes the five spike tools", () => {
    const names = TOOL_DEFS.map((t) => t.name).sort();
    expect(names).toEqual([
      "rrf_fetch_fria",
      "rrf_fetch_spatial_eval_run",
      "rrf_fetch_spatial_eval_spec",
      "rrf_list_registry",
      "rrf_lookup_robot",
    ]);
  });

  it("each tool has an inputSchema", () => {
    for (const t of TOOL_DEFS) {
      expect(t.inputSchema).toBeDefined();
      expect((t.inputSchema as { type: string }).type).toBe("object");
    }
  });
});

describe("rrf_lookup_robot", () => {
  it("hits /v2/robots/{rrn} and returns the body", async () => {
    const client = new RrfClient({
      base: "https://x",
      fetchImpl: makeFakeFetch({
        "/v2/robots/RRN-000000000001": {
          body: { rrn: "RRN-000000000001", name: "bob" },
        },
      }),
    });
    const out = await callTool(client, "rrf_lookup_robot", { rrn: "RRN-000000000001" });
    expect(out).toEqual({ rrn: "RRN-000000000001", name: "bob" });
  });

  it("returns an error envelope on 404 instead of throwing", async () => {
    const client = new RrfClient({
      base: "https://x",
      fetchImpl: makeFakeFetch({
        "/v2/robots/RRN-000000000099": {
          status: 404,
          body: { error: "Not registered" },
        },
      }),
    });
    const out = (await callTool(client, "rrf_lookup_robot", {
      rrn: "RRN-000000000099",
    })) as { status: number; error: string };
    expect(out.status).toBe(404);
    expect(out.error).toContain("404");
  });
});

describe("rrf_list_registry", () => {
  it("encodes type+limit query params", async () => {
    let captured: string | undefined;
    const fetchImpl: typeof fetch = vi.fn(async (url) => {
      captured = url.toString();
      return new Response(JSON.stringify({ entries: [] }));
    }) as unknown as typeof fetch;
    const client = new RrfClient({ base: "https://x", fetchImpl });
    await callTool(client, "rrf_list_registry", { type: "robot", limit: 50 });
    expect(captured).toContain("/v2/registry");
    expect(captured).toContain("type=robot");
    expect(captured).toContain("limit=50");
  });

  it("works without filters", async () => {
    const client = new RrfClient({
      base: "https://x",
      fetchImpl: makeFakeFetch({
        "/v2/registry": { body: { entries: [{ rrn: "RRN-000000000001" }] } },
      }),
    });
    const out = await callTool(client, "rrf_list_registry", {});
    expect(out).toEqual({ entries: [{ rrn: "RRN-000000000001" }] });
  });
});

describe("rrf_fetch_spatial_eval_spec", () => {
  it("hits /v1/spatial-eval/spec/{version}", async () => {
    const client = new RrfClient({
      base: "https://x",
      fetchImpl: makeFakeFetch({
        "/v1/spatial-eval/spec/1.0.0": {
          body: { spec_version: "1.0.0", rrf_pubkey: "AAAA" },
        },
      }),
    });
    const out = (await callTool(client, "rrf_fetch_spatial_eval_spec", {
      version: "1.0.0",
    })) as { rrf_pubkey: string };
    expect(out.rrf_pubkey).toBe("AAAA");
  });
});

describe("rrf_fetch_spatial_eval_run (Bearer-gated)", () => {
  it("sends Authorization: Bearer when api key is configured", async () => {
    let captured: Headers | undefined;
    const fetchImpl: typeof fetch = vi.fn(async (_url, init) => {
      captured = new Headers(init?.headers);
      return new Response(JSON.stringify({ submission_id: "sub_x", status: "pending" }));
    }) as unknown as typeof fetch;
    const client = new RrfClient({ base: "https://x", apiKey: "k1", fetchImpl });
    await callTool(client, "rrf_fetch_spatial_eval_run", { submission_id: "sub_abc" });
    expect(captured?.get("authorization")).toBe("Bearer k1");
  });

  it("returns an error envelope when no api key is configured", async () => {
    const client = new RrfClient({ base: "https://x", fetchImpl: makeFakeFetch({}) });
    const out = (await callTool(client, "rrf_fetch_spatial_eval_run", {
      submission_id: "sub_abc",
    })) as { error: string };
    expect(out.error).toContain("Bearer-gated");
  });
});

describe("RrfHttpError", () => {
  it("formats the URL and status into the message", () => {
    const e = new RrfHttpError(403, "https://x/y", { error: "nope" });
    expect(e.message).toContain("403");
    expect(e.message).toContain("https://x/y");
  });
});
