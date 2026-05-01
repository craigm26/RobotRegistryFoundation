/**
 * Thin fetch client for the public RRF endpoints.
 *
 * One method per endpoint; no caching, no retries, no auth complexity
 * for the spike. Bearer headers pass through verbatim when the caller
 * provides them — write tools (which need apikey-bound auth) are out of
 * scope here.
 *
 * Configurable via RRF_BASE env so a developer can point at
 * http://localhost:8788 (wrangler pages dev) instead of production.
 */

const DEFAULT_BASE = "https://robotregistryfoundation.org";

export interface RrfClientOptions {
  base?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
}

export class RrfHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    public readonly body: unknown,
  ) {
    super(`RRF ${url} returned ${status}: ${JSON.stringify(body).slice(0, 200)}`);
  }
}

export class RrfClient {
  private readonly base: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: RrfClientOptions = {}) {
    this.base = (opts.base ?? process.env.RRF_BASE ?? DEFAULT_BASE).replace(/\/$/, "");
    this.apiKey = opts.apiKey ?? process.env.RRF_API_KEY;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private async get(path: string, opts: { bearer?: boolean } = {}): Promise<unknown> {
    const url = `${this.base}${path}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.bearer) {
      if (!this.apiKey) {
        throw new Error(
          `${path} is Bearer-gated; pass --api-key or set RRF_API_KEY env`,
        );
      }
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    const res = await this.fetchImpl(url, { headers });
    const text = await res.text();
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = { _raw: text.slice(0, 500) };
    }
    if (!res.ok) throw new RrfHttpError(res.status, url, body);
    return body;
  }

  /** Look up a single robot record by RRN. Public. */
  async lookupRobot(rrn: string): Promise<unknown> {
    return this.get(`/v2/robots/${encodeURIComponent(rrn)}`);
  }

  /** Unified listing of registry entries (robots/components/models/harnesses).
   * Server-side filter by `type` and `limit`. Public. */
  async listRegistry(type?: string, limit?: number): Promise<unknown> {
    const params = new URLSearchParams();
    if (type) params.set("type", type);
    if (limit !== undefined) params.set("limit", String(limit));
    const q = params.toString();
    return this.get(`/v2/registry${q ? `?${q}` : ""}`);
  }

  /** Fetch the canonical spatial-eval spec metadata for a version. Public. */
  async fetchSpatialEvalSpec(version: string): Promise<unknown> {
    return this.get(`/v1/spatial-eval/spec/${encodeURIComponent(version)}`);
  }

  /** Poll a counter-signed (or pending/rejected) spatial-eval submission.
   * Bearer-gated. */
  async fetchSpatialEvalRun(submissionId: string): Promise<unknown> {
    return this.get(`/v1/spatial-eval/runs/${encodeURIComponent(submissionId)}`, {
      bearer: true,
    });
  }

  /** Fetch a stored FRIA document for a robot. Bearer-gated. */
  async fetchFria(rrn: string): Promise<unknown> {
    return this.get(`/v2/robots/${encodeURIComponent(rrn)}/fria`, { bearer: true });
  }
}
