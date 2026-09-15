/**
 * M-05: the registry must not hand out URLs at a hostname with no DNS record.
 *
 * Seven compliance submission routes used to return `*_url` values against an
 * `api.` subdomain of the registry's rcan.dev name. `getent hosts` resolved
 * neither that subdomain nor its parent, while robotregistryfoundation.org and
 * rcan.dev both resolved, so every receipt pointed a third party at nothing.
 *
 * This test is the repository check that keeps it dropped. It scans functions/
 * and src/ for any hostname under the registry's rcan.dev name and fails unless
 * the hostname resolves at test time or tests/dead-hostname-allowlist.json
 * records that file with a reason.
 *
 * DNS is consulted, not trusted: if the network itself is unavailable the
 * resolution half is skipped and the allowlist half still runs, so the check is
 * meaningful offline and never green by accident.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promises as dns } from "node:dns";

import { API_BASE } from "../functions/v2/_lib/api-base.js";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCAN_DIRS = ["functions", "src"];
const SCAN_EXTS = [".ts", ".tsx", ".astro", ".js", ".mjs"];

/** Any host under the registry's rcan.dev name, e.g. rrf.rcan.dev, api.rrf.rcan.dev. */
const HOST_RE = /\b((?:[a-z0-9][a-z0-9-]*\.)*rrf\.rcan\.dev)\b/gi;

interface AllowEntry {
  hostname: string;
  attached: boolean;
  allowed_in: string[];
  reason: string;
}

const allowlist: { hostnames: AllowEntry[] } = JSON.parse(
  readFileSync(join(REPO_ROOT, "tests", "dead-hostname-allowlist.json"), "utf8"),
);

function walk(dir: string, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (name === "node_modules" || name === "dist" || name.startsWith(".")) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (SCAN_EXTS.some((e) => name.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

interface Occurrence {
  file: string;
  hostname: string;
  line: number;
  text: string;
  inUrl: boolean;
}

/** Literal-escape a hostname: its dots must not match any character. */
function escapeRe(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function collect(): Occurrence[] {
  const found: Occurrence[] = [];
  for (const dir of SCAN_DIRS) {
    for (const file of walk(join(REPO_ROOT, dir))) {
      const rel = relative(REPO_ROOT, file).split(sep).join("/");
      if (rel.endsWith(".test.ts") || rel.endsWith(".test.tsx")) continue;
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((text, i) => {
        HOST_RE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = HOST_RE.exec(text)) !== null) {
          found.push({
            file: rel,
            hostname: m[1].toLowerCase(),
            line: i + 1,
            text: text.trim(),
            inUrl: new RegExp(`https?://[^\\s"'\`]*${escapeRe(m[1])}`, "i").test(text),
          });
        }
      });
    }
  }
  return found;
}

async function resolves(hostname: string): Promise<boolean> {
  try {
    await dns.lookup(hostname);
    return true;
  } catch {
    return false;
  }
}

describe("no dead hostnames in what the registry hands out", () => {
  let dnsWorks = false;

  beforeAll(async () => {
    // Control: if this fails there is no network here, so skip the DNS half.
    dnsWorks = await resolves("robotregistryfoundation.org");
  });

  it("API_BASE names a host that resolves", async () => {
    const host = new URL(API_BASE).hostname;
    expect(host).not.toMatch(/rrf\.rcan\.dev$/);
    if (!dnsWorks) return;
    expect(await resolves(host)).toBe(true);
  });

  it("no submission receipt is built against an unresolvable registry host", () => {
    const inUrls = collect().filter((o) => o.inUrl);
    const unexplained = inUrls.filter((o) => {
      const entry = allowlist.hostnames.find((h) => h.hostname === o.hostname);
      return !entry || !entry.allowed_in.includes(o.file);
    });
    expect(
      unexplained.map((o) => `${o.file}:${o.line} ${o.hostname}`),
    ).toEqual([]);
  });

  it("every remaining occurrence is either resolvable or allowlisted with a reason", async () => {
    const failures: string[] = [];

    for (const occ of collect()) {
      if (dnsWorks && (await resolves(occ.hostname))) continue;

      const entry = allowlist.hostnames.find((h) => h.hostname === occ.hostname);
      if (!entry) {
        failures.push(
          `${occ.file}:${occ.line} uses ${occ.hostname}, which does not resolve and is not in tests/dead-hostname-allowlist.json`,
        );
        continue;
      }
      if (!entry.allowed_in.includes(occ.file)) {
        failures.push(
          `${occ.file}:${occ.line} uses ${occ.hostname}; the allowlist covers that hostname but not this file`,
        );
        continue;
      }
      if (!entry.reason || entry.reason.length < 40) {
        failures.push(
          `${occ.hostname} is allowlisted without a usable reason`,
        );
      }
    }

    expect(failures).toEqual([]);
  });

  it("an allowlist entry marked attached must actually resolve", async () => {
    if (!dnsWorks) return;
    for (const entry of allowlist.hostnames) {
      if (!entry.attached) continue;
      expect(
        await resolves(entry.hostname),
        `${entry.hostname} is recorded as attached but does not resolve`,
      ).toBe(true);
    }
  });

  it("the allowlist is not a place to park new receipt URLs", () => {
    // Anything allowlisted must be there for a non-URL reason. A receipt URL
    // belongs in functions/v2/_lib/api-base.ts.
    for (const entry of allowlist.hostnames) {
      if (entry.attached) continue;
      const urlUses = collect().filter(
        (o) => o.hostname === entry.hostname && o.inUrl,
      );
      expect(urlUses.map((o) => `${o.file}:${o.line}`)).toEqual([]);
    }
  });
});
