# CLAUDE.md — RobotRegistryFoundation Development Guide

> **Agent context file.** Read this before making any changes.

## What Is This?

The **Robot Registry Foundation (RRF)** website — the governance body for Robot Registration Numbers (RRNs). Deployed at **robotregistryfoundation.org** via Cloudflare Pages. Astro + Tailwind static site.

**Repo**: craigm26/RobotRegistryFoundation | **Branch**: main

## Repository Layout

```
RobotRegistryFoundation/
├── src/
│   ├── pages/
│   │   ├── index.astro              # Homepage
│   │   ├── registry/
│   │   │   ├── index.astro          # Robot registry listing (search + filter)
│   │   │   └── submit.astro         # Submit a robot form
│   │   ├── api/index.astro          # API documentation
│   │   ├── about/index.astro        # About + OpenCastor cross-link
│   │   ├── federation/index.astro   # Federation protocol docs
│   │   ├── governance/index.astro   # Governance structure
│   │   ├── verification/index.astro # Verification tiers
│   │   └── rcan-integration/        # How RRF integrates with RCAN §21
│   └── content/
│       └── robots/                  # One JSON per registered robot
│           ├── opencastor-bob.json  # Bob: RRN-000000000001
│           ├── opencastor-alex.json # Alex: RRN-000000000005
│           └── ...
└── public/                          # Static assets
```

## Robot JSON Schema

Each robot in `src/content/robots/` must have:

```json
{
  "rrn": "RRN-000000000001",
  "rrn_uri": "rrn://org/category/model/id",
  "name": "Human-readable name",
  "manufacturer": "github-username-or-org",
  "model": "model-slug",
  "description": "One or two sentences.",
  "status": "active | inactive | retired",
  "production_year": 2026,
  "specs": {
    "compute": "...",
    "sensors": ["..."],
    "actuators": ["..."]
  },
  "verification_status": "community | verified | manufacturer | certified",
  "ruri": "rcan://host:port/robot-id",
  "rcan_version": "3.2",
  "opencastor_version": "see PyPI",
  "tags": ["..."],
  "submitted_by": "github-username",
  "submitted_date": "YYYY-MM-DD",
  "registered_at": "ISO 8601 UTC"
}
```

**Numeric RRN format**: `RRN-XXXXXXXXXXXX` (exactly 12 digits, zero-padded)

## Verification Tiers

| Badge | Name | Meaning |
|---|---|---|
| ⬜ | Community | Self-reported; no independent verification |
| 🟡 | Verified | Identity verified via registry process |
| 🔵 | Manufacturer-claimed | DNS TXT record proves domain ownership |
| ✅ | Manufacturer-verified | Signed attestation reviewed by RRF (gold standard) |

Tier transitions: ⬜ → 🟡 → 🔵 → ✅ (no skipping)

## Registry Search/Filter (registry/index.astro)

The registry page has client-side search + filter:
- Search input debounced 200ms — matches `data-name`, `data-manufacturer`, `data-model`, `data-tags`
- Verification filter pills: `all | community | verified | manufacturer | certified`
- Robot cards have `data-verification` attribute for filter matching
- Empty state shown when no results match

## Styling Rules

**Tailwind CSS only — no inline styles.**

Same token set as rcan-spec: `bg-bg`, `bg-bg-card`, `text-text`, `text-text-muted`, `text-accent`, `border-border`.

## Build & Deploy — deploy path verified 2026-09-12

**`git push origin main` does publish this site, and the Cloudflare Pages project is still direct-upload. Both are true.** `.github/workflows/deploy.yml` runs the direct upload for you via `cloudflare/wrangler-action`. Earlier drafts of this file hedged ("confirm which is actually true before trusting a push"); it is settled, and the evidence is below. Do not re-open it without new evidence.

Three checks, all run 2026-09-12:

1. **Actions are enabled on this repo — not billing-blocked.**
   `gh api repos/craigm26/RobotRegistryFoundation/actions/permissions`
   → `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`
   `gh run list --repo craigm26/RobotRegistryFoundation --workflow deploy.yml --event push --branch main`
   → 148 total runs; the most recent push-to-`main` run **succeeded** on 2026-06-17 for `f0068dc`.

2. **The Pages project is direct-upload, not git-connected.**
   `npx wrangler pages project list` → `robot-registry-foundation`
   (`robot-registry-foundation.pages.dev`, `robotregistryfoundation.com`, `robotregistryfoundation.org`),
   **Git Provider: No**. Account: Civqo, `71d59adbd067633aca3e95f915fbf2b4`.

3. **The live site is the tip of `origin/main`.**
   `npx wrangler pages deployment list --project-name robot-registry-foundation | head -3`
   (Build column trimmed):

   ```
   Id                                    Environment  Branch  Source   Deployment                                            Status
   ac91dd97-fa4d-4c9f-9c62-20329c9689de  Production   main    f0068dc  https://ac91dd97.robot-registry-foundation.pages.dev  2 months ago
   ```

   `f0068dc` is `origin/main` HEAD. Nothing is queued behind it.

### The one command that publishes by hand

```bash
npm run build && npx wrangler pages deploy dist --project-name=robot-registry-foundation --branch=main
```

Use it when you need the site live without a push, or when a push's Action fails. `--branch=main` is mandatory: without it the upload lands as a preview deployment and the apex domain does not move. The OAuth token lives at `~/.wrangler/config/default.toml`.

**This clone is behind what is live.** The local `main` here is `ecb11c8` (2026-06-10) and there is no local `refs/remotes/origin/main` at all; `origin/HEAD` is `f0068dc` (2026-06-17), which is the commit the production deployment above was built from. `git fetch origin` and rebase onto `origin/main` before merging or pushing anything from this checkout, or the push is rejected and the tree you reasoned about is not the tree that is serving.

**Consequence for security work:** a push to `main` ships whatever is on `main` at that moment, including a half-landed credential change. Land the whole fix on a branch, merge deliberately, then watch the run. Do **not** edit or delete `.github/workflows/deploy.yml` — the standing house rule is never to *author* a GitHub Action, not to tear out one that is already load-bearing here.

## Key Cross-References

- RCAN spec §21 (Registry Integration): https://rcan.dev/spec/section-21/
- OpenCastor (productized open-core RCAN runtime, Layer 4 per spec §3): https://opencastor.com
- rcan.dev (RRN authority): https://rcan.dev

## When Updating Registered Robots

Always update both:
1. `src/content/robots/<robot-slug>.json` — the JSON data
2. If OpenCastor version changes: update `opencastor_version` and `rcan_version` fields

Current registered robots (versions per the live `/v2/registry` API; `src/content/robots/` is intentionally empty since the registry was redesigned to dynamic — see `[rrn].astro:1-7`):
- **Bob**: RRN-000000000001, Raspberry Pi 5 + Hailo-8 + SO-ARM101 6-DOF arm, OpenCastor (see PyPI for canonical version)
- **Alex**: RRN-000000000005, Raspberry Pi 5 + OAK-D, OpenCastor (see PyPI for canonical version)
