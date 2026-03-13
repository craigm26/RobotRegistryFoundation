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
  "rcan_version": "1.4",
  "opencastor_version": "2026.3.13.11",
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

## Build & Deploy

```bash
npm run build    # Must build clean
git push origin main  # Triggers Cloudflare Pages deploy
```

## Key Cross-References

- RCAN spec §21 (Registry Integration): https://rcan.dev/spec/section-21/
- OpenCastor (reference impl): https://opencastor.com
- rcan.dev (RRN authority): https://rcan.dev

## When Updating Registered Robots

Always update both:
1. `src/content/robots/<robot-slug>.json` — the JSON data
2. If OpenCastor version changes: update `opencastor_version` and `rcan_version` fields

Current registered robots:
- **Bob** (`opencastor-bob.json`): RRN-000000000001, Raspberry Pi 5 + Hailo-8, OpenCastor v2026.3.13.11
- **Alex** (`opencastor-alex.json`): RRN-000000000005, Raspberry Pi 5 + OAK-D, OpenCastor v2026.3.13.11
