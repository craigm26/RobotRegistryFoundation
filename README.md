# Robot Registry Foundation

The independent body operating the global robot identity registry — like ICANN for robotics.

🌐 **[robotregistryfoundation.org](https://robotregistryfoundation.org)**

## What We Do

The Robot Registry Foundation (RRF) assigns globally unique **Robot Registration Numbers (RRNs)** to robots worldwide. Any robot, any manufacturer, any runtime can register — regardless of which software stack they use.

- **Assign** — Issue RRNs: permanent, globally unique identifiers for physical robots
- **Verify** — 4-tier verification from community self-report to full conformance audit
- **Federate** — Multiple registry nodes that cross-verify and stay in sync

## Relationship to RCAN

The RRF and the [RCAN protocol](https://rcan.dev) are related but independent:

- **RCAN** is a communication protocol — it defines how robots identify themselves, sign messages, and prove behavior. Think of it like HTTPS.
- **The RRF** operates the registry — it's the directory where robots get their permanent address. Think of it like ICANN/DNS.

You can implement RCAN without registering here. You can register here without implementing RCAN. Both together give you a globally identifiable, auditable robot.

## Site Structure

| Page | Purpose |
|---|---|
| `/` | Foundation home — what we do and why |
| `/registry/` | Browse all registered robots |
| `/registry/submit/` | Register your robot, get an RRN |
| `/governance/` | Foundation charter and board composition |
| `/verification/` | How the 4 verification tiers work |
| `/federation/` | How to run a federated registry node |
| `/about/` | About the foundation |
| `/api/` | Registry REST API reference |

## Tech Stack

- [Astro 4](https://astro.build) — static site generator
- [Tailwind CSS](https://tailwindcss.com) — styling
- [Cloudflare Pages](https://pages.cloudflare.com) — hosting
- TypeScript throughout

## Development

```bash
npm install
npm run dev       # localhost:4321
npm run build     # production build → dist/
```

## Contributing

The RRF is a proposed independent foundation — currently in formation. We're seeking:
- Co-founders and board members
- Manufacturer partnerships
- Standards body endorsements
- Technical contributors

Open an issue or start a discussion on GitHub.

## Governance

The full draft charter is at [robotregistryfoundation.org/governance/](https://robotregistryfoundation.org/governance/).

## Ecosystem

The RRF is part of a broader open robotics stack:

| Project | Role | Link |
|---|---|---|
| **RCAN Protocol** | Communication & auth standard (v1.4) | [rcan.dev](https://rcan.dev) |
| **OpenCastor** | Python robot runtime (RCAN reference implementation) | [github.com/craigm26/OpenCastor](https://github.com/craigm26/OpenCastor) |
| **OpenCastor Fleet UI** | Web app for remote robot management | [app.opencastor.com](https://app.opencastor.com) |
| **rcan-py** | Python RCAN SDK | [PyPI: rcan](https://pypi.org/project/rcan/) |
| **rcan-ts** | TypeScript RCAN SDK | [npm: @continuonai/rcan](https://www.npmjs.com/package/@continuonai/rcan) |
| **Robot Registry Foundation** | Global robot identity (this repo) | [robotregistryfoundation.org](https://robotregistryfoundation.org) |

### Registered Robots (Examples)

Real robots running this stack with publicly registered RRNs:

| RRN | Name | Runtime | Notes |
|---|---|---|---|
| RRN-000000000001 | Bob | OpenCastor v2026.3.16.1 | Raspberry Pi 5, Gemini 2.5 Flash brain |
| RRN-000000000005 | Alex | OpenCastor v2026.3.16.1 | Raspberry Pi 5 + SO-ARM101 5-DOF arm |

Register your robot at [rcan.dev/registry](https://rcan.dev/registry).

## License

Site content: CC BY 4.0. Code: MIT.
