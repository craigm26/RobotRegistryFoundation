# Firestore v1.6 Migration Guide

**Version:** RRF v1.6.0  
**Date:** 2026-03-17  
**Author:** Architecture Agent  
**Status:** READY FOR CRAIG TO DEPLOY  
**Prerequisite:** [firestore-v1.5-migration.md](./firestore-v1.5-migration.md) applied first

---

## Overview

This document describes the Firestore schema changes required for RCAN v1.6 support
(GAP-14 federation, GAP-16 LoA enforcement, GAP-17 transports, GAP-18 multi-modal)
and provides a migration script to add new fields with safe defaults to existing robot documents.

> ⚠️ **Craig must run this migration manually.** The migration script touches live production data. Review it carefully before running.
> Run the v1.5 migration first if not already applied.

---

## New Firestore Fields on Robot Documents

All new fields are added to the `robots/{rrn}` collection with backward-compatible defaults.

### Collection: `robots/{rrn}`

| Field | Type | Default | Description | RCAN Gap |
|-------|------|---------|-------------|----------|
| `supported_transports` | `array<string>` | `["http"]` | Transport encodings the robot accepts | GAP-17 |
| `min_loa_for_control` | `number` | `1` | Minimum LoA required for control-scope commands | GAP-16 |
| `loa_enforcement` | `boolean` | `false` | Whether LoA policy is enforced (false = log-only) | GAP-16 |
| `multimodal_enabled` | `boolean` | `true` | Whether the robot accepts multi-modal (image/audio) commands | GAP-18 |
| `registry_tier` | `string` | `"community"` | Trust tier: `root` \| `authoritative` \| `community` | GAP-14 |

### rcan_version Update

Set `rcan_version` to `"1.6"` for robots running OpenCastor v2026.3.17.1 or later.

---

## Migration Script

Save as `deploy/migrate-v1.6.py` and run **once** on existing robots.

```python
#!/usr/bin/env python3
"""
RRF v1.6.0 Firestore Migration Script
Adds RCAN v1.6 fields with safe defaults to all existing robot documents.

Idempotent — safe to run multiple times.

Usage:
    pip install firebase-admin
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccountKey.json
    python deploy/migrate-v1.6.py

    # Dry run (no writes):
    python deploy/migrate-v1.6.py --dry-run
"""

import argparse
from datetime import datetime, timezone

import firebase_admin
from firebase_admin import credentials, firestore

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Safe defaults for all new v1.6 fields
V1_6_DEFAULTS = {
    "supported_transports": ["http"],
    "min_loa_for_control": 1,
    "loa_enforcement": False,
    "multimodal_enabled": True,
    "registry_tier": "community",
}

# Override defaults for specific robots (Bob and Alex are already v1.6)
ROBOT_OVERRIDES = {
    "RRN-000000000001": {
        "rcan_version": "1.6",
        "supported_transports": ["http", "compact"],
        "min_loa_for_control": 1,
        "loa_enforcement": False,
        "multimodal_enabled": True,
        "registry_tier": "community",
    },
    "RRN-000000000005": {
        "rcan_version": "1.6",
        "supported_transports": ["http"],
        "min_loa_for_control": 1,
        "loa_enforcement": False,
        "multimodal_enabled": True,
        "registry_tier": "community",
    },
}


def migrate(dry_run: bool = False) -> None:
    """Add v1.6 fields to all robot documents that are missing them."""
    app = firebase_admin.initialize_app()
    db = firestore.client()

    robots_ref = db.collection("robots")
    robots = list(robots_ref.stream())

    print(f"Found {len(robots)} robot documents")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE WRITE'}")
    print(f"Migration: RCAN v1.6 fields")
    print()

    updated = 0
    skipped = 0
    errors = 0

    for doc in robots:
        rrn = doc.id
        data = doc.to_dict()

        # Build the update dict — only add fields that don't already exist
        update = {}
        defaults = dict(V1_6_DEFAULTS)

        # Apply per-robot overrides
        if rrn in ROBOT_OVERRIDES:
            defaults.update(ROBOT_OVERRIDES[rrn])

        for field, default_value in defaults.items():
            if field not in data:
                update[field] = default_value

        # Also bump rcan_version to 1.6 if it's "1.5" or "1.4"
        current_version = data.get("rcan_version", "1.4")
        if current_version in ("1.4", "1.5"):
            # Only bump for robots that are in the v1.6 override list
            # (others keep their current version until firmware is updated)
            if rrn in ROBOT_OVERRIDES:
                update["rcan_version"] = ROBOT_OVERRIDES[rrn].get("rcan_version", current_version)

        if not update:
            print(f"  SKIP  {rrn} — all v1.6 fields already present")
            skipped += 1
            continue

        print(f"  {'DRY ' if dry_run else ''}UPDATE  {rrn}:")
        for k, v in update.items():
            print(f"    + {k}: {v!r}")

        if not dry_run:
            try:
                robots_ref.document(rrn).update(update)
                updated += 1
            except Exception as e:
                print(f"    ERROR: {e}")
                errors += 1
        else:
            updated += 1

    print()
    print(f"Summary: {updated} updated, {skipped} skipped, {errors} errors")
    print()

    if dry_run:
        print("Dry run complete. Re-run without --dry-run to apply changes.")


def main() -> None:
    parser = argparse.ArgumentParser(description="RRF v1.6 Firestore migration")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without writing",
    )
    args = parser.parse_args()
    migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
```

---

## Deployment Steps

Craig must run these steps in order:

### Step 1: Ensure v1.5 migration is complete
```bash
# Check that v1.5 fields exist on at least one robot
cd ~/RobotRegistryFoundation
python - <<'EOF'
import firebase_admin
from firebase_admin import firestore
firebase_admin.initialize_app()
db = firestore.client()
doc = db.collection("robots").document("RRN-000000000001").get()
data = doc.to_dict()
v15_fields = ["rcan_version", "revocation_status", "supports_qos_2"]
missing = [f for f in v15_fields if f not in data]
if missing:
    print(f"v1.5 migration not complete! Missing: {missing}")
    print("Run: python deploy/migrate-v1.5.py first")
else:
    print("v1.5 migration confirmed. Ready for v1.6.")
EOF
```

### Step 2: Dry run the v1.6 migration
```bash
pip install firebase-admin
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/firebase/serviceAccountKey.json
python deploy/migrate-v1.6.py --dry-run
```

Review the output. Confirm the fields and values look correct.

### Step 3: Run the v1.6 migration
```bash
python deploy/migrate-v1.6.py
```

### Step 4: Deploy Firestore security rules (no changes required for v1.6 fields)
```bash
# v1.6 fields use same read/write rules as v1.5
# Only update if you're adding new collections
firebase deploy --only firestore:rules
```

### Step 5: Deploy the RRF site (Cloudflare Pages)
```bash
# Via Cloudflare Pages CI (auto-triggered by git push to main)
# OR manually:
npm run build
# Upload dist/ to Cloudflare Pages dashboard
```

---

## Rollback

If anything goes wrong, revert v1.6 fields to v1.5 defaults:

```python
#!/usr/bin/env python3
"""Rollback RCAN v1.6 fields to v1.5 defaults."""
import firebase_admin
from firebase_admin import firestore

firebase_admin.initialize_app()
db = firestore.client()

V1_6_FIELDS = [
    "supported_transports",
    "min_loa_for_control",
    "loa_enforcement",
    "multimodal_enabled",
    "registry_tier",
]

# Use Firestore DELETE_FIELD sentinel to remove new fields
from google.cloud.firestore import DELETE_FIELD

robots = list(db.collection("robots").stream())
for doc in robots:
    update = {field: DELETE_FIELD for field in V1_6_FIELDS}
    db.collection("robots").document(doc.id).update(update)
    print(f"Rolled back v1.6 fields from {doc.id}")

print("Done.")
```

---

## Notes

- All new v1.6 fields have safe defaults that preserve existing v1.5/v1.4 behavior.
- `loa_enforcement: false` is conservative — set to `true` only after testing LoA flows end-to-end.
- `supported_transports: ["http"]` is the safe default — add `"compact"` only after firmware supports it.
- `multimodal_enabled: true` enables multi-modal stubs but doesn't send images until the media backend is ready.
- The migration is **idempotent** — safe to run multiple times (skips already-migrated documents).
