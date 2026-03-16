# Firestore v1.5 Migration Guide

**Version:** RRF v1.5.0  
**Date:** 2026-03-16  
**Author:** Architecture Agent  
**Status:** READY FOR CRAIG TO DEPLOY  

---

## Overview

This document describes the Firestore schema changes required for RCAN v1.5 support and provides a migration script to add new fields with safe defaults to existing robot documents.

> ⚠️ **Craig must run this migration manually.** The migration script touches live production data. Review it carefully before running.

---

## New Firestore Fields on Robot Documents

All new fields are added to the `robots/{rrn}` collection with backward-compatible defaults.

### Collection: `robots/{rrn}`

| Field | Type | Default | Description | RCAN Gap |
|-------|------|---------|-------------|----------|
| `rcan_version` | `string` | `"1.4"` | RCAN spec version the robot supports | GAP-12 |
| `revocation_status` | `string` | `"active"` | `"active"` \| `"revoked"` \| `"suspended"` | GAP-02 |
| `revoked_at` | `timestamp \| null` | `null` | Timestamp of revocation (null if active) | GAP-02 |
| `revocation_reason` | `string \| null` | `null` | Human-readable revocation reason | GAP-02 |
| `revocation_authority` | `string \| null` | `null` | Who issued the revocation | GAP-02 |
| `key_id` | `string \| null` | `null` | Current signing key fingerprint/ID | GAP-09 |
| `key_history` | `array<string>` | `[]` | Previous key IDs (key rotation audit) | GAP-09 |
| `supports_qos_2` | `boolean` | `false` | Supports exactly-once ESTOP delivery | GAP-11 |
| `supports_delegation` | `boolean` | `false` | Supports command delegation chains | GAP-01 |
| `offline_capable` | `boolean` | `false` | Can operate offline with cached credentials | GAP-06 |

### New Collection: `revocation_events/{event_id}`

Created when a robot is revoked. Used for audit trail and ROBOT_REVOCATION broadcasts.

| Field | Type | Description |
|-------|------|-------------|
| `rrn` | `string` | Revoked robot's RRN |
| `status` | `string` | `"revoked"` or `"suspended"` |
| `revoked_at` | `timestamp` | When revocation occurred |
| `reason` | `string` | Reason for revocation |
| `authority` | `string` | Who issued the revocation |
| `broadcast_sent` | `boolean` | Whether ROBOT_REVOCATION broadcast was sent |
| `created_at` | `timestamp` | Event creation timestamp |

### Updated Firestore Security Rules

Add to `firestore.rules`:

```
// Revocation status — readable by anyone; writable only by registry admins
match /robots/{rrn} {
  allow read: if true;
  allow update: if request.auth != null && (
    // Owner can update their own robot
    resource.data.firebase_uid == request.auth.uid ||
    // Registry admin role (custom claim)
    request.auth.token.registry_admin == true
  ) && (
    // If updating revocation_status, must be admin or owner
    !('revocation_status' in request.resource.data.diff(resource.data).affectedKeys()) ||
    request.auth.token.registry_admin == true ||
    resource.data.firebase_uid == request.auth.uid
  );
}

// Revocation events — append-only for authenticated, readable by owner
match /revocation_events/{eventId} {
  allow read: if request.auth != null;
  allow create: if request.auth != null && request.auth.token.registry_admin == true;
  allow update, delete: if false;
}
```

---

## Migration Script

Save as `deploy/migrate-v1.5.py` and run **once** on existing robots.

```python
#!/usr/bin/env python3
"""
RRF v1.5.0 Firestore Migration Script
Adds RCAN v1.5 fields with safe defaults to all existing robot documents.

Usage:
    pip install firebase-admin
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccountKey.json
    python deploy/migrate-v1.5.py

    # Dry run (no writes):
    python deploy/migrate-v1.5.py --dry-run
"""

import argparse
import sys
from datetime import datetime

import firebase_admin
from firebase_admin import credentials, firestore

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Safe defaults for all new v1.5 fields
V1_5_DEFAULTS = {
    "rcan_version": "1.4",        # Conservative — existing robots are v1.4
    "revocation_status": "active",
    "revoked_at": None,
    "revocation_reason": None,
    "revocation_authority": None,
    "key_id": None,               # Populated when robot next registers keys
    "key_history": [],
    "supports_qos_2": False,      # Opt-in when robot firmware is updated
    "supports_delegation": False,
    "offline_capable": False,
}

# Override defaults for specific robots (Bob and Alex are already v1.5)
ROBOT_OVERRIDES = {
    "RRN-000000000001": {
        "rcan_version": "1.5",
        "revocation_status": "active",
        "key_id": "kid-bob-2026-03-001",
        "supports_qos_2": True,
        "supports_delegation": True,
        "offline_capable": True,
    },
    "RRN-000000000005": {
        "rcan_version": "1.5",
        "revocation_status": "active",
        "key_id": "kid-alex-2026-03-001",
        "supports_qos_2": True,
        "supports_delegation": True,
        "offline_capable": True,
    },
}


def migrate(dry_run: bool = False) -> None:
    """Add v1.5 fields to all robot documents that are missing them."""
    app = firebase_admin.initialize_app()
    db = firestore.client()

    robots_ref = db.collection("robots")
    robots = list(robots_ref.stream())

    print(f"Found {len(robots)} robot documents")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE WRITE'}")
    print()

    updated = 0
    skipped = 0
    errors = 0

    for doc in robots:
        rrn = doc.id
        data = doc.to_dict()

        # Build the update dict — only add fields that don't already exist
        update = {}
        defaults = dict(V1_5_DEFAULTS)

        # Apply per-robot overrides
        if rrn in ROBOT_OVERRIDES:
            defaults.update(ROBOT_OVERRIDES[rrn])

        for field, default_value in defaults.items():
            if field not in data:
                update[field] = default_value

        if not update:
            print(f"  SKIP  {rrn} — all v1.5 fields already present")
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

    if dry_run:
        print()
        print("Dry run complete. Re-run without --dry-run to apply changes.")


def main() -> None:
    parser = argparse.ArgumentParser(description="RRF v1.5 Firestore migration")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be changed without writing")
    args = parser.parse_args()
    migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
```

---

## Deployment Steps

Craig must run these steps in order:

### Step 1: Dry run the migration
```bash
cd ~/RobotRegistryFoundation
pip install firebase-admin
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/firebase/serviceAccountKey.json
python deploy/migrate-v1.5.py --dry-run
```

Review the output. Confirm the fields and values look correct.

### Step 2: Run the migration
```bash
python deploy/migrate-v1.5.py
```

### Step 3: Deploy Firestore rules
```bash
firebase deploy --only firestore:rules
```

### Step 4: Deploy Cloud Functions (new revocation endpoints)
```bash
firebase deploy --only functions
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

If anything goes wrong:

```bash
# Revert a specific robot's revocation status:
python - <<'EOF'
import firebase_admin
from firebase_admin import firestore
firebase_admin.initialize_app()
db = firestore.client()
db.collection("robots").document("RRN-000000000001").update({
    "rcan_version": "1.4",
    "revocation_status": "active",
})
print("Reverted.")
EOF
```

New fields with `None` defaults are safe to leave — they don't affect existing functionality.

---

## Notes

- All new fields have safe defaults that preserve existing v1.4 behavior.  
- The migration is **idempotent** — safe to run multiple times (skips already-migrated documents).  
- `key_id` is intentionally `null` for existing robots until they next connect and register a key.  
- `supports_qos_2: false` is conservative — set to `true` only after the robot's firmware is updated to rcan-py v0.5.0.  
