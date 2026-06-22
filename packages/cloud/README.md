# Cloud (Proprietary — Gated)

This directory documents **cloud-only** components. The actual code lives in the main tree and is **gated by `EXTSHIELD_MODE`** and feature flags; when `EXTSHIELD_MODE=oss` (default), cloud-only routes return **HTTP 501** and no cloud code runs.

## What is Cloud (Proprietary)

- **Supabase service logic**: Auth (JWT verification), Supabase-backed storage adapter, multi-tenant persistence.
- **Cloud-only API routes**: History, user karma, telemetry summary, diagnostic scans, delete scan, clear all, community review queue, enterprise/careers forms.
- **Scripts**: `../scripts/cloud_only/` — migrations runner, destructive/admin operations (only used when Cloud is enabled).

Implementation locations:

- `../src/extension_shield/api/supabase_auth.py` — Supabase JWT verification.
- `../src/extension_shield/api/database.py` — `SupabaseDatabase` class (used only when `DB_BACKEND=supabase`).
- `../src/extension_shield/api/main.py` — Cloud-only routes use `require_cloud_dep("feature_name")`; they return 501 in OSS mode.
- `../scripts/cloud_only/` — Supabase migrations and cloud-only scripts.

**Enforcement**: All cloud-only routes declare `dependencies=[require_cloud_dep("...")]` so the guard runs before any handler; in OSS mode no Supabase calls are made. See [OPEN_CORE_BOUNDARIES.md](../../docs/OPEN_CORE_BOUNDARIES.md).
