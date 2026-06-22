# Core (MIT — Public)

This directory documents the **open-core boundary**. The **Core (MIT) = trust layer**: the code that anyone can run locally to verify and improve extension security. The canonical source for the core scanner is:

- **`../src/extension_shield/`** — scoring engine, signal pack models, governance rules, local analyzers, API (scan/report/feedback), workflow, utils, LLM clients.

## What lives in Core (MIT)

- **Scoring engine**: `scoring/` (layers, normalizers, weights, gates, explainability)
- **Signal pack models**: `governance/signal_pack.py`, `governance/signal_extractor.py`
- **Local analyzers**: `core/analyzers/` (permissions, manifest, entropy, SAST, ChromeStats, webstore, VirusTotal wrapper — no API keys in code)
- **Storage**: SQLite implementation in `api/database.py` (`Database` class)
- **CLI**: `cli/main.py` (local scan, JSON output, report generation)
- **Report schema**: Same report structure for OSS and Cloud; no cloud-only fields required for local use

All of the above are MIT-licensed and fully functional with `EXTSHIELD_MODE=oss` (default). No Supabase or cloud calls in OSS mode.

See [OPEN_CORE_BOUNDARIES.md](../../docs/OPEN_CORE_BOUNDARIES.md) for the full boundary and enforcement.
