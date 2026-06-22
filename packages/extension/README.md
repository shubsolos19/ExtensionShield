# Extension / Web UI (MIT — Public)

The scanner web UI is part of the open core. Canonical source:

- **`../frontend/`** — React app (trigger scan, upload CRX/ZIP, view report). No proprietary logic or secrets in the frontend bundle; auth/history/cloud UI is gated by `VITE_AUTH_ENABLED` and returns 501 from the API when not in cloud mode.

In OSS mode the UI works without sign-in; cloud-only features (history, karma, review queue, enterprise forms) are hidden or disabled and the API returns HTTP 501 for those routes.

See [OPEN_CORE_BOUNDARIES.md](../../docs/OPEN_CORE_BOUNDARIES.md).
