# Enterprise (Proprietary — Gated)

This directory documents **enterprise-only** components. Enterprise features (org policies, enforcement, compliance packs, SSO, admin dashboards) are **not** open-sourced; they are part of ExtensionShield Cloud (hosted product) or gated behind `EXTSHIELD_MODE=cloud` and feature flags.

In this repo:

- **Gated routes**: Enterprise pilot request and careers apply forms are behind `require_cloud_dep("enterprise_forms")`; they return HTTP 501 in OSS mode.
- **Full enterprise product**: Policy enforcement workflows, Google Admin/MDM/SIEM integrations, curated intel, and enterprise dashboards are **not** implemented in this repository; they live in ExtensionShield Cloud.

See [OPEN_CORE_BOUNDARIES.md](../../docs/OPEN_CORE_BOUNDARIES.md).
