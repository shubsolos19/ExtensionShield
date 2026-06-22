# CLI (MIT — Public)

The ExtensionShield CLI is part of the open core. Entry point:

- **`../src/extension_shield/cli/main.py`** — `extension-shield` command (local scan from URL or file, JSON output, report generation).

Install and run:

```bash
# After uv sync / pip install -e .
extension-shield analyze URL=https://chromewebstore.google.com/detail/...
# or
make analyze URL=...
```

CLI uses the same scoring engine and analyzers as the API; no cloud required. See [OPEN_CORE_BOUNDARIES.md](../../docs/OPEN_CORE_BOUNDARIES.md).
