# Scripts

Use these when you need to run something outside the usual `make` targets (e.g. deploy, migrations, or one-off tasks). Prefer **Make** when possible: `make api`, `make deploy`, `make migrate`, etc.

## How to run (Make)

| What you want | Command |
|---------------|---------|
| Start API | `make api` |
| Check Railway env before deploy | `make deploy-check` |
| Deploy to Railway | `make deploy` |
| Run Supabase migrations | `make migrate` |
| Clear all scans (Cloud only) | `make clear-scans` |
| Check Postgres connection (Cloud) | `make validate-postgres` |

---

## What each script does

**Start / deploy**

- **start_api.sh** — Starts the API (used by Docker). You can run `make api` instead for local dev.
- **deploy.sh** — Pushes the app to Railway. Same as `make deploy`.
- **check_railway_env.sh** — Makes sure required env vars are set for Railway. Run before deploying.
- **sync_railway_env.sh** — Copies env from your `.env` into the Railway project. Handy after adding new keys.

**Supabase / database**

- **supabase_push_env.sh** — Pushes schema and env to Supabase (staging or prod). Run once per environment when you change migrations.
- **cloud_only/run_supabase_migrations.py** — Applies SQL migrations (used at startup when Supabase is configured, or in CI).
- **cloud_only/validate_postgres_local.py** — Checks that local dev is talking to the right Supabase DB. `make validate-postgres`.
- **cloud_only/lint_migrations.py** — Checks migration file names and order. `make lint-migrations`.
- **cloud_only/clear_all_scans.py** — Deletes every scan from the DB. Cloud only. `make clear-scans`.
- **cloud_only/delete_scans_before_extension.py** — Deletes scans for a given extension (admin cleanup). Run with `PYTHONPATH=src python scripts/cloud_only/delete_scans_before_extension.py "Extension Name"`.

**Security / CSP**

- **setup-production-csp.sh** — Builds the frontend and configures CSP headers for production.
- **verify-csp.sh** — Checks that CSP is correct (dev or prod). Run after changing headers.
- **security_smoke.sh** — Quick security checks. Run by hand when you want a sanity check.

**Auth / email (Cloud dev)**

- **send-resend-test-email.mjs** — Sends a test email via Resend. `npm run resend:test` or `node scripts/send-resend-test-email.mjs`.
- **debug-magic-link.mjs** — Helps debug magic-link sign-in. `node scripts/debug-magic-link.mjs your@email.com`.
- **supabase-set-smtp.mjs** — Configures SMTP in Supabase for auth emails. Run from project root when setting up a new project.

**Diagnostics (run by hand)**

- **check_local_db_backend.py** — Reports which database backend the API uses (SQLite vs Supabase) and where scans are stored. From root: `uv run python scripts/check_local_db_backend.py`.
- **verify_openai_api.py** — Validates `OPENAI_API_KEY` format and connectivity with a minimal OpenAI call. From root: `uv run python scripts/verify_openai_api.py`.

---

## Running scripts directly

Start API (same as Docker):

```bash
./scripts/start_api.sh
```

Check Railway env:

```bash
./scripts/check_railway_env.sh
```

Deploy:

```bash
./scripts/deploy.sh
```

Supabase schema push (staging vs prod):

```bash
./scripts/supabase_push_env.sh prod
# or with staging ref:
SUPABASE_STAGING_REF=your-ref ./scripts/supabase_push_env.sh staging
```

CSP (after changing headers):

```bash
./scripts/setup-production-csp.sh
./scripts/verify-csp.sh
```
