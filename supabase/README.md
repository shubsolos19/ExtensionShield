# Supabase database and migrations

This folder holds the Postgres schema for ExtensionShield when using Supabase. Migrations run in order by filename (timestamp prefix).

---

## Why did the CLI ask “Do you want to push these migrations?”

When you run `supabase db push`, the CLI:

1. **Compares** the migration files in `supabase/migrations/` with the list of migrations **already applied** on the remote database.
2. **Finds** any migrations that exist locally but have not been applied remotely.
3. **Asks** before applying them, because they will change the live database (add/change tables or columns).

So the prompt you saw means: *“I see a new migration file that hasn’t been applied to your linked project yet. Apply it now?”* Answering **Y** applies it; **n** cancels.

After you push, that migration is marked as applied. The next time you run `db push`, it won’t ask for that file again unless you reset migration history on the remote project.

---

## Recently pushed migration (Feb 2026)

**`20260210200000_scan_time_tracking.sql`**

Adds three columns to `scan_results`:

| Column | Purpose |
|--------|--------|
| `first_scanned_at` | When the extension was first scanned (set once). |
| `previous_scanned_at` | When it was scanned before the last run (for “hot” extensions). |
| `previous_scan_state` | JSON snapshot of the previous scan (e.g. user_count, rating) for analytics. |

Used for accurate “recently scanned” times and for future Hot-extensions analytics.

---

## How to push migrations

From the project root, with [Supabase CLI](https://supabase.com/docs/guides/cli) installed and logged in:

```bash
npx supabase login
npx supabase link --project-ref <your-project-ref>
npx supabase db push
```

Or use the project script (default prod ref):

```bash
./scripts/supabase_push_env.sh prod
```

When there are new migration files, the CLI will list them and ask for confirmation before applying.

---

## Migration list (order)

Migrations in `migrations/` are applied in filename order:

- `20260205000000_scan_results.sql` — base `scan_results` table
- `20260205000001_rename_timestamp_to_scanned_at.sql`
- `20260205000002_user_scan_history.sql`
- `20260205000003_page_views_daily.sql`
- `20260205000004_increment_page_view_rpc.sql`
- `20260205000005_statistics.sql`
- `20260206000000_add_icon_path.sql` — icon path on `scan_results`
- `20260206031453_add_user_profiles_karma.sql` — user_profiles, karma trigger
- `20260210200000_scan_time_tracking.sql` — first/previous scan time and state

Full schema details: the migrations listed above plus the consolidated SQL in [`supabase/schemas/`](schemas/).
