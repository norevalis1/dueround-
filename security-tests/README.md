# Security tests

Attack tests for dueround's waitlist and the habit-tracker data that share the
same Supabase project. They run **only against a throwaway local copy** and
refuse to run against a `supabase.co` address. Run them again before each launch.

| File | What it attacks |
|---|---|
| `attacks.mjs` | The database through its web API: logged-out reads, A vs B, role tricks, limits, bursts, bad input, SQL injection, SSRF addresses |
| `browser-attacks.mjs` | The pages in a real browser: script injection (XSS), the `?src=` tag, the waitlist form, what the offline cache keeps |
| `function-attacks.mjs` | The `send-reminders` server function: login checks and SSRF |
| `schema.sql` | Copy of the live tables, access rules, triggers and grants (read 2026-10-16) |
| `fix-waitlist-columns.sql` | The fix from the 2026-10-16 audit |

## Set up the local copy

You need Postgres 16, [PostgREST](https://github.com/PostgREST/postgrest/releases) 12,
Node 22, Chromium and `playwright-core` (`npm i playwright-core`). Deno 2 for the function test.

1. Start an empty Postgres and create the Supabase-style roles and `auth` schema
   (`anon`, `authenticated`, `service_role`, `authenticator`, `auth.users`, `auth.uid()`).
2. Load `schema.sql`, then the fix files.
3. Start PostgREST with `db-anon-role = "anon"` and a random `jwt-secret` (keep it in `.env`, which git ignores).
4. Serve each app folder on a local port.

## Run

```sh
export JWT_SECRET=... PGURI=postgresql://postgres@localhost:54322/app
node attacks.mjs
DUEROUND_URL=http://localhost:8301/ HABITS_URL=http://localhost:8302/ SUBS_URL=http://localhost:8303/ \
  CHROMIUM=/path/to/chrome node browser-attacks.mjs
FUNCTION_URL=http://localhost:54330 SSRF_LOG=/tmp/hits.log node function-attacks.mjs
```

Each script prints a results table, deletes its test users and rows, and exits
with code 1 if any attack got through. Tokens are masked in the output.
