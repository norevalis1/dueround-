// Attack tests for the Supabase database shared by dueround and habit-tracker.
//
// Runs ONLY against a throwaway local copy (schema.sql loaded into a local
// Postgres + PostgREST). It refuses to run against a real supabase.co address.
//
//   PGREST_URL=http://localhost:3000 JWT_SECRET=... PGURI=postgres://... node attacks.mjs
//
// It creates test users A, B and C (C stands in for an admin; neither app has
// an admin role), runs every attack, prints a results table and deletes the
// test data at the end. Exit code 1 if any attack got through.

import { createHmac, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";

const BASE = process.env.PGREST_URL || "http://localhost:3000";
const SECRET = process.env.JWT_SECRET;
const PGURI = process.env.PGURI;
if (!SECRET || !PGURI) { console.error("Set JWT_SECRET and PGURI (see README.md)"); process.exit(2); }
if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(BASE)) { console.error("Refusing: tests only run against a local database."); process.exit(2); }

const b64u = (s) => Buffer.from(s).toString("base64url");
function jwt(claims) {
  const head = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...claims }));
  return head + "." + body + "." + createHmac("sha256", SECRET).update(head + "." + body).digest("base64url");
}
const sql = (q) => execFileSync("psql", [PGURI, "-v", "ON_ERROR_STOP=1", "-Atqc", q], { encoding: "utf8" }).trim();
const mask = (t) => (t ? t.slice(0, 6) + "…" + t.slice(-4) : "none");

const users = { A: randomUUID(), B: randomUUID(), C: randomUUID() };
const tokens = { anon: jwt({ role: "anon" }) };
for (const [k, id] of Object.entries(users)) tokens[k] = jwt({ role: "authenticated", sub: id, email: `test-${k.toLowerCase()}@example.test` });

async function call(who, method, path, body, extra = {}) {
  const headers = { "Content-Type": "application/json", Authorization: "Bearer " + tokens[who], Prefer: "return=representation", ...extra };
  const res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, text: await res.text() };
}

const results = [];
// expect: "refused" means the attack must fail. check() returns true when the attack got through.
async function attack(group, name, who, method, path, body, gotThrough, extra) {
  const r = await call(who, method, path, body, extra);
  const through = await gotThrough(r);
  results.push({ group, name, who, req: `${method} ${path}${body !== undefined ? " " + JSON.stringify(body).slice(0, 70) : ""}`, res: `${r.status} ${r.text.replace(/\s+/g, " ").slice(0, 90)}`, ok: !through });
  return r;
}
const rows = (r) => { try { const j = JSON.parse(r.text); return Array.isArray(j) ? j.length : 0; } catch { return 0; } };
const ok2xx = (r) => r.status >= 200 && r.status < 300;

try {
  // ---------- seed (as the database owner, like signing up three people) ----------
  sql(`insert into auth.users (id, email) values ('${users.A}','test-a@example.test'),('${users.B}','test-b@example.test'),('${users.C}','test-c@example.test')`);
const bHabit = JSON.parse((await call("B", "POST", "/habits", { name: "B's private habit" })).text)[0].id;
const aHabit = JSON.parse((await call("A", "POST", "/habits", { name: "A habit" })).text)[0].id;
await call("B", "POST", "/check_ins", { habit_id: bHabit, day: new Date().toISOString().slice(0, 10), note: "B's secret note" });
await call("B", "POST", "/push_subscriptions", { endpoint: "https://fcm.googleapis.com/fcm/send/test-b", p256dh: "x", auth: "y" });

  // ===== Impersonate other users =====
  const G1 = "Impersonation";
  for (const t of ["habits", "check_ins", "push_subscriptions", "waitlist"]) {
    await attack(G1, `Logged out, read every row of ${t}`, "anon", "GET", `/${t}?select=*`, undefined, (r) => rows(r) > 0);
  }
  await attack(G1, "Logged out, run the reminders function (lists everyone's habits)", "anon", "POST", "/rpc/due_reminders", {}, ok2xx);
  await attack(G1, "Logged out, delete all habits", "anon", "DELETE", "/habits?id=not.is.null", undefined, (r) => ok2xx(r) && sql("select count(*) from habits") === "0");
  await attack(G1, "A reads B's habit by id", "A", "GET", `/habits?id=eq.${bHabit}`, undefined, (r) => rows(r) > 0);
  await attack(G1, "A reads B's check-in notes", "A", "GET", `/check_ins?habit_id=eq.${bHabit}`, undefined, (r) => rows(r) > 0);
  await attack(G1, "A reads B's push keys", "A", "GET", `/push_subscriptions?select=*`, undefined, (r) => rows(r) > 0);
  await attack(G1, "A renames B's habit", "A", "PATCH", `/habits?id=eq.${bHabit}`, { name: "hacked" }, () => sql(`select name from habits where id='${bHabit}'`) === "hacked");
  await attack(G1, "A deletes B's habit", "A", "DELETE", `/habits?id=eq.${bHabit}`, undefined, () => sql(`select count(*) from habits where id='${bHabit}'`) === "0");
  await attack(G1, "A adds a check-in to B's habit", "A", "POST", "/check_ins", { habit_id: bHabit, day: "2026-01-01" }, ok2xx);
  await attack(G1, "A creates a habit owned by B", "A", "POST", "/habits", { name: "planted", user_id: users.B }, ok2xx);
  await attack(G1, "A moves own habit to B", "A", "PATCH", `/habits?id=eq.${aHabit}`, { user_id: users.B }, () => sql(`select user_id from habits where id='${aHabit}'`) === users.B);
  await attack(G1, "A takes over B's push subscription (same endpoint)", "A", "POST", "/push_subscriptions?on_conflict=endpoint", { endpoint: "https://fcm.googleapis.com/fcm/send/test-b", p256dh: "x", auth: "y" }, () => sql(`select user_id from push_subscriptions where endpoint like '%test-b'`) === users.A, { Prefer: "resolution=merge-duplicates,return=representation" });
  await attack(G1, "A adds role: admin to their own row", "A", "PATCH", `/habits?id=eq.${aHabit}`, { name: "ok", role: "admin" }, ok2xx);
  await attack(G1, "A reads the login table (auth.users)", "A", "GET", "/users?select=*", undefined, (r) => rows(r) > 0, { "Accept-Profile": "auth" });
  await attack(G1, "Forged token (signed with the wrong key)", "anon", "GET", "/habits?select=*", undefined, (r) => rows(r) > 0, { Authorization: "Bearer " + tokens.B.slice(0, -4) + "AAAA" });

  // ===== Get around limits in the UI =====
  const G2 = "Limits";
  sql(`insert into habits (user_id, name) select '${users.C}', 'h'||g from generate_series(1,55) g`);
  await Promise.all(Array.from({ length: 20 }, (_, i) => call("C", "POST", "/habits", { name: "burst " + i })));
  const cCount = +sql(`select count(*) from habits where user_id='${users.C}'`);
  results.push({ group: G2, name: "20 habit inserts at once with room for 5 (limit 60)", who: "C", req: "20 × POST /habits in parallel", res: `${cCount} habits after the burst`, ok: cCount <= 60 });
  await attack(G2, "61st habit sent straight to the API", "C", "POST", "/habits", { name: "one too many" }, ok2xx);
  await attack(G2, "Check-in dated far in the future", "A", "POST", "/check_ins", { habit_id: aHabit, day: "2099-01-01" }, ok2xx);
  await attack(G2, "Habit name 5,000 characters", "A", "POST", "/habits", { name: "x".repeat(5000) }, ok2xx);
  await attack(G2, "Empty habit name", "A", "POST", "/habits", { name: "" }, ok2xx);
  await attack(G2, "Negative color / goal", "A", "POST", "/habits", { name: "neg", color: -1, target_per_week: -3 }, ok2xx);
  await attack(G2, "Note 10,000 characters", "A", "POST", "/check_ins", { habit_id: aHabit, day: "2026-02-02", note: "n".repeat(10000) }, ok2xx);
  await attack(G2, "Waitlist: made-up trade and SQL in source", "anon", "POST", "/waitlist", { email: "x@example.test", trade: "'; drop table waitlist;--", tracking: "memory", source: "a' or 1=1--" }, ok2xx, { Prefer: "return=minimal" });
  await attack(G2, "SQL injection in a filter", "A", "GET", "/habits?name=eq.x' or '1'='1", undefined, (r) => rows(r) > 1);
  await attack(G2, "Push endpoint pointing at the cloud metadata address (SSRF)", "A", "POST", "/push_subscriptions", { endpoint: "http://169.254.169.254/latest/meta-data/", p256dh: "x", auth: "y" }, ok2xx);
  await attack(G2, "Push endpoint on a look-alike domain (SSRF)", "A", "POST", "/push_subscriptions", { endpoint: "https://fcm.googleapis.com.evil.test/x", p256dh: "x", auth: "y" }, ok2xx);

  // Waitlist speed limit: 25 sign-ups at once must give at most 20.
  sql("delete from waitlist");
  const burst = await Promise.all(Array.from({ length: 25 }, (_, i) => call("anon", "POST", "/waitlist", { email: `burst${i}@example.test`, trade: "hvac", tracking: "memory" }, { Prefer: "return=minimal" })));
  const okCount = burst.filter(ok2xx).length;
  results.push({ group: G2, name: "25 waitlist sign-ups at once (limit 20 a minute)", who: "anon", req: "25 × POST /waitlist in parallel", res: `${okCount} accepted, ${burst.filter((r) => r.status === 429).length} got 429`, ok: okCount <= 20 });
  // Can a bot that backdates created_at on every sign-up skip the speed limit?
  sql("delete from waitlist");
  let backdated = 0;
  for (let i = 0; i < 30; i++) {
    const r = await call("anon", "POST", "/waitlist", { email: `old${i}@example.test`, trade: "hvac", tracking: "memory", created_at: "2000-01-01T00:00:00Z" }, { Prefer: "return=minimal" });
    if (ok2xx(r)) backdated++;
  }
  results.push({ group: G2, name: "30 waitlist sign-ups in a row, each backdated to 2000 (limit 20 a minute)", who: "anon", req: `30 × POST /waitlist {..., "created_at":"2000-01-01T00:00:00Z"}`, res: `${backdated} accepted`, ok: backdated <= 20 });
  await attack(G2, "Waitlist: pick your own row id", "anon", "POST", "/waitlist", { id: "00000000-0000-0000-0000-000000000001", email: "id@example.test", trade: "hvac", tracking: "memory" }, () => sql("select count(*) from waitlist where id='00000000-0000-0000-0000-000000000001'") === "1", { Prefer: "return=minimal" });
  await attack(G2, "Logged out, read back the waitlist after joining", "anon", "GET", "/waitlist?select=email", undefined, (r) => rows(r) > 0);
} finally {
  // ---------- clean up all test data ----------
  sql(`delete from waitlist; delete from auth.users where id in ('${users.A}','${users.B}','${users.C}')`);
}

const left = sql("select (select count(*) from habits)+(select count(*) from check_ins)+(select count(*) from push_subscriptions)+(select count(*) from waitlist)+(select count(*) from auth.users)");
console.log(`\nTokens used: anon ${mask(tokens.anon)}, A ${mask(tokens.A)}, B ${mask(tokens.B)}, C ${mask(tokens.C)}`);
console.log("| Group | Attack | As | Request | Response | Refused? |\n|---|---|---|---|---|---|");
for (const r of results) console.log(`| ${r.group} | ${r.name} | ${r.who} | \`${r.req.replace(/\|/g, "\\|")}\` | \`${r.res.replace(/\|/g, "\\|").replace(/`/g, "'")}\` | ${r.ok ? "yes" : "**NO**"} |`);
console.log(`\n${results.filter((r) => !r.ok).length} of ${results.length} attacks got through. Test rows left behind: ${left}.`);
process.exit(results.some((r) => !r.ok) ? 1 : 0);
