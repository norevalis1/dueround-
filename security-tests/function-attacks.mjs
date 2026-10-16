// Attack tests for the habit-tracker "send-reminders" server function,
// run against a LOCAL copy of the function (Deno) and the local test database.
//
//   FUNCTION_URL=http://localhost:54330 JWT_SECRET=... PGURI=... CRON_SECRET=... SSRF_LOG=/path/hits.log node function-attacks.mjs
//
// SSRF_LOG is the log of a small local listener on 127.0.0.1:9999 that stands in
// for an internal service; any line in it means the function made the request.

import { createHmac, randomUUID, createECDH, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const { FUNCTION_URL, JWT_SECRET, PGURI, CRON_SECRET, SSRF_LOG } = process.env;
if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(FUNCTION_URL || "")) { console.error("Refusing: only a local copy of the function."); process.exit(2); }
const sql = (q) => execFileSync("psql", [PGURI, "-v", "ON_ERROR_STOP=1", "-Atqc", q], { encoding: "utf8" }).trim();
const b64u = (s) => Buffer.from(s).toString("base64url");
const jwt = (c, key = JWT_SECRET) => { const h = b64u('{"alg":"HS256","typ":"JWT"}'), b = b64u(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...c })); return h + "." + b + "." + createHmac("sha256", key).update(h + "." + b).digest("base64url"); };
const hits = () => (fs.existsSync(SSRF_LOG) ? fs.readFileSync(SSRF_LOG, "utf8").trim().split("\n").filter(Boolean).length : 0);

const A = randomUUID();
const phone = createECDH("prime256v1"); phone.generateKeys(); // a pretend phone's push keys
const results = [];
async function attack(name, headers, gotThrough) {
  const res = await fetch(FUNCTION_URL, { method: "POST", headers });
  const r = { status: res.status, text: (await res.text()).slice(0, 90) };
  results.push({ name, req: Object.keys(headers).join(", ") || "no credentials", res: `${r.status} ${r.text}`, ok: !gotThrough(r) });
}

try {
  sql(`insert into auth.users (id, email) values ('${A}', 'test-a@example.test')`);
  await attack("No login at all", {}, (r) => r.status < 400);
  await attack("Made-up token", { Authorization: "Bearer not-a-token" }, (r) => r.status < 400);
  await attack("Token signed with the wrong key", { Authorization: "Bearer " + jwt({ sub: A, role: "authenticated" }, "wrong-key") }, (r) => r.status < 400);
  await attack("Expired token", { Authorization: "Bearer " + jwt({ sub: A, role: "authenticated", exp: 1 }) }, (r) => r.status < 400);
  await attack("Guessed scheduler secret", { "x-cron-secret": "guess" }, (r) => r.status < 400);
  await attack("Public key used as a login", { Authorization: "Bearer sb_publishable_BRYsZUKxHwL43t36mRF0nA_YF-6rMsQ" }, (r) => r.status < 400);

  // SSRF: a subscription that points at an internal address. The database already
  // refuses these (push_endpoint_host); drop that rule here, locally, to test the
  // function's own guard on its own.
  sql("alter table push_subscriptions drop constraint push_endpoint_host");
  sql(`insert into push_subscriptions (user_id, endpoint, p256dh, auth) values ('${A}', 'http://127.0.0.1:9999/internal-admin', '${phone.getPublicKey("base64url")}', '${randomBytes(16).toString("base64url")}')`);
  const before = hits();
  await attack("SSRF: A's push address points at an internal service", { Authorization: "Bearer " + jwt({ sub: A, role: "authenticated", email: "test-a@example.test" }) }, () => hits() > before);
  results[results.length - 1].res += ` · internal service got ${hits() - before} request(s)`;
  await attack("Legit: A presses 'Send a test' while logged in", { Authorization: "Bearer " + jwt({ sub: A, role: "authenticated", email: "test-a@example.test" }) }, (r) => r.status !== 200);
  results[results.length - 1].name += " (should work)";
} finally {
  sql(`delete from auth.users where id='${A}'`);
  sql("alter table push_subscriptions add constraint push_endpoint_host check (endpoint ~ '^https://(fcm\\.googleapis\\.com|updates\\.push\\.services\\.mozilla\\.com|[a-z0-9.-]+\\.push\\.apple\\.com|[a-z0-9.-]+\\.notify\\.windows\\.com)/') not valid");
}

console.log("| Attack on send-reminders | Sent | Response | Refused? |\n|---|---|---|---|");
for (const r of results) console.log(`| ${r.name} | ${r.req} | \`${r.res.replace(/\|/g, "\\|")}\` | ${r.ok ? "yes" : "**NO**"} |`);
console.log(`\n${results.filter((r) => !r.ok).length} of ${results.length} got through.`);
process.exit(results.some((r) => !r.ok) ? 1 : 0);
