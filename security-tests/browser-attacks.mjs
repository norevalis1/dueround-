// Browser attack tests: script injection (XSS), the ?src= link tag, the
// waitlist form end to end, and what the habit app's offline cache keeps.
//
// Opens each app in headless Chromium from a local web server and sends every
// Supabase call to the local test copy (see README.md). Nothing reaches the
// real project: any request to another address is blocked and reported.
//
//   DUEROUND_URL=http://localhost:8301/ HABITS_URL=http://localhost:8302/ SUBS_URL=http://localhost:8303/ \
//   PGREST_URL=http://localhost:3000 JWT_SECRET=... PGURI=... CHROMIUM=/path/to/chrome node browser-attacks.mjs

import { createHmac, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT || "playwright-core");

const { DUEROUND_URL, HABITS_URL, SUBS_URL, JWT_SECRET, PGURI } = process.env;
const PGREST = process.env.PGREST_URL || "http://localhost:3000";
const local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//;
for (const u of [DUEROUND_URL, HABITS_URL, SUBS_URL, PGREST + "/"]) if (!local.test(u || "")) { console.error("Refusing: every URL must be local."); process.exit(2); }

const sql = (q) => execFileSync("psql", [PGURI, "-v", "ON_ERROR_STOP=1", "-Atqc", q], { encoding: "utf8" }).trim();
const b64u = (s) => Buffer.from(s).toString("base64url");
function jwt(claims) {
  const head = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...claims }));
  return head + "." + body + "." + createHmac("sha256", JWT_SECRET).update(head + "." + body).digest("base64url");
}

const PAYLOADS = [
  `<img src=x onerror="window.__xss=1;alert(1)">`,
  `"><svg onload="window.__xss=1;alert(2)">`,
  `[click](javascript:window.__xss=1)`,
];
const results = [];
const record = (name, how, res, ok) => results.push({ name, how, res, ok });

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM, args: ["--no-sandbox"] });

async function openPage(ctx) {
  const page = await ctx.newPage();
  page.dialogs = 0; page.outside = [];
  page.on("dialog", (d) => { page.dialogs++; d.dismiss(); });
  await page.route("**/*", async (route) => {
    const url = route.request().url();
    if (local.test(url) || url.startsWith("data:") || url.startsWith("blob:")) return route.continue();
    const m = url.match(/^https:\/\/[a-z0-9]+\.supabase\.co\/(rest|auth)\/v1(\/[^]*)$/);
    if (m && m[1] === "rest") {
      // The hosted gateway swaps the publishable key for an anon token; do the same here.
      const headers = { ...route.request().headers() };
      if (/^Bearer sb_publishable_/.test(headers.authorization || "")) headers.authorization = "Bearer " + jwt({ role: "anon" });
      return route.fulfill({ response: await route.fetch({ url: PGREST + m[2], headers }) });
    }
    if (m && m[1] === "auth") return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(page.authUser || {}) });
    page.outside.push(url);
    return route.abort();
  });
  return page;
}
const xssFired = async (page) => page.dialogs > 0 || (await page.evaluate(() => !!window.__xss));

const userA = randomUUID();
try {
  // ---------- dueround: ?src= tag and the waitlist form ----------
  {
    const ctx = await browser.newContext();
    const page = await openPage(ctx);
    await page.goto(DUEROUND_URL + "?src=" + encodeURIComponent(PAYLOADS[0] + "' or 1=1--"), { waitUntil: "networkidle" });
    await page.fill("#f-email", "browser-test@example.test");
    await page.selectOption("#f-trade", "hvac");
    await page.selectOption("#f-track", "memory");
    await page.selectOption("#f-want", "due_list");
    await page.click("#send");
    await page.waitForFunction(() => /list|save|Lots/.test(document.getElementById("msg").textContent), null, { timeout: 10000 });
    const msg = await page.textContent("#msg");
    const saved = sql("select coalesce(string_agg(source,','),'') from waitlist where email='browser-test@example.test'");
    record("dueround: script in the ?src= link tag", "Open /?src=<img onerror=…>' or 1=1-- and join the list", `alert fired: ${await xssFired(page)}; saved source: "${saved}"`, !(await xssFired(page)) && /^[a-z0-9_-]*$/.test(saved));
    record("dueround: waitlist form still saves", "Fill and send the form in the browser", `page says "${msg}"`, /on the list/.test(msg));
    record("dueround: no outside requests", "Watch every request the page makes", page.outside.length ? page.outside.join(" ") : "none", page.outside.length === 0);
    await ctx.close();
  }

  // ---------- habit-tracker: XSS in a habit name and a note, offline cache ----------
  {
    sql(`insert into auth.users (id, email) values ('${userA}', 'test-a@example.test')`);
    const habit = sql(`insert into habits (user_id, name) values ('${userA}', $$${PAYLOADS[0].slice(0, 60)}$$) returning id`);
    sql(`insert into habits (user_id, name) values ('${userA}', $$${PAYLOADS[1].slice(0, 60)}$$)`);
    sql(`insert into check_ins (user_id, habit_id, day, note) values ('${userA}', '${habit}', current_date - 1, $$${PAYLOADS[2]}$$)`);
    const token = jwt({ role: "authenticated", sub: userA, email: "test-a@example.test", aud: "authenticated" });
    const authUser = { id: userA, aud: "authenticated", role: "authenticated", email: "test-a@example.test", app_metadata: {}, user_metadata: {} };
    const ctx = await browser.newContext();
    await ctx.addInitScript(([k, v]) => { if (!localStorage.getItem(k)) localStorage.setItem(k, v); }, ["sb-ujmcxqopymupiwakwfdb-auth-token", JSON.stringify({ access_token: token, refresh_token: "test", token_type: "bearer", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, user: authUser })]);
    const page = await openPage(ctx);
    page.authUser = authUser;
    await page.goto(HABITS_URL, { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);
    const shown = await page.evaluate(() => document.body.innerText.includes("<img src=x"));
    // open History, where notes and calendars render
    await page.getByRole("tab", { name: /history/i }).click().catch(() => {});
    await page.waitForTimeout(800);
    record("habits: script in a habit name and a note", "Save <img onerror=…>, <svg onload=…> and a javascript: link, then open Today and History as that user", `shown as plain text: ${shown}; alert fired: ${await xssFired(page)}`, shown && !(await xssFired(page)));
    const cached = await page.evaluate(async () => { const out = []; for (const k of await caches.keys()) for (const r of await (await caches.open(k)).keys()) out.push(r.url); return out; });
    const leaky = cached.filter((u) => !u.startsWith(new URL(HABITS_URL).origin) || /\/(rest|auth)\/v1\//.test(u));
    record("habits: offline cache never keeps a person's data", "Log in as A, then list everything the service worker saved", `${cached.length} files saved, all app files: ${cached.map((u) => new URL(u).pathname.split("/").pop() || "/").join(", ")}`, leaky.length === 0);
    record("habits: no outside requests", "Watch every request the page makes", page.outside.length ? page.outside.join(" ") : "none", page.outside.length === 0);
    await ctx.close();
  }

  // ---------- Sub-Tracker: XSS in a subscription name ----------
  {
    const ctx = await browser.newContext();
    await ctx.addInitScript((v) => { if (!localStorage.getItem("subscriptions-v1")) localStorage.setItem("subscriptions-v1", v); }, JSON.stringify(PAYLOADS.map((p, i) => ({ id: i + 1, name: p, category: p, cost: 5, cycle: "monthly", date: "2026-11-01" }))));
    const page = await openPage(ctx);
    await page.goto(SUBS_URL, { waitUntil: "networkidle" });
    await page.waitForTimeout(800);
    const shown = await page.evaluate(() => document.body.innerText.includes("<img src=x"));
    record("Sub-Tracker: script in a subscription name and category", "Save <img onerror=…>, <svg onload=…> and a javascript: link as names", `shown as plain text: ${shown}; alert fired: ${await xssFired(page)}`, shown && !(await xssFired(page)));
    await ctx.close();
  }
} finally {
  sql(`delete from waitlist where email='browser-test@example.test'; delete from auth.users where id='${userA}'`);
  await browser.close();
}

console.log("| Attack | How | Result | Refused? |\n|---|---|---|---|");
for (const r of results) console.log(`| ${r.name} | ${r.how.replace(/\|/g, "\\|").replace(/</g, "&lt;")} | ${r.res.replace(/\|/g, "\\|").replace(/</g, "&lt;")} | ${r.ok ? "yes" : "**NO**"} |`);
console.log(`\n${results.filter((r) => !r.ok).length} of ${results.length} got through.`);
process.exit(results.some((r) => !r.ok) ? 1 : 0);
