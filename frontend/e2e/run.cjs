/* Browser end-to-end test (Chromium via Playwright) against the REAL backend app and the REAL production frontend build.
 *
 *   node frontend/e2e/run.cjs            (from the repo root; needs Python deps for backend/ and `npm ci` in frontend/)
 *
 * WHAT IS REAL: the FastAPI app, auth (signed JWTs verified by the backend), RBAC, the durable queue + embedded worker,
 * detection, correlation, the agent pipeline code, and the built React app in a real browser.
 * WHAT IS NOT: the database is the in-memory PostgREST stand-in, the LLM is scripted, and Supabase Auth/Realtime are not
 * running (a session is injected into localStorage and Supabase requests are blocked). So this does not validate Supabase
 * sign-in, Realtime updates, or real LLM output.
 */
const { spawn, execFileSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..", "..");
const API_PORT = 8791;
const WEB_PORT = 4791;
const API = `http://127.0.0.1:${API_PORT}`;
const WEB = `http://127.0.0.1:${WEB_PORT}`;
const children = [];
let lastPage = null;
let failures = 0;
const results = [];

function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${!ok && detail ? ` -> ${detail}` : ""}`);
  if (!ok) failures++;
}

function start(cmd, args, opts) {
  const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
  children.push(p);
  return p;
}

async function waitFor(url, ms = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`timeout waiting for ${url}`);
}

function sessionFor(token, uid) {
  const exp = Math.floor(Date.now() / 1000) + 3600 * 12;
  return {
    access_token: token, refresh_token: "e2e-refresh", token_type: "bearer", expires_in: 43200, expires_at: exp,
    user: { id: uid, aud: "authenticated", role: "authenticated", email: `${uid}@example.com`, app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() },
  };
}

async function newPage(browser, tokens, users, who, errors) {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  await ctx.addInitScript(([key, sess, tok]) => {
    localStorage.setItem(key, JSON.stringify(sess));
    localStorage.setItem("threatbrain.auth.token", tok);
  }, ["sb-localhost-auth-token", sessionFor(tokens[who], users[who]), tokens[who]]);
  await ctx.route("http://localhost:54321/**", (r) => r.abort());   // Supabase Auth / Realtime are not part of this rig
  const page = await ctx.newPage();
  lastPage = page;
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !/54321|WebSocket|ERR_FAILED|Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`);
  });
  return page;
}

(async () => {
  console.log("building the frontend (production build against the rig's API)…");
  const env = { ...process.env, VITE_API_BASE_URL: `${API}/api/v1`, VITE_SUPABASE_URL: "http://localhost:54321", VITE_SUPABASE_ANON_KEY: "anon-e2e" };
  execFileSync("npx", ["vite", "build", "--outDir", "dist-e2e", "--emptyOutDir"], { cwd: path.join(ROOT, "frontend"), env, stdio: "ignore" });

  const py = process.env.PYTHON || "python3";
  const server = start(py, ["-m", "tests.e2e_server", "--port", String(API_PORT)], { cwd: path.join(ROOT, "backend"), env: { ...process.env, PYTHONPATH: ".", E2E_EXTRA_ORIGINS: WEB } });
  let first = "";
  server.stdout.on("data", (d) => { first += d.toString(); });
  server.stderr.on("data", () => {});
  await waitFor(`${API}/api/v1/health`);
  const boot = JSON.parse(first.split("\n").find((l) => l.startsWith("{")));
  const { tokens, users } = boot;
  start("npx", ["vite", "preview", "--outDir", "dist-e2e", "--port", String(WEB_PORT), "--strictPort", "--host", "127.0.0.1"], { cwd: path.join(ROOT, "frontend"), env });
  await waitFor(WEB);

  const browser = await chromium.launch();
  const errors = [];
  try {
    // ---------------------------------------------------------------- admin: onboarding + demo campaign
    let page = await newPage(browser, tokens, users, "admin_a", errors);
    await page.goto(`${WEB}/dashboard`);
    await page.getByRole("heading", { name: "Getting started" }).waitFor({ timeout: 15000 });
    check("dashboard shows the getting-started checklist", true);
    await page.getByRole("button", { name: /synthetic attack campaign/i }).click();
    const t0 = Date.now();
    let threats = 0;
    while (Date.now() - t0 < 30000) {
      const r = await (await fetch(`${API}/api/v1/threats`, { headers: { Authorization: `Bearer ${tokens.admin_a}` } })).json();
      threats = r.total ?? (r.items || []).length;
      if (threats >= 8) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    check("demo campaign is processed by the worker into threats", threats >= 8, `threats=${threats}`);
    await page.goto(`${WEB}/threats`);
    await page.getByText(/^THR-/).first().waitFor({ timeout: 15000 });
    const rows = await page.getByText(/^THR-/).count();
    check("threats page lists the detections produced from the demo events", rows >= 8, `rows=${rows}`);

    // ---------------------------------------------------------------- detection page
    await page.goto(`${WEB}/detection`);
    await page.getByText("Encoded or obfuscated PowerShell").waitFor({ timeout: 15000 });
    await page.getByLabel("Search rules").fill("TB-EXEC-001");
    check("rule search narrows the table", (await page.locator("tbody tr").count()) === 1);
    page.once("dialog", (d) => d.accept("noisy in our environment"));
    await page.getByRole("button", { name: "Disable" }).click();
    await page.getByText("disabled", { exact: true }).waitFor({ timeout: 10000 });
    check("disabling a built-in rule (with a reason) is reflected in the UI", true);
    const cov = await (await fetch(`${API}/api/v1/rules/coverage`, { headers: { Authorization: `Bearer ${tokens.admin_a}` } })).json();
    check("…and removes it from the tenant's coverage", !(cov.techniques["T1059.001"] || []).includes("TB-EXEC-001"));
    await page.getByRole("button", { name: "Enable" }).click();
    await page.getByText("enabled", { exact: true }).waitFor({ timeout: 10000 });

    await page.getByRole("tab", { name: "Coverage" }).click();
    await page.getByLabel(/Execution: \d+ of \d+ techniques covered/).waitFor();
    check("coverage tab renders per-tactic coverage with the honest caveat", await page.getByText(/not how well each rule detects/).isVisible());

    await page.getByRole("tab", { name: /Custom rules/ }).click();
    await page.getByRole("button", { name: /Validate & run tests/ }).click();
    await page.getByText(/Valid\. All tests pass/).waitFor({ timeout: 10000 });
    await page.getByRole("button", { name: "Save as draft" }).click();
    await page.getByText("corp-forbidden-tool", { exact: false }).first().waitFor({ timeout: 10000 });
    await page.getByRole("button", { name: "Enable" }).first().click();
    await page.getByText("enabled", { exact: true }).first().waitFor({ timeout: 10000 });
    check("custom rule: validate -> save draft -> enable (test-gated)", true);

    await page.getByRole("tab", { name: "Sigma import" }).click();
    await page.getByLabel("Sigma rule YAML").fill("title: Evil tool usage\nlevel: high\ntags: [attack.t1105]\nlogsource: {product: linux}\ndetection:\n  s:\n    CommandLine|contains: evil-tool\n  condition: s\n");
    await page.getByRole("button", { name: "Preview conversion" }).click();
    await page.getByText(/logsource is not enforced/).waitFor({ timeout: 10000 });
    check("sigma import previews the conversion with its caveat", true);
    await page.getByLabel("Sigma rule YAML").fill("title: Agg\ndetection:\n  s:\n    CommandLine|contains: a\n  condition: s | count() > 3\n");
    await page.getByRole("button", { name: "Preview conversion" }).click();
    await page.getByRole("alert").filter({ hasText: /unsupported/i }).waitFor({ timeout: 10000 });
    check("unsupported sigma (aggregation) is refused, not guessed", true);

    // ---------------------------------------------------------------- operations
    await page.goto(`${WEB}/operations`);
    await page.getByText("ready", { exact: true }).first().waitFor({ timeout: 15000 });
    check("operations page: platform reports ready", true);
    check("operations page: rule set and correlation count shown", await page.getByText(/rules, \d+ correlations/).isVisible());
    check("operations page: no dead-lettered jobs after the demo", await page.getByText(/None\. Every job that exhausted/).isVisible());

    // ---------------------------------------------------------------- settings: signed key + rotation + members
    await page.goto(`${WEB}/settings`);
    await page.getByPlaceholder("e.g. kali-lab collector").fill("e2e collector");
    await page.getByLabel("Require signed requests").check();
    await page.getByRole("button", { name: "Create key" }).click();
    await page.getByText(/Signing secret/).waitFor({ timeout: 10000 });
    check("signed key: secret shown once at creation", true);
    await page.getByRole("button", { name: "Done" }).click();
    page.once("dialog", (d) => d.accept());
    await page.getByRole("button", { name: /Rotate e2e collector/ }).click();
    await page.getByText(/Copy your new key now/).waitFor({ timeout: 10000 });
    check("key rotation issues a replacement with a new signing secret", await page.getByText(/Signing secret/).isVisible());
    const viewerRow = page.locator("li", { hasText: "viewer_a" }).first();
    const sel = page.getByLabel(/^Role for /).first();
    check("members: admin sees role controls", (await sel.count()) > 0);

    // ---------------------------------------------------------------- viewer: least privilege in the UI
    const vpage = await newPage(browser, tokens, users, "viewer_a", errors);
    await vpage.goto(`${WEB}/detection`);
    await vpage.getByText("Encoded or obfuscated PowerShell").waitFor({ timeout: 15000 }).catch(() => {});
    const denied = await vpage.getByRole("alert").first().isVisible().catch(() => false);
    const noEdit = (await vpage.getByRole("button", { name: "Disable" }).count()) === 0;
    check("viewer cannot use the detection editor (error shown or controls hidden)", denied || noEdit);
    await vpage.goto(`${WEB}/operations`);
    await vpage.getByRole("alert").waitFor({ timeout: 15000 });
    check("viewer gets a clear error on the admin-only operations page", true);

    // ---------------------------------------------------------------- hygiene
    check("no uncaught page errors or console errors during the run", errors.length === 0, errors.slice(0, 3).join(" | "));
    fs.mkdirSync(path.join(__dirname, "screenshots"), { recursive: true });
    await page.goto(`${WEB}/detection`);
    await page.screenshot({ path: path.join(__dirname, "screenshots", "detection.png") });
  } catch (e) {
    check("e2e run completed without an exception", false, String(e).split("\n")[0]);
    if (lastPage) {
      fs.mkdirSync(path.join(__dirname, "screenshots"), { recursive: true });
      await lastPage.screenshot({ path: path.join(__dirname, "screenshots", "failure.png") }).catch(() => {});
      console.log("url at failure:", lastPage.url());
      console.log("page text at failure:", ((await lastPage.locator("body").innerText().catch(() => "")) || "").slice(0, 600).replace(/\s+/g, " "));
      console.log("collected errors:", errors.slice(0, 5));
    }
  } finally {
    await browser.close();
    children.forEach((c) => { try { c.kill("SIGTERM"); } catch { /* already gone */ } });
    fs.rmSync(path.join(ROOT, "frontend", "dist-e2e"), { recursive: true, force: true });
  }
  console.log(`\n${results.length - failures} passed, ${failures} failed`);
  fs.writeFileSync(path.join(__dirname, "last-run.json"), JSON.stringify({ at: new Date().toISOString(), results }, null, 2));
  process.exit(failures ? 1 : 0);
})();
