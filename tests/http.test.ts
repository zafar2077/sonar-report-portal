import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";

test("HTTP routes fail closed without a session", { timeout: 30000 }, async () => {
  const base = "http://localhost:5188";
  const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", "5188"], { env: { ...process.env, APP_ORIGIN: base, MONGODB_URI: "", SONAR_TOKEN: "" }, stdio: "pipe" });
  let output = "";
  server.stdout.on("data", data => { output += data; });
  server.stderr.on("data", data => { output += data; });
  try {
    for (let i = 0; i < 80; i++) {
      if (server.exitCode !== null) throw new Error("Test server failed to start.");
      if (output.includes("Ready")) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    for (const path of ["/", "/admin/users"]) {
      const r = await fetch(base + path, { redirect: "manual" });
      assert.equal(r.status, 307); assert.equal(r.headers.get("location"), "/login");
    }
    for (const path of ["/api/sonar?action=projects", "/api/auth/me", "/api/admin/users"]) {
      const r = await fetch(base + path);
      assert.equal(r.status, 401);
      assert.match(r.headers.get("cache-control") || "", /no-store/);
    }
    for (const method of ["POST", "PATCH"]) {
      const r = await fetch(base + "/api/admin/users", { method, headers: { origin: base, "content-type": "application/json" }, body: "{}" });
      assert.equal(r.status, 401);
    }
    const crossOrigin = await fetch(base + "/api/auth/login", { method: "POST", headers: { origin: "https://attacker.example", "content-type": "application/json" }, body: "{}" });
    assert.equal(crossOrigin.status, 403);
    const invalid = await fetch(base + "/api/auth/login", { method: "POST", headers: { origin: base, "content-type": "application/json" }, body: "broken" });
    assert.equal(invalid.status, 400);
    const unconfigured = await fetch(base + "/api/auth/login", { method: "POST", headers: { origin: base, "content-type": "application/json" }, body: JSON.stringify({ email: "test@example.test", password: "Test-only passphrase 729!" }) });
    assert.equal(unconfigured.status, 503);
    const login = await fetch(base + "/login");
    assert.equal(login.status, 200); assert.match(await login.text(), /Sign in/);
  } finally {
    if (server.exitCode === null) { const stopped = once(server, "exit"); server.kill("SIGTERM"); await stopped; }
  }
});
