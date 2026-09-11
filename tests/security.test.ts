import test from "node:test";
import assert from "node:assert/strict";
import { appOrigin, assertSameOrigin, hashPassword, newToken, normalizeEmail, readJson, tokenHash, validatePassword, verifyPassword } from "../lib/security";

test("passwords are salted, verified, and bounded", async () => {
  const password = "A long testing passphrase 482!";
  const first = await hashPassword(password), second = await hashPassword(password);
  assert.notEqual(first, second);
  assert.equal(await verifyPassword(password, first), true);
  assert.equal(await verifyPassword("wrong password", first), false);
  assert.equal(await verifyPassword(password), false);
  assert.equal(await verifyPassword(password, "invalid"), false);
  assert.throws(() => validatePassword("short"));
  assert.throws(() => validatePassword("a".repeat(129)));
});
test("emails reject query objects and normalize casing", () => {
  assert.equal(normalizeEmail(" User@Example.com "), "user@example.com");
  assert.throws(() => normalizeEmail({ $ne: null }));
});
test("tokens are high entropy and only hashes are stored", () => {
  const first = newToken(), second = newToken();
  assert.match(first, /^[a-f0-9]{64}$/); assert.notEqual(first, second); assert.notEqual(tokenHash(first), first);
});
test("mutations require the configured origin and JSON; body is bounded", async () => {
  process.env.APP_ORIGIN = "http://localhost:5173";
  assertSameOrigin(new Request(appOrigin(), { headers: { origin: appOrigin() } }));
  assert.throws(() => assertSameOrigin(new Request(appOrigin(), { headers: { origin: "https://attacker.example" } })));
  assert.throws(() => assertSameOrigin(new Request(appOrigin())));
  const request = (body: string, type = "application/json") => new Request(appOrigin(), { method: "POST", headers: { origin: appOrigin(), "content-type": type }, body });
  assert.deepEqual(await readJson(request('{"name":"Test"}')), { name: "Test" });
  await assert.rejects(readJson(request("[]")));
  await assert.rejects(readJson(request("broken")));
  await assert.rejects(readJson(request("{}", "text/plain")));
  await assert.rejects(readJson(request(JSON.stringify({ text: "a".repeat(9000) }))));
  process.env.APP_ORIGIN = "http://public.example";
  assert.throws(appOrigin);
  process.env.APP_ORIGIN = "http://localhost:5173";
});
