import test from "node:test";
import assert from "node:assert/strict";
import { MongoMemoryServer } from "mongodb-memory-server-core";
import { closeDb, collections } from "../lib/db";
import { createAccount, login, revokeSession, sessionUser, updateAccount } from "../lib/accounts";
import { tokenHash } from "../lib/security";

// Always uses a disposable local MongoDB process, never the configured Atlas database.
test("MongoDB account and session lifecycle", { timeout: 180000 }, async t => {
  const mongo = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongo.getUri();
  process.env.MONGODB_DB = "portal_auth_test";
  const password = "Temporary testing passphrase 729!";
  try {
    const admin = await createAccount({ name: "Test Administrator", email: "admin@example.test", password, role: "admin" });
    const viewer = await createAccount({ name: "Test Viewer", email: "viewer@example.test", password, role: "viewer" });
    const db = await collections();
    await t.test("unique emails and restricted account payload", async () => {
      await assert.rejects(createAccount({ name: "Duplicate", email: " VIEWER@EXAMPLE.TEST ", password, role: "viewer" }), { status: 409 });
      assert.equal("passwordHash" in viewer, false);
      const row = await db.users.findOne({ email: viewer.email });
      assert.notEqual(row?.passwordHash, password);
      assert.match(row!.passwordHash, /^scrypt-v1/);
    });
    await t.test("login rejects wrong passwords and creates persistent hashed sessions", async () => {
      await assert.rejects(login(viewer.email, "Wrong password"), { status: 401 });
      const result = await login(viewer.email, password);
      assert.equal((await sessionUser(result.token))?.id, viewer.id);
      const row = await db.sessions.findOne({ _id: tokenHash(result.token) });
      assert.ok(row); assert.notEqual(row._id, result.token);
      await closeDb();
      assert.equal((await sessionUser(result.token))?.id, viewer.id);
      await revokeSession(result.token);
      assert.equal(await sessionUser(result.token), null);
    });
    await t.test("explicit expiry rejects sessions before TTL cleanup", async () => {
      const result = await login(viewer.email, password);
      await (await collections()).sessions.updateOne({ _id: tokenHash(result.token) }, { $set: { expiresAt: new Date(0) } });
      assert.equal(await sessionUser(result.token), null);
      assert.equal(await sessionUser("forged"), null);
    });
    await t.test("viewers cannot administer users and administrator lockout is blocked", async () => {
      await assert.rejects(updateAccount(viewer, admin.id, "active", false), { status: 403 });
      await assert.rejects(updateAccount(admin, admin.id, "active", false), { status: 403 });
    });
    await t.test("disabling and re-enabling never revives old sessions", async () => {
      const result = await login(viewer.email, password);
      await updateAccount(admin, viewer.id, "active", false);
      assert.equal(await sessionUser(result.token), null);
      await assert.rejects(login(viewer.email, password), { status: 401 });
      await updateAccount(admin, viewer.id, "active", true);
      assert.equal(await sessionUser(result.token), null);
    });
    await t.test("password resets invalidate all existing sessions", async () => {
      const result = await login(viewer.email, password);
      const replacement = "Another testing passphrase 582!";
      await updateAccount(admin, viewer.id, "password", replacement);
      assert.equal(await sessionUser(result.token), null);
      await assert.rejects(login(viewer.email, password), { status: 401 });
      assert.equal((await login(viewer.email, replacement)).user.id, viewer.id);
    });
    await t.test("persistent throttling bounds unknown-account attempts", async () => {
      for (let i = 0; i < 10; i++) await assert.rejects(login("unknown@example.test", "Wrong password"), { status: 401 });
      await assert.rejects(login("unknown@example.test", "Wrong password"), { status: 429 });
      await closeDb();
      await assert.rejects(login("unknown@example.test", "Wrong password"), { status: 429 });
    });
  } finally { await closeDb(); await mongo.stop(); }
});
