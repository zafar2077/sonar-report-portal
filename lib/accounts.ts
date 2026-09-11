import { ObjectId, MongoServerError } from "mongodb";
import { collections, type UserRecord } from "./db";
import { AppError, hashPassword, newToken, normalizeEmail, tokenHash, validateName, validatePassword, verifyPassword } from "./security";

export const SESSION_SECONDS = 8 * 60 * 60;
function validateProjectKeys(value: unknown, required: boolean) {
  if (!Array.isArray(value)) {
    if (required) throw new AppError(400, "Assign at least one Sonar project to a viewer.");
    return [];
  }
  if (value.length > 500) throw new AppError(400, "Too many projects selected.");
  const keys = [...new Set(value.map(item => {
    if (typeof item !== "string") throw new AppError(400, "Invalid Sonar project selection.");
    const key = item.trim();
    if (!key || key.length > 400 || /[\u0000-\u001f\u007f]/.test(key)) throw new AppError(400, "Invalid Sonar project selection.");
    return key;
  }))];
  if (required && !keys.length) throw new AppError(400, "Assign at least one Sonar project to a viewer.");
  return keys;
}
export function publicUser(user: UserRecord) {
  return {
    id: user._id.toHexString(),
    email: user.email,
    name: user.name,
    role: user.role,
    active: user.active,
    allProjects: user.role === "admin" || user.allProjects === true,
    projectKeys: user.role === "admin" ? [] : validateProjectKeys(user.projectKeys, false),
  };
}
export type PublicUser = ReturnType<typeof publicUser>;
export async function createAccount(input: { name: unknown; email: unknown; password: unknown; role: unknown; projectKeys?: unknown }) {
  const name = validateName(input.name), email = normalizeEmail(input.email);
  validatePassword(input.password);
  if (input.role !== "admin" && input.role !== "viewer") throw new AppError(400, "Choose administrator or viewer.");
  const { users } = await collections();
  const now = new Date();
  const user: UserRecord = {
    _id: new ObjectId(), name, email, role: input.role, active: true,
    passwordHash: await hashPassword(input.password), authVersion: 1,
    allProjects: input.role === "admin",
    projectKeys: input.role === "viewer" ? validateProjectKeys(input.projectKeys, true) : [],
    createdAt: now, updatedAt: now,
  };
  try { await users.insertOne(user); }
  catch (error) {
    if (error instanceof MongoServerError && error.code === 11000) throw new AppError(409, "An account with this email already exists.");
    throw error;
  }
  return publicUser(user);
}
async function limitAttempt(key: string, maximum: number, windowMs: number) {
  const { limits } = await collections();
  const window = Math.floor(Date.now() / windowMs);
  const id = `${key}:${window}`;
  const update = { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date((window + 2) * windowMs) } };
  let record;
  try { record = await limits.findOneAndUpdate({ _id: id }, update, { upsert: true, returnDocument: "after" }); }
  catch (error) {
    if (!(error instanceof MongoServerError) || error.code !== 11000) throw error;
    record = await limits.findOneAndUpdate({ _id: id }, { $inc: { count: 1 } }, { returnDocument: "after" });
  }
  if (!record || record.count > maximum) throw new AppError(429, "Too many attempts. Wait 15 minutes before trying again.");
}
export async function login(emailInput: unknown, password: unknown) {
  // App-wide budget also limits attempts using random emails. No untrusted proxy headers.
  await limitAttempt("all", 100, 15 * 60 * 1000);
  const email = normalizeEmail(emailInput);
  await limitAttempt(`email:${tokenHash(email)}`, 10, 15 * 60 * 1000);
  if (typeof password !== "string" || Buffer.byteLength(password) > 512) throw new AppError(401, "Invalid email or password.");
  const { users, sessions } = await collections();
  const user = await users.findOne({ email });
  const valid = await verifyPassword(password, user?.passwordHash);
  if (!valid || !user?.active) throw new AppError(401, "Invalid email or password.");
  const token = newToken();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1000);
  await sessions.insertOne({ _id: tokenHash(token), userId: user._id, authVersion: user.authVersion, createdAt: new Date(), expiresAt });
  return { token, user: publicUser(user), expiresAt };
}
export async function sessionUser(token?: string) {
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const { users, sessions } = await collections();
  // TTL cleanup is asynchronous; expiry must also be enforced in this query.
  const session = await sessions.findOne({ _id: tokenHash(token), expiresAt: { $gt: new Date() } });
  if (!session) return null;
  const user = await users.findOne({ _id: session.userId, active: true, authVersion: session.authVersion });
  return user ? publicUser(user) : null;
}
export async function revokeSession(token?: string) {
  if (token && /^[a-f0-9]{64}$/.test(token)) await (await collections()).sessions.deleteOne({ _id: tokenHash(token) });
}
export async function updateAccount(actor: PublicUser, id: unknown, action: unknown, value: unknown) {
  if (actor.role !== "admin") throw new AppError(403, "Administrator access required.");
  if (typeof id !== "string" || !/^[a-f0-9]{24}$/.test(id)) throw new AppError(400, "Invalid account.");
  const { users } = await collections();
  const target = await users.findOne({ _id: new ObjectId(id) });
  if (!target) throw new AppError(404, "Account not found.");
  // Other administrators are immutable from this UI: prevents lockout and concurrent demotions.
  if (target.role === "admin" && (action !== "password" || actor.id !== id)) throw new AppError(403, "Administrator accounts cannot be disabled or changed here.");
  const changes: Partial<UserRecord> = { updatedAt: new Date() };
  if (action === "active" && typeof value === "boolean") changes.active = value;
  else if (action === "password") { validatePassword(value); changes.passwordHash = await hashPassword(value); }
  else if (action === "projects" && target.role === "viewer") {
    changes.allProjects = false;
    changes.projectKeys = validateProjectKeys(value, true);
  }
  else throw new AppError(400, "Invalid account action.");
  if (action === "projects") {
    // Sessions resolve the current user on every request, so permission changes apply immediately.
    await users.updateOne({ _id: target._id }, { $set: changes });
  } else {
    // Bumping the version revokes sessions atomically, including login/reset races.
    await users.updateOne({ _id: target._id }, { $set: changes, $inc: { authVersion: 1 } });
  }
  return { ok: true };
}
