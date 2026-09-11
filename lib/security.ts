import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

export class AppError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export function normalizeEmail(value: unknown) {
  if (typeof value !== "string") throw new AppError(400, "Enter a valid email address.");
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new AppError(400, "Enter a valid email address.");
  return email;
}
export function validateName(value: unknown) {
  if (typeof value !== "string" || value.trim().length < 2 || value.trim().length > 100) throw new AppError(400, "Name must contain 2–100 characters.");
  return value.trim();
}
export function validatePassword(value: unknown): asserts value is string {
  if (typeof value !== "string" || [...value].length < 15 || [...value].length > 128 || Buffer.byteLength(value) > 512) throw new AppError(400, "Use a password or passphrase of 15–128 characters.");
}
function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, salt, 64, { N: 131072, r: 8, p: 1, maxmem: 192 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(key)));
}
export async function hashPassword(password: string) {
  validatePassword(password);
  const salt = randomBytes(16);
  const key = await derive(password, salt);
  return `scrypt-v1$${salt.toString("hex")}$${key.toString("hex")}`;
}
// Unknown users take the same expensive password-verification path.
const dummyHash = `scrypt-v1$${"0".repeat(32)}$${"0".repeat(128)}`;
export async function verifyPassword(password: string, encoded = dummyHash) {
  if (Buffer.byteLength(password) > 512) return false;
  const match = /^scrypt-v1\$([a-f0-9]{32})\$([a-f0-9]{128})$/.exec(encoded);
  if (!match) return false;
  const key = await derive(password, Buffer.from(match[1], "hex"));
  return timingSafeEqual(key, Buffer.from(match[2], "hex"));
}
export function tokenHash(token: string) { return createHash("sha256").update(token).digest("hex"); }
export function newToken() { return randomBytes(32).toString("hex"); }
export function appOrigin() {
  const url = new URL(process.env.APP_ORIGIN || "http://localhost:5173");
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new AppError(503, "APP_ORIGIN must be an origin without a path.");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) throw new AppError(503, "Use HTTPS for a non-local APP_ORIGIN.");
  return url.origin;
}
export function assertSameOrigin(request: Request) {
  if (request.headers.get("origin") !== appOrigin() || request.headers.get("sec-fetch-site") === "cross-site") throw new AppError(403, "Request origin is not allowed. Open the configured app URL.");
}
export async function readJson(request: Request): Promise<Record<string, unknown>> {
  assertSameOrigin(request);
  if (request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") throw new AppError(415, "JSON content is required.");
  const reader = request.body?.getReader();
  if (!reader) throw new AppError(400, "Request body is required.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8192) { await reader.cancel(); throw new AppError(413, "Request is too large."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
    return body;
  } catch { throw new AppError(400, "Invalid JSON body."); }
}
