import { MongoClient, ObjectId, type Db } from "mongodb";
import { AppError } from "./security";

export type Role = "admin" | "viewer";
export type UserRecord = {
  _id: ObjectId;
  email: string;
  name: string;
  role: Role;
  active: boolean;
  passwordHash: string;
  authVersion: number;
  allProjects?: boolean;
  projectKeys?: string[];
  createdAt: Date;
  updatedAt: Date;
};
export type SessionRecord = { _id: string; userId: ObjectId; authVersion: number; expiresAt: Date; createdAt: Date };
type LimitRecord = { _id: string; count: number; expiresAt: Date };
const state = globalThis as typeof globalThis & { portalDb?: Promise<Db>; portalClient?: MongoClient };

export async function getDb(): Promise<Db> {
  if (!state.portalDb) {
    const uri = process.env.MONGODB_URI;
    const database = process.env.MONGODB_DB || "code_cop";
    if (!uri || uri.includes("CLUSTER_HOST") || uri.includes("URL_ENCODED_PASSWORD")) throw new AppError(503, "Database is not configured. Set MONGODB_URI in .env.local and restart.");
    if (!/^[A-Za-z0-9_-]{1,63}$/.test(database)) throw new AppError(503, "MONGODB_DB must be a simple database name.");
    const client = new MongoClient(uri, { maxPoolSize: 10, serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000, socketTimeoutMS: 15000 });
    state.portalClient = client;
    state.portalDb = (async () => {
      try {
        await client.connect();
        const db = client.db(database);
        await Promise.all([
          db.collection("users").createIndex({ email: 1 }, { unique: true }),
          db.collection("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
          db.collection("sessions").createIndex({ userId: 1 }),
          db.collection("login_limits").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
        ]);
        return db;
      } catch {
        state.portalDb = undefined;
        await client.close().catch(() => undefined);
        throw new AppError(503, "Database unavailable. Check Atlas credentials, network access, and your internet connection.");
      }
    })();
  }
  return state.portalDb;
}
export async function collections() {
  const db = await getDb();
  return { users: db.collection<UserRecord>("users"), sessions: db.collection<SessionRecord>("sessions"), limits: db.collection<LimitRecord>("login_limits") };
}
export async function closeDb() {
  await state.portalClient?.close();
  state.portalDb = undefined;
  state.portalClient = undefined;
}
