import { requireApiUser } from "@/lib/auth";
import { collections } from "@/lib/db";
import { createAccount, publicUser, updateAccount } from "@/lib/accounts";
import { readJson } from "@/lib/security";
import { json, apiError } from "@/lib/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET() {
  try {
    await requireApiUser(true);
    const { users } = await collections();
    return json({ users: (await users.find({}).sort({ createdAt: -1 }).limit(500).toArray()).map(publicUser) });
  } catch (error) { return apiError(error); }
}
export async function POST(request: Request) {
  try {
    await requireApiUser(true);
    const input = await readJson(request);
    return json({ user: await createAccount({ name: input.name, email: input.email, password: input.password, role: input.role, projectKeys: input.projectKeys }) }, 201);
  } catch (error) { return apiError(error); }
}
export async function PATCH(request: Request) {
  try {
    const user = await requireApiUser(true);
    const input = await readJson(request);
    return json(await updateAccount(user, input.id, input.action, input.value));
  } catch (error) { return apiError(error); }
}
