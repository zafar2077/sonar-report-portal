import { requireApiUser } from "@/lib/auth";
import { json, apiError } from "@/lib/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET() {
  try { return json({ user: await requireApiUser() }); }
  catch (error) { return apiError(error); }
}
