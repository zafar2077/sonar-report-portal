import { NextRequest } from "next/server";
import { login, revokeSession, SESSION_SECONDS } from "@/lib/accounts";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth";
import { readJson } from "@/lib/security";
import { json, apiError } from "@/lib/http";
export const runtime = "nodejs";
export async function POST(request: NextRequest) {
  try {
    const input = await readJson(request);
    const result = await login(input.email, input.password);
    await revokeSession(request.cookies.get(SESSION_COOKIE)?.value);
    const response = json({ user: result.user });
    response.cookies.set(SESSION_COOKIE, result.token, { ...sessionCookieOptions(), maxAge: SESSION_SECONDS });
    return response;
  } catch (error) { return apiError(error); }
}
