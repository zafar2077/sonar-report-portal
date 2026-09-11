import { NextRequest } from "next/server";
import { revokeSession } from "@/lib/accounts";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth";
import { assertSameOrigin } from "@/lib/security";
import { json, apiError } from "@/lib/http";
export const runtime = "nodejs";
export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request);
    await revokeSession(request.cookies.get(SESSION_COOKIE)?.value);
    const response = json({ ok: true });
    response.cookies.set(SESSION_COOKIE, "", { ...sessionCookieOptions(), maxAge: 0 });
    return response;
  } catch (error) { return apiError(error); }
}
