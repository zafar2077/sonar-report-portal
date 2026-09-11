import { NextResponse } from "next/server";
import { AppError } from "./security";
export function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: { "Cache-Control": "private, no-store" } });
}
export function apiError(error: unknown) {
  if (error instanceof AppError) {
    const response = json({ error: error.message }, error.status);
    if (error.status === 429) response.headers.set("Retry-After", "900");
    return response;
  }
  // Never echo driver errors: they may contain credentials or infrastructure details.
  console.error("Account operation failed:", error instanceof Error ? error.name : "UnknownError");
  return json({ error: "Account service unavailable. Please try again." }, 503);
}
