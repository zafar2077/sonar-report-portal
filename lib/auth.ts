import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { sessionUser, type PublicUser } from "./accounts";
import { AppError, appOrigin } from "./security";

export const SESSION_COOKIE = "code_cop_session";
export function sessionCookieOptions() {
  return { httpOnly: true, secure: appOrigin().startsWith("https:"), sameSite: "lax" as const, path: "/" };
}
export async function currentUser(): Promise<PublicUser | null> {
  return sessionUser((await cookies()).get(SESSION_COOKIE)?.value);
}
export async function requireApiUser(admin = false) {
  const user = await currentUser();
  if (!user) throw new AppError(401, "Your session has expired. Sign in again.");
  if (admin && user.role !== "admin") throw new AppError(403, "Administrator access required.");
  return user;
}
export async function requirePageUser(admin = false) {
  const user = await currentUser();
  if (!user) redirect("/login");
  if (admin && user.role !== "admin") redirect("/");
  return user;
}
