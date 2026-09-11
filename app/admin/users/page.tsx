import { requirePageUser } from "@/lib/auth";
import UserManagement from "./user-management";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export default async function UsersPage() {
  const user = await requirePageUser(true);
  return <UserManagement currentUser={user} />;
}
