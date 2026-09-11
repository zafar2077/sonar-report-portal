import { requirePageUser } from "@/lib/auth";
import ReportStudio from "./report-studio";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export default async function Home() {
  const user = await requirePageUser();
  return <ReportStudio user={user} />;
}
