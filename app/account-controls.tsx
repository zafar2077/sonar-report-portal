"use client";
import { useEffect, useState } from "react";
import type { PublicUser } from "@/lib/accounts";
export default function AccountControls({ user }: { user: PublicUser }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const check = () => fetch("/api/auth/me", { cache: "no-store" }).then(r => { if (r.status === 401) window.location.replace("/login"); }).catch(() => undefined);
    const timer = window.setInterval(check, 60000);
    window.addEventListener("focus", check);
    // Revalidate pages restored from the browser back/forward cache.
    window.addEventListener("pageshow", check);
    return () => { window.clearInterval(timer); window.removeEventListener("focus", check); window.removeEventListener("pageshow", check); };
  }, []);
  async function logout() {
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/auth/logout", { method: "POST" });
      if (!response.ok) throw new Error("Could not sign out. Please retry.");
      window.location.replace("/login");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not sign out."); setBusy(false); }
  }
  return <div className="account-controls">
    <span>{user.name}</span>
    {user.role === "admin" && <a href="/admin/users">Manage users</a>}
    <button type="button" onClick={logout} disabled={busy}>{busy ? "Signing out…" : "Sign out"}</button>
    {error && <span role="alert">{error}</span>}
  </div>;
}
