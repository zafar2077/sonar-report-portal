"use client";
import { useState, type FormEvent } from "react";
export default function LoginForm() {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    setError(""); setBusy(true);
    try {
      const response = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: fields.get("email"), password: fields.get("password") }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Unable to sign in.");
      form.reset();
      window.location.replace("/");
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to sign in."); }
    finally { setBusy(false); }
  }
  return <main className="auth-screen"><section className="auth-card">
    <div className="auth-brand"><img src="/codebase-technologies-logo.png" alt="Codebase Technologies" /></div>
    <h1>Sign in</h1><p>Code Quality Portal</p>
    <form onSubmit={submit} className="account-form">
      <label>Email<input name="email" type="email" autoComplete="username" maxLength={254} required autoFocus /></label>
      <label>Password<input name="password" type="password" autoComplete="current-password" maxLength={128} required /></label>
      {error && <p className="account-error" role="alert">{error}</p>}
      <button className="account-primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
    <p className="account-help">Need access or a password reset? Contact your portal administrator.</p>
  </section></main>;
}
