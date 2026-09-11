"use client";
import { useEffect, useState, type FormEvent } from "react";
import type { PublicUser } from "@/lib/accounts";
import AccountControls from "../../account-controls";
type Project = { key: string; name: string };
export default function UserManagement({ currentUser }: { currentUser: PublicUser }) {
  const [users, setUsers] = useState<PublicUser[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState("");
  const [projectError, setProjectError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [resetId, setResetId] = useState("");
  const [accessId, setAccessId] = useState("");
  const [accessProjects, setAccessProjects] = useState<string[]>([]);
  const [createRole, setCreateRole] = useState<"admin" | "viewer">("viewer");
  const [createProjects, setCreateProjects] = useState<string[]>([]);
  async function request(method = "GET", body?: unknown) {
    const response = await fetch("/api/admin/users", { method, cache: "no-store", headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
    if (response.status === 401) { window.location.replace("/login"); throw new Error("Sign in again."); }
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to update users.");
    return result;
  }
  async function reload() {
    try { setUsers((await request()).users); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to load users."); }
    finally { setLoading(false); }
  }
  async function loadProjects() {
    setProjectError("");
    try {
      const response = await fetch("/api/sonar?action=projects", { cache: "no-store" });
      if (response.status === 401) { window.location.replace("/login"); return; }
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to load Sonar projects.");
      setProjects(result.projects || []);
    } catch (e) { setProjectError(e instanceof Error ? e.message : "Unable to load Sonar projects."); }
  }
  useEffect(() => { void reload(); void loadProjects(); }, []);
  function toggleProject(key: string, selected: string[], setSelected: (value: string[]) => void) {
    setSelected(selected.includes(key) ? selected.filter(item => item !== key) : [...selected, key]);
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const values = new FormData(form);
    setBusy(true); setError(""); setMessage("");
    try {
      await request("POST", { ...Object.fromEntries(values), role: createRole, projectKeys: createRole === "viewer" ? createProjects : [] });
      form.reset(); setCreateRole("viewer"); setCreateProjects([]); setMessage("Account created. Share the password through your approved secure channel."); await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to create user."); }
    finally { setBusy(false); }
  }
  async function update(id: string, action: string, value: unknown) {
    setBusy(true); setError(""); setMessage("");
    try {
      await request("PATCH", { id, action, value });
      if (id === currentUser.id && action === "password") { window.location.replace("/login"); return; }
      setResetId(""); setAccessId("");
      setMessage(action === "projects" ? "Project access updated immediately." : "Account updated. Previous sessions are no longer valid.");
      await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to update user."); }
    finally { setBusy(false); }
  }
  return <main className="users-screen">
    <header className="users-header"><div><a href="/">← Report studio</a><h1>Manage users</h1></div><AccountControls user={currentUser} /></header>
    <div className="users-grid">
      <section className="account-panel"><h2>Create account</h2><form className="account-form" onSubmit={create}>
        <label>Name<input name="name" required minLength={2} maxLength={100} autoComplete="name" /></label>
        <label>Email<input name="email" type="email" required maxLength={254} autoComplete="off" /></label>
        <label>Password<input name="password" type="password" required minLength={15} maxLength={128} autoComplete="new-password" /></label>
        <small>Use a unique passphrase of at least 15 characters.</small>
        <label>Role<select name="role" value={createRole} onChange={event => setCreateRole(event.target.value as "admin" | "viewer")}><option value="viewer">Viewer — assigned projects only</option><option value="admin">Administrator — all projects and users</option></select></label>
        {createRole === "viewer" && <fieldset className="project-picker">
          <legend>Project access</legend>
          {projectError && <p className="account-error">{projectError} <button type="button" onClick={loadProjects}>Retry</button></p>}
          {!projectError && !projects.length && <small>No Sonar projects are available. Check the Sonar connection before creating a viewer.</small>}
          {projects.map(project => <label className="project-option" key={project.key}>
            <input type="checkbox" checked={createProjects.includes(project.key)} onChange={() => toggleProject(project.key, createProjects, setCreateProjects)} />
            <span><strong>{project.name}</strong><small>{project.key}</small></span>
          </label>)}
        </fieldset>}
        <button className="account-primary" disabled={busy}>Create user</button>
      </form></section>
      <section className="account-panel"><h2>Accounts</h2>
        {error && <p className="account-error" role="alert">{error} <button onClick={reload} disabled={busy}>Retry loading</button></p>}
        {message && <p className="account-message" role="status">{message}</p>}
        {loading ? <p>Loading accounts…</p> : <div className="users-list">{users.map(user => <article className="user-row" key={user.id}>
          <div><strong>{user.name}</strong><span>{user.email}</span><small>{user.role === "admin" ? "Administrator · All projects" : `Viewer · ${user.projectKeys.length} project${user.projectKeys.length === 1 ? "" : "s"}`} · {user.active ? "Active" : "Disabled"}</small></div>
          <div className="user-actions">
            {user.role !== "admin" && <button disabled={busy} onClick={() => update(user.id, "active", !user.active)}>{user.active ? "Disable" : "Enable"}</button>}
            {user.role !== "admin" && <button disabled={busy || !projects.length} onClick={() => { setResetId(""); setAccessId(user.id); setAccessProjects(user.projectKeys); }}>Project access</button>}
            {(user.role !== "admin" || user.id === currentUser.id) && <button disabled={busy} onClick={() => setResetId(user.id)}>Set password</button>}
          </div>
          {accessId === user.id && <form className="account-form access-form" onSubmit={event => { event.preventDefault(); void update(user.id, "projects", accessProjects); }}>
            <fieldset className="project-picker"><legend>Allowed Sonar projects</legend>
              {projects.map(project => <label className="project-option" key={project.key}>
                <input type="checkbox" checked={accessProjects.includes(project.key)} onChange={() => toggleProject(project.key, accessProjects, setAccessProjects)} />
                <span><strong>{project.name}</strong><small>{project.key}</small></span>
              </label>)}
            </fieldset>
            <small>At least one project is required. Changes apply to the viewer immediately.</small>
            <div className="access-actions"><button className="account-primary" disabled={busy || !accessProjects.length}>Save access</button><button type="button" onClick={() => setAccessId("")} disabled={busy}>Cancel</button></div>
          </form>}
          {resetId === user.id && <form className="account-form reset-form" onSubmit={event => { event.preventDefault(); const form = event.currentTarget; const password = new FormData(form).get("password"); void update(user.id, "password", password).then(() => form.reset()); }}>
            <label>New password<input type="password" name="password" required minLength={15} maxLength={128} autoComplete="new-password" autoFocus /></label>
            <small>This signs the user out of all existing sessions.</small>
            <button className="account-primary" disabled={busy}>Save password</button><button type="button" onClick={() => setResetId("")} disabled={busy}>Cancel</button>
          </form>}
        </article>)}</div>}
        <p className="account-help">Administrators can access every project available to the configured Sonar token. Viewers can only list and generate reports for their assigned projects.</p>
      </section>
    </div>
  </main>;
}
