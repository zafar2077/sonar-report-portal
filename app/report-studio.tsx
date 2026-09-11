"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { PublicUser } from "@/lib/accounts";
import AccountControls from "./account-controls";

type ReportType = "executive" | "owasp" | "cwe" | "full";
type Project = { key: string; name: string; qualifier?: string; visibility?: string };
type Branch = { name: string; isMain: boolean; type?: string; analysisDate?: string };
type Finding = {
  key: string; severity: string; type: string; message: string; component: string;
  line?: number; rule: string; effort?: string; status?: string; tags?: string[];
};
type Report = {
  project: { key: string; name: string; branch?: string; lastAnalysis?: string };
  gate: { status: string; conditions: { metric: string; status: string; actual?: string; threshold?: string }[] };
  metrics: Record<string, string | number>;
  findings: Finding[];
  generatedAt: string;
  source: "live" | "demo";
};

const reportTypes: { id: ReportType; title: string; description: string; badge: string }[] = [
  { id: "executive", title: "Executive overview", description: "Release-ready summary for management and governance.", badge: "Recommended" },
  { id: "owasp", title: "OWASP Top 10", description: "Security findings grouped against OWASP categories.", badge: "Security" },
  { id: "cwe", title: "CWE Top 25", description: "Weakness-focused view for AppSec and remediation.", badge: "AppSec" },
  { id: "full", title: "Full engineering", description: "All measures, ratings and prioritized issues.", badge: "Detailed" },
];

const metricLabels: Record<string, string> = {
  reliability_issues: "Reliability issues", security_issues: "Security issues", security_hotspots: "Security hotspots",
  maintainability_issues: "Maintainability issues", coverage: "Coverage", duplicated_lines_density: "Duplication",
};

function ratingTone(value: string | number) {
  if (["A", "0", 0].includes(value)) return "good";
  if (["B", "C"].includes(value as string)) return "warn";
  return "bad";
}

export default function ReportStudio({ user }: { user: PublicUser }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState("");
  const [branches, setBranches] = useState<Branch[]>([]);
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [branch, setBranch] = useState("");
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [connected, setConnected] = useState(false);
  const [notice, setNotice] = useState("Connecting to Sonar…");
  const branchRequest = useRef(0);

  async function loadBranches(projectKey: string) {
    const requestId = ++branchRequest.current;
    setBranchesLoading(true);
    setBranches([]);
    setBranch("");
    try {
      const response = await fetch(`/api/sonar?action=branches&project=${encodeURIComponent(projectKey)}`, { cache: "no-store" });
      if (response.status === 401) { window.location.replace("/login"); return; }
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Unable to load branches.");
      if (requestId !== branchRequest.current) return;
      const available: Branch[] = body.branches || [];
      setBranches(available);
      setBranch(available.find(item => item.isMain)?.name || available[0]?.name || "");
      setConnected(true);
      setNotice(available.length ? "Connected to Sonar" : "No analyzed branches found");
    } catch (error) {
      if (requestId !== branchRequest.current) return;
      setConnected(false);
      setNotice(error instanceof Error ? error.message : "Unable to load branches.");
    } finally {
      if (requestId === branchRequest.current) setBranchesLoading(false);
    }
  }

  useEffect(() => {
    fetch("/api/sonar?action=projects", { cache: "no-store" })
      .then(async r => {
        if (r.status === 401) { window.location.replace("/login"); return; }
        const body = await r.json();
        if (!r.ok) throw new Error(body.error || "Unable to load projects.");
        setProjects(body.projects || []);
        const firstProject = body.projects?.[0]?.key || "";
        setSelected(firstProject);
        setConnected(true);
        setNotice(body.projects?.length ? "Connected to Sonar" : "No accessible projects found");
        if (firstProject) void loadBranches(firstProject);
      }).catch(error => setNotice(error.message || "Unable to connect to Sonar."));
  }, []);

  const selectedProject = projects.find(p => p.key === selected) || projects[0];
  const filteredFindings = useMemo(() => {
    if (!report) return [];
    if (reportType === "owasp") return report.findings.filter(f => f.tags?.some(t => t.startsWith("owasp")) || f.type === "VULNERABILITY" || f.type === "SECURITY_HOTSPOT");
    if (reportType === "cwe") return report.findings.filter(f => f.tags?.includes("cwe") || f.type === "VULNERABILITY");
    return report.findings;
  }, [report, reportType]);

  async function generateReport() {
    setLoading(true); setReport(null);
    try {
      const params = new URLSearchParams({ action: "report", project: selected, branch, reportType });
      const res = await fetch(`/api/sonar?${params}`);
      if (res.status === 401) { window.location.replace("/login"); return; }
      if (!res.ok) { const body = await res.json(); throw new Error(body.error || "Unable to generate report."); }
      const body = await res.json(); setReport(body); setConnected(true); setNotice("Live Sonar data");
    } catch (error) {
      setConnected(false);
      setNotice(error instanceof Error ? error.message : "Unable to generate report.");
    } finally { setLoading(false); }
  }

  function exportCsv() {
    if (!report) return;
    const rows = [["Severity", "Type", "Rule", "Finding", "Component", "Line", "Effort"], ...filteredFindings.map(f => [f.severity, f.type, f.rule, f.message, f.component, String(f.line || ""), f.effort || ""])];
    const csv = rows.map(r => r.map(v => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); link.download = `${selected}-${reportType}-findings.csv`; link.click();
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><img className="brand-logo" src="/codebase-technologies-logo.png" alt="Codebase Technologies" /></div>
        <nav aria-label="Main navigation">
          <a className="active" href="#create"><span>✦</span> Create report</a>
    
        </nav>
        <div className="sidebar-foot">
          <div className={`connection ${connected ? "online" : ""}`}><i />{connected ? "Sonar connected" : "Sonar disconnected"}</div>
         
          <div className="profile"><div>{user.name.split(" ").map(w => w[0]).slice(0, 2).join("").toUpperCase()}</div><p><strong>{user.name}</strong><span>{user.role === "admin" ? "Report administrator" : "Report viewer"}</span></p></div>
        </div>
      </aside>

      <section className="workspace" id="create">
        <AccountControls user={user} />
        <header className="topbar"><div><h1>Codebase CodeWatch</h1><span><i>“Controlling complexity is the essence of computer programming.”</i> — Brian Kernighan</span></div><div className="status-pill" role="status"><i />{notice}</div></header>

        {!report && <div className="builder">
          <section className="builder-main">
            <div className="step-heading"><span>01</span><div><h2>Choose the source</h2><p>Select a Sonar project and analysis branch.</p></div></div>
            <div className="field-grid">
              <label><span>Project</span><select value={selected} onChange={e => { const projectKey = e.target.value; setSelected(projectKey); void loadBranches(projectKey); }}>{projects.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}</select><small>{projects.length} projects available</small></label>
              <label><span>Branch</span><select value={branch} onChange={e => setBranch(e.target.value)} disabled={branchesLoading || !branches.length}>{branchesLoading ? <option value="">Loading branches…</option> : !branches.length ? <option value="">No analyzed branches</option> : branches.map(item => <option key={item.name} value={item.name}>{item.name}{item.isMain ? " — Main" : ""}</option>)}</select><small>{branchesLoading ? "Loading analyzed branches from Sonar" : `${branches.length} analyzed branch${branches.length === 1 ? "" : "es"} available`}</small></label>
            </div>

            <div className="divider" />
            <div className="step-heading"><span>02</span><div><h2>Shape the report</h2><p>Choose the lens that matches your audience.</p></div></div>
            <div className="type-grid">{reportTypes.map(type => <button key={type.id} onClick={() => setReportType(type.id)} className={reportType === type.id ? "selected" : ""}>
              <div className="type-top"><i>{type.id === "executive" ? "↗" : type.id === "owasp" ? "◈" : type.id === "cwe" ? "⌁" : "▦"}</i><span>{type.badge}</span></div>
              <strong>{type.title}</strong><p>{type.description}</p><b className="radio" />
            </button>)}</div>
          </section>

          <aside className="summary-card">
            <div className="summary-head"><span>REPORT BRIEF</span><i>Live preview</i></div>
            <div className="project-monogram">{selectedProject?.name.split(" ").map(w => w[0]).slice(0, 2).join("")}</div>
            <h3>{selectedProject?.name}</h3><code>{selected}</code>
            <dl><div><dt>Framework</dt><dd>{reportTypes.find(t => t.id === reportType)?.title}</dd></div><div><dt>Branch</dt><dd>{branch}</dd></div><div><dt>Output</dt><dd>Interactive + PDF</dd></div></dl>
            <div className="included"><span>INCLUDED</span><p>✓ Quality gate & ratings</p><p>✓ Executive risk summary</p><p>✓ Prioritized issue register</p><p>✓ Coverage & duplication</p></div>
            <button className="generate" onClick={generateReport} disabled={loading || branchesLoading || !selected || !branch || !projects.length}>{loading ? <><i className="spinner" />Building report…</> : <>Generate report <span>→</span></>}</button>
            <small>No analysis data is stored by the portal.</small>
          </aside>
        </div>}

        {report && <div className="report-view" id="reports">
          <div className="report-actions"><button onClick={() => setReport(null)}>← New report</button><div><button onClick={exportCsv}>↓ CSV</button><button className="primary" onClick={() => window.print()}>Export PDF</button></div></div>
          <article className="report-paper">
            <header className="report-cover"><div><img className="report-logo" src="/codebase-technologies-logo.png" alt="Codebase Technologies" /><span>CODE HEALTH REPORT</span><h2>{report.project.name}</h2><p>{report.project.key} · {report.project.branch || branch}</p></div><div className={`gate ${report.gate.status === "OK" ? "pass" : "fail"}`}><span>QUALITY GATE</span><strong>{report.gate.status === "OK" ? "Passed" : "Failed"}</strong></div></header>
            <div className="report-meta"><span>{reportTypes.find(t => t.id === reportType)?.title}</span><span>Analysis: {report.project.lastAnalysis || "Latest"}</span><span>Generated: {new Date(report.generatedAt).toLocaleString()}</span></div>
            <section className="metric-strip">{["reliability_issues", "security_issues", "security_hotspots", "maintainability_issues", "coverage", "duplicated_lines_density"].map(k => <div key={k}><span>{metricLabels[k]}</span><strong className={ratingTone(report.metrics[k])}>{report.metrics[k] ?? "0"}{["coverage", "duplicated_lines_density"].includes(k) ? "%" : ""}</strong></div>)}</section>
            <section className="report-section"><div className="section-title"><span>01</span><div><h3>Executive summary</h3><p>The release posture at a glance.</p></div></div><div className="signal-grid">
              <div className="risk-callout"><span>RELEASE DECISION</span><h4>{report.gate.status === "OK" ? "Ready with monitoring" : "Remediation required"}</h4><p>{report.gate.status === "OK" ? "The project satisfies its configured quality gate." : "At least one configured gate condition is outside its acceptable threshold. Resolve blockers before production promotion."}</p></div>
              <div className="ratings"><span>RATINGS</span>{[["Reliability", "reliability_rating"], ["Security", "security_rating"], ["Maintainability", "sqale_rating"]].map(([l,k]) => <div key={k}><p>{l}</p><b className={ratingTone(report.metrics[k])}>{report.metrics[k] || "—"}</b></div>)}</div>
            </div></section>
            <section className="report-section"><div className="section-title"><span>02</span><div><h3>Quality gate conditions</h3><p>Measured against the policy assigned in Sonar.</p></div></div><div className="condition-table"><div className="tr th"><span>Condition</span><span>Actual</span><span>Target</span><span>Status</span></div>{report.gate.conditions.map((c, i) => <div className="tr" key={i}><span>{c.metric.replaceAll("_", " ")}</span><span>{c.actual || "—"}</span><span>{c.threshold || "Configured"}</span><span className={c.status === "OK" ? "ok" : "error"}>{c.status === "OK" ? "Pass" : "Review"}</span></div>)}</div></section>
            <section className="report-section"><div className="section-title"><span>03</span><div><h3>{reportType === "owasp" ? "OWASP security findings" : reportType === "cwe" ? "CWE weakness register" : "Priority issue register"}</h3><p>{filteredFindings.length} priority findings shown, ordered by severity.</p></div></div><div className="findings">{filteredFindings.map(f => <div className="finding" key={f.key}><span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span><div><h4>{f.message}</h4><p>{f.component}{f.line ? `:${f.line}` : ""}</p><div><code>{f.rule}</code><span>{f.type.replaceAll("_", " ")}</span>{f.effort && <span>Effort {f.effort}</span>}</div></div><b>→</b></div>)}{!filteredFindings.length && <div className="empty">No matching findings returned for this framework.</div>}</div></section>
            <footer className="report-footer"><img className="footer-logo" src="/codebase-technologies-logo.png" alt="Codebase Technologies" /><p>Generated from Sonar analysis data · {report.source === "demo" ? "Demonstration" : "Live source"}</p></footer>
          </article>
        </div>}
      </section>
    </main>
  );
}
