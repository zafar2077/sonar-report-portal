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
  issueBreakdown?: { severities: Record<string, number>; qualities: Record<string, number> };
  history?: { date: string; reliability?: number; security?: number; maintainability?: number; coverage?: number; duplication?: number }[];
  generatedAt: string;
  source: "live" | "demo";
};

type TrendKey = "reliability" | "security" | "maintainability" | "coverage" | "duplication";

function TrendChart({ title, data, series }: { title: string; data: NonNullable<Report["history"]>; series: { key: TrendKey; label: string; color: string }[] }) {
  const width = 420, height = 150, left = 34, right = 14, top = 20, bottom = 28;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  if (data.length < 2) return <div className="trend-card"><div className="trend-head"><strong>{title}</strong></div><div className="trend-empty">Historical measures are not yet available for this project.</div></div>;
  const pointsFor = (key: TrendKey) => {
    const values = data.map(point => Number(point[key] ?? 0));
    const min = Math.min(...values), max = Math.max(...values), range = max - min || 1;
    return values.map((value, index) => `${left + (index / (values.length - 1)) * plotWidth},${top + plotHeight - ((value - min) / range) * plotHeight}`).join(" ");
  };
  const formatValue = (key: TrendKey, value: number) => `${new Intl.NumberFormat().format(value)}${key === "coverage" || key === "duplication" ? "%" : ""}`;
  return <div className="trend-card">
    <div className="trend-head"><strong>{title}</strong><div>{series.map(item => {
      const first = Number(data[0][item.key] ?? 0), current = Number(data[data.length - 1][item.key] ?? 0), change = current - first;
      const improving = item.key === "coverage" ? change > 0 : change < 0;
      return <span className="trend-stat" key={item.key}><i style={{ background: item.color }} /><b>{formatValue(item.key, current)}</b><small>{item.label}</small><em className={change === 0 ? "flat" : improving ? "improving" : "worsening"}>{change > 0 ? "+" : ""}{formatValue(item.key, change)}</em></span>;
    })}</div></div>
    <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} trend`}>
      {[0, 1, 2, 3].map(line => <line key={line} x1={left} x2={width - right} y1={top + line * plotHeight / 3} y2={top + line * plotHeight / 3} className="chart-grid" />)}
      {series.map(item => <polyline key={item.key} points={pointsFor(item.key)} fill="none" stroke={item.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />)}
      <text x={left} y={height - 7}>{displayDate(data[0].date)}</text><text x={width - right} y={height - 7} textAnchor="end">{displayDate(data[data.length - 1].date)}</text>
    </svg>
  </div>;
}

const reportTypes: { id: ReportType; title: string; description: string; badge: string }[] = [
  { id: "executive", title: "Executive overview", description: "Release-ready summary for management and governance.", badge: "Recommended" },
  { id: "owasp", title: "OWASP Top 10", description: "Security findings grouped against OWASP categories.", badge: "Security" },
  { id: "cwe", title: "CWE Top 25", description: "Weakness-focused view for AppSec and remediation.", badge: "AppSec" },
  { id: "full", title: "Full engineering", description: "All measures, ratings and prioritized issues.", badge: "Detailed" },
];

const owaspTop10 = [
  ["A01", "Broken Access Control"],
  ["A02", "Cryptographic Failures"],
  ["A03", "Injection"],
  ["A04", "Insecure Design"],
  ["A05", "Security Misconfiguration"],
  ["A06", "Vulnerable and Outdated Components"],
  ["A07", "Identification and Authentication Failures"],
  ["A08", "Software and Data Integrity Failures"],
  ["A09", "Security Logging and Monitoring Failures"],
  ["A10", "Server-Side Request Forgery (SSRF)"],
] as const;

const cweTop25 = [
  ["CWE-79", "Cross-site Scripting"], ["CWE-787", "Out-of-bounds Write"],
  ["CWE-89", "SQL Injection"], ["CWE-352", "Cross-Site Request Forgery"],
  ["CWE-22", "Path Traversal"], ["CWE-125", "Out-of-bounds Read"],
  ["CWE-78", "OS Command Injection"], ["CWE-416", "Use After Free"],
  ["CWE-862", "Missing Authorization"], ["CWE-434", "Unrestricted Upload of Dangerous File"],
  ["CWE-94", "Code Injection"], ["CWE-20", "Improper Input Validation"],
  ["CWE-77", "Command Injection"], ["CWE-287", "Improper Authentication"],
  ["CWE-269", "Improper Privilege Management"], ["CWE-502", "Deserialization of Untrusted Data"],
  ["CWE-200", "Exposure of Sensitive Information"], ["CWE-863", "Incorrect Authorization"],
  ["CWE-918", "Server-Side Request Forgery"], ["CWE-119", "Improper Memory Buffer Operations"],
  ["CWE-476", "NULL Pointer Dereference"], ["CWE-798", "Hard-coded Credentials"],
  ["CWE-190", "Integer Overflow or Wraparound"], ["CWE-400", "Uncontrolled Resource Consumption"],
  ["CWE-306", "Missing Authentication for Critical Function"],
] as const;
const cweTop25Codes = new Set<string>(cweTop25.map(([code]) => code));

function cweCategory(tags: string[] = []) {
  for (const tag of tags) {
    const match = tag.toUpperCase().match(/CWE[-_: ]*(\d+)/);
    if (match) return `CWE-${match[1]}`;
  }
  return null;
}

function owaspCategory(tags: string[] = []) {
  for (const tag of tags) {
    const match = tag.toLowerCase().match(/owasp(?:top10)?[-_: ]*a0?(10|[1-9])(?:[-_: ]*2021)?/);
    if (match) return `A${match[1].padStart(2, "0")}`;
  }
  return null;
}

const metricLabels: Record<string, string> = {
  reliability_issues: "Reliability issues", security_issues: "Security issues", security_hotspots: "Security hotspots",
  maintainability_issues: "Maintainability issues", coverage: "Coverage", duplicated_lines_density: "Duplication",
};

const headlineMetrics = [
  "reliability_issues", "security_issues", "security_hotspots",
  "maintainability_issues", "coverage", "duplicated_lines_density",
];

const qualityRatings = [
  ["Reliability", "reliability_rating", "reliability_issues"],
  ["Security", "security_rating", "security_issues"],
  ["Maintainability", "sqale_rating", "maintainability_issues"],
] as const;

function displayDate(value?: string) {
  if (!value) return "Latest analysis";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });
}

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
    if (reportType === "owasp") return report.findings.filter(f => owaspCategory(f.tags) !== null);
    if (reportType === "cwe") return report.findings.filter(f => { const category = cweCategory(f.tags); return category !== null && cweTop25Codes.has(category); });
    return report.findings;
  }, [report, reportType]);
  const frameworkGroups = useMemo(() => {
    if (!report || (reportType !== "owasp" && reportType !== "cwe")) return [];
    if (reportType === "owasp") {
      const counts = new Map<string, number>(owaspTop10.map(([code]) => [code, 0]));
      for (const finding of filteredFindings) {
        const category = owaspCategory(finding.tags);
        if (category) counts.set(category, (counts.get(category) || 0) + 1);
      }
      return owaspTop10.map(([code, title]) => [`${code} · ${title}`, counts.get(code) || 0] as [string, number]);
    }
    const counts = new Map<string, number>(cweTop25.map(([code]) => [code, 0]));
    for (const finding of filteredFindings) {
      const category = cweCategory(finding.tags);
      if (category && cweTop25Codes.has(category)) counts.set(category, (counts.get(category) || 0) + 1);
    }
    return cweTop25.map(([code, title]) => [`${code} · ${title}`, counts.get(code) || 0] as [string, number]);
  }, [filteredFindings, report, reportType]);
  const reportLabel = reportType === "executive" ? "Executive report" : reportType === "owasp" ? "OWASP Top 10 report" : reportType === "cwe" ? "CWE Top 25 report" : "Full engineering report";
  const severityScale = report && ["HIGH", "MEDIUM", "LOW"].some(key => key in (report.issueBreakdown?.severities || {}))
    ? ["BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO"]
    : ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"];
  const severityTotal = severityScale.reduce((sum, key) => sum + Number(report?.issueBreakdown?.severities?.[key] || 0), 0);
  const qualityTotal = ["RELIABILITY", "SECURITY", "MAINTAINABILITY"].reduce((sum, key) => sum + Number(report?.issueBreakdown?.qualities?.[key] || 0), 0);
  const gatePassCount = report?.gate.conditions.filter(condition => condition.status === "OK").length || 0;
  const gateReviewCount = (report?.gate.conditions.length || 0) - gatePassCount;
  const frameworkTotal = frameworkGroups.reduce((sum, [, count]) => sum + count, 0);
  const frameworkMax = Math.max(1, ...frameworkGroups.map(([, count]) => count));
  const displayedFindings = reportType === "executive" ? filteredFindings.slice(0, 10) : filteredFindings;
  const urgentFindings = displayedFindings.filter(finding => ["BLOCKER", "CRITICAL", "HIGH"].includes(finding.severity)).length;
  const affectedComponents = new Set(displayedFindings.map(finding => finding.component)).size;

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
          <a href="#reports"><span>▤</span> Reports</a>
          <a href="#projects"><span>◇</span> Projects</a>
        </nav>
        <div className="sidebar-foot">
          <div className={`connection ${connected ? "online" : ""}`}><i />{connected ? "Sonar connected" : "Sonar disconnected"}</div>
          <button className="settings">⚙ <span>Connection settings</span></button>
          <div className="profile"><div>{user.name.split(" ").map(w => w[0]).slice(0, 2).join("").toUpperCase()}</div><p><strong>{user.name}</strong><span>{user.role === "admin" ? "Report administrator" : "Report viewer"}</span></p></div>
        </div>
      </aside>

      <section className="workspace" id="create">
        <AccountControls user={user} />
        <header className="topbar"><div><span>REPORT STUDIO</span><h1>Turn code analysis into a decision.</h1></div><div className="status-pill" role="status"><i />{notice}</div></header>

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
            <div className="included"><span>INCLUDED</span>{reportType === "executive" ? <><p>✓ Release decision & ratings</p><p>✓ Quality trends and gate</p><p>✓ Top management risks</p><p>✓ Coverage & duplication</p></> : reportType === "owasp" ? <><p>✓ OWASP Top 10 (2021) matrix</p><p>✓ Category-mapped findings</p><p>✓ Security rating & hotspots</p><p>✓ Exportable issue register</p></> : reportType === "cwe" ? <><p>✓ CWE-tagged weaknesses</p><p>✓ Weakness distribution</p><p>✓ Security rating & hotspots</p><p>✓ Exportable issue register</p></> : <><p>✓ Complete quality trends</p><p>✓ All gate conditions</p><p>✓ Full issue distribution</p><p>✓ Complete issue register</p></>}</div>
            <button className="generate" onClick={generateReport} disabled={loading || branchesLoading || !selected || !branch || !projects.length}>{loading ? <><i className="spinner" />Building report…</> : <>Generate report <span>→</span></>}</button>
            <small>No analysis data is stored by the portal.</small>
          </aside>
        </div>}

        {report && <div className="report-view" id="reports">
          <div className="report-actions"><button onClick={() => setReport(null)}>← New report</button><div><button onClick={exportCsv}>↓ CSV</button><button className="primary" onClick={() => window.print()}>Export PDF</button></div></div>
          <article className="report-paper">
            <header className="report-cover">
              <div className="report-brand-row"><img className="report-logo" src="/codebase-technologies-logo.png" alt="Codebase Technologies" /><span>CODE QUALITY · {reportLabel.toUpperCase()}</span></div>
              <div className="report-title-row">
                <div><span className="report-kicker">{reportTypes.find(t => t.id === reportType)?.title}</span><h2>{report.project.name}</h2><p>{report.project.key}</p></div>
                <div className={`gate ${report.gate.status === "OK" ? "pass" : "fail"}`}><span>QUALITY GATE</span><strong>{report.gate.status === "OK" ? "Passed" : "Failed"}</strong><small>{report.gate.status === "OK" ? "Policy requirements met" : "Action required before release"}</small></div>
              </div>
              <div className="report-meta">
                <div><span>Branch</span><strong>{report.project.branch || branch}</strong></div>
                <div><span>Analysis date</span><strong>{displayDate(report.project.lastAnalysis)}</strong></div>
                <div><span>Generated</span><strong>{displayDate(report.generatedAt)}</strong></div>
                <div><span>Data source</span><strong>{report.source === "demo" ? "Demonstration" : "Live Sonar"}</strong></div>
              </div>
            </header>

            <section className="rating-overview" aria-label="Software quality ratings">
              {qualityRatings.map(([label, ratingKey, issueKey]) => <div className="rating-card" key={ratingKey}>
                <div><span>{label}</span><small>{metricLabels[issueKey]}</small></div>
                <strong className={ratingTone(report.metrics[ratingKey])}>{report.metrics[ratingKey] || "—"}</strong>
                <b>{report.metrics[issueKey] ?? "0"}</b>
              </div>)}
            </section>

            <section className="metric-strip" aria-label="Analysis metrics">{headlineMetrics.map(k => <div key={k}><span>{metricLabels[k]}</span><strong className={ratingTone(report.metrics[k])}>{report.metrics[k] ?? "0"}{["coverage", "duplicated_lines_density"].includes(k) ? "%" : ""}</strong></div>)}</section>
            {reportType === "executive" && <section className="report-section"><div className="section-title"><span>01</span><div><h3>Executive summary</h3><p>The release posture at a glance.</p></div></div><div className="signal-grid">
              <div className="risk-callout"><span>RELEASE DECISION</span><h4>{report.gate.status === "OK" ? "Ready with monitoring" : "Remediation required"}</h4><p>{report.gate.status === "OK" ? "The project satisfies its configured quality gate." : "At least one configured gate condition is outside its acceptable threshold. Resolve blockers before production promotion."}</p></div>
              <div className="ratings"><span>RATINGS</span>{[["Reliability", "reliability_rating"], ["Security", "security_rating"], ["Maintainability", "sqale_rating"]].map(([l,k]) => <div key={k}><p>{l}</p><b className={ratingTone(report.metrics[k])}>{report.metrics[k] || "—"}</b></div>)}</div>
            </div></section>}
            {(reportType === "executive" || reportType === "full") && <section className="report-section trend-section"><div className="section-title"><span>{reportType === "executive" ? "02" : "01"}</span><div><h3>Analysis trends</h3><p>How the project’s quality measures have changed across recent analyses.</p></div></div><div className="trend-grid">
              <TrendChart title="Reliability" data={report.history || []} series={[{ key: "reliability", label: "Issues", color: "#71358f" }]} />
              <TrendChart title="Security" data={report.history || []} series={[{ key: "security", label: "Issues", color: "#d4573f" }]} />
              <TrendChart title="Maintainability" data={report.history || []} series={[{ key: "maintainability", label: "Issues", color: "#8a55a5" }]} />
              <TrendChart title="Coverage and duplication" data={report.history || []} series={[{ key: "coverage", label: "Coverage", color: "#3e8b6f" }, { key: "duplication", label: "Duplication", color: "#d18b35" }]} />
            </div></section>}
            {(reportType === "executive" || reportType === "full") && <section className="report-section"><div className="section-title"><span>{reportType === "executive" ? "03" : "02"}</span><div><h3>Quality gate conditions</h3><p>Measured against the policy assigned in Sonar.</p></div></div><div className="section-counts"><div><span>Total conditions</span><strong>{report.gate.conditions.length}</strong></div><div className="count-pass"><span>Passed</span><strong>{gatePassCount}</strong></div><div className="count-review"><span>Needs review</span><strong>{gateReviewCount}</strong></div></div><div className="condition-table"><div className="tr th"><span>Condition</span><span>Actual</span><span>Target</span><span>Status</span></div>{report.gate.conditions.map((c, i) => <div className="tr" key={i}><span>{c.metric.replaceAll("_", " ")}</span><span>{c.actual || "—"}</span><span>{c.threshold || "Configured"}</span><span className={c.status === "OK" ? "ok" : "error"}>{c.status === "OK" ? "Pass" : "Review"}</span></div>)}</div></section>}
            {(reportType === "executive" || reportType === "full") && <section className="report-section breakdown-section"><div className="section-title"><span>{reportType === "executive" ? "04" : "03"}</span><div><h3>Issue distribution</h3><p>Current unresolved issues grouped using Sonar’s complete facet totals.</p></div></div><div className="breakdown-grid">
              <div className="breakdown-table"><div className="breakdown-heading"><span>Severity</span><span>{severityTotal.toLocaleString()} total</span></div>{severityScale.map(key => { const count = Number(report.issueBreakdown?.severities?.[key] || 0); return <div key={key}><span><i className={`severity-dot ${key.toLowerCase()}`} />{key.charAt(0) + key.slice(1).toLowerCase()}</span><span className="count-cell"><i style={{ width: `${severityTotal ? count / severityTotal * 100 : 0}%` }} /><strong>{count.toLocaleString()}</strong><em>{severityTotal ? Math.round(count / severityTotal * 100) : 0}%</em></span></div>; })}</div>
              <div className="breakdown-table"><div className="breakdown-heading"><span>Software quality</span><span>{qualityTotal.toLocaleString()} total</span></div>{[["RELIABILITY", "Reliability"], ["SECURITY", "Security"], ["MAINTAINABILITY", "Maintainability"]].map(([key, label]) => { const count = Number(report.issueBreakdown?.qualities?.[key] || 0); return <div key={key}><span>{label}</span><span className="count-cell"><i style={{ width: `${qualityTotal ? count / qualityTotal * 100 : 0}%` }} /><strong>{count.toLocaleString()}</strong><em>{qualityTotal ? Math.round(count / qualityTotal * 100) : 0}%</em></span></div>; })}</div>
            </div></section>}
            {(reportType === "owasp" || reportType === "cwe") && <section className="report-section framework-overview"><div className="section-title"><span>01</span><div><h3>{reportType === "owasp" ? "OWASP exposure overview" : "CWE weakness overview"}</h3><p>{reportType === "owasp" ? "Security findings mapped to OWASP categories returned by Sonar." : "Detected weaknesses grouped by their CWE tags."}</p></div></div><div className="framework-summary">
              <div><span>Matching findings</span><strong>{filteredFindings.length}</strong></div><div><span>Security rating</span><strong className={ratingTone(report.metrics.security_rating)}>{report.metrics.security_rating || "—"}</strong></div><div><span>Security hotspots</span><strong>{report.metrics.security_hotspots ?? 0}</strong></div>
            </div><div className="framework-table"><div className="framework-row framework-head"><span>{reportType === "owasp" ? "OWASP category" : "CWE category"}</span><span>{frameworkTotal.toLocaleString()} mapped</span></div>{frameworkGroups.map(([label, count]) => <div className="framework-row" key={label}><span>{label}</span><span className="framework-count"><i style={{ width: `${count / frameworkMax * 100}%` }} /><strong>{count.toLocaleString()}</strong></span></div>)}{!frameworkGroups.length && <div className="empty">No framework tags were returned for the selected project and branch.</div>}</div></section>}
            <section className="report-section"><div className="section-title"><span>{reportType === "executive" ? "05" : reportType === "full" ? "04" : "02"}</span><div><h3>{reportType === "owasp" ? "OWASP security findings" : reportType === "cwe" ? "CWE weakness register" : reportType === "full" ? "Complete engineering issue register" : "Priority issue register"}</h3><p>{reportType === "executive" ? `${Math.min(filteredFindings.length, 10)} highest-priority findings shown for management review.` : `${filteredFindings.length} matching findings shown, ordered by severity.`}</p></div></div><div className="section-counts findings-counts"><div><span>Findings shown</span><strong>{displayedFindings.length}</strong></div><div className="count-review"><span>High priority</span><strong>{urgentFindings}</strong></div><div><span>Components</span><strong>{affectedComponents}</strong></div></div><div className="findings">{displayedFindings.map(f => <div className="finding" key={f.key}><span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span><div><h4>{f.message}</h4><p>{f.component}{f.line ? `:${f.line}` : ""}</p><div><code>{f.rule}</code><span>{f.type.replaceAll("_", " ")}</span>{f.effort && <span>Effort {f.effort}</span>}</div></div><b>→</b></div>)}{!filteredFindings.length && <div className="empty">No matching findings returned for this report.</div>}</div></section>
            <footer className="report-footer"><img className="footer-logo" src="/codebase-technologies-logo.png" alt="Codebase Technologies" /><p>Generated from Sonar analysis data · {report.source === "demo" ? "Demonstration" : "Live source"}</p></footer>
          </article>
        </div>}
      </section>
    </main>
  );
}
