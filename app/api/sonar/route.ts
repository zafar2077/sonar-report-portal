import { NextRequest, NextResponse } from "next/server";
import { requireApiUser } from "@/lib/auth";
import { AppError } from "@/lib/security";
import { apiError } from "@/lib/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const METRICS = ["bugs", "vulnerabilities", "security_hotspots", "code_smells", "coverage", "duplicated_lines_density", "ncloc", "reliability_rating", "security_rating", "sqale_rating"].join(",");
const HISTORY_METRICS = ["bugs", "vulnerabilities", "code_smells", "coverage", "duplicated_lines_density"].join(",");

function demoMode() {
  return process.env.SONAR_DEMO_MODE === "true" && process.env.NODE_ENV !== "production";
}

function demoReport(project: string, branch: string) {
  const history = [
    ["2026-04-01", 84, 15, 1682, 0, 2.8], ["2026-05-01", 79, 14, 1610, 0, 2.6],
    ["2026-06-01", 74, 12, 1548, 0, 2.4], ["2026-07-01", 69, 11, 1492, 0, 2.2],
    ["2026-08-01", 65, 10, 1441, 0, 2.0], ["2026-09-01", 61, 9, 1397, 0, 1.9],
    ["2026-10-01", 58, 8, 1359, 0, 1.7], ["2026-11-17", 55, 8, 1328, 0, 1.6],
  ].map(([date, reliability, security, maintainability, coverage, duplication]) => ({ date, reliability, security, maintainability, coverage, duplication }));
  return {
    project: {
      key: project,
      name: project === "code-cop-demo" ? "Code Cop Portal" : project,
      branch: branch || "main",
      lastAnalysis: "2026-11-17T08:30:00.000Z",
    },
    gate: {
      status: "ERROR",
      conditions: [
        { metric: "new_reliability_rating", status: "OK", actual: "1", threshold: "GT 1" },
        { metric: "new_security_rating", status: "ERROR", actual: "5", threshold: "GT 1" },
        { metric: "new_maintainability_rating", status: "OK", actual: "1", threshold: "GT 1" },
        { metric: "new_duplicated_lines_density", status: "OK", actual: "1.6", threshold: "GT 3" },
        { metric: "new_coverage", status: "ERROR", actual: "0", threshold: "LT 80" },
      ],
    },
    metrics: {
      reliability_issues: 55,
      security_issues: 8,
      security_hotspots: 0,
      maintainability_issues: 1328,
      coverage: "0",
      duplicated_lines_density: "1.6",
      ncloc: "6847",
      reliability_rating: "C",
      security_rating: "E",
      sqale_rating: "A",
    },
    findings: [
      { key: "demo-1", severity: "CRITICAL", type: "VULNERABILITY", message: "Use a cryptographically secure mechanism for sensitive operations.", component: "src/security/session.ts", line: 42, rule: "typescript:S2245", effort: "30min", status: "OPEN", tags: ["owasp-a02", "cwe-330"] },
      { key: "demo-2", severity: "MAJOR", type: "CODE_SMELL", message: "Refactor this function to reduce its cognitive complexity.", component: "src/reports/generator.ts", line: 118, rule: "typescript:S3776", effort: "45min", status: "OPEN", tags: [] },
      { key: "demo-3", severity: "MAJOR", type: "BUG", message: "Handle the rejected promise or remove this redundant catch block.", component: "src/api/sonar.ts", line: 76, rule: "typescript:S2737", effort: "15min", status: "OPEN", tags: [] },
    ],
    issueBreakdown: {
      severities: { BLOCKER: 2, CRITICAL: 9, MAJOR: 75, MINOR: 10, INFO: 0 },
      qualities: { RELIABILITY: 55, SECURITY: 8, MAINTAINABILITY: 1328 },
    },
    history,
    generatedAt: new Date().toISOString(),
    source: "demo" as const,
  };
}

function config() {
  const baseUrl = (process.env.SONAR_BASE_URL || "").replace(/\/$/, "");
  const token = process.env.SONAR_TOKEN || "";
  const organization = process.env.SONAR_ORGANIZATION || "";
  if (!baseUrl || !token) throw new Error("Sonar connection is not configured");
  return { baseUrl, token, organization };
}

async function sonar(path: string, params: Record<string, string> = {}) {
  const { baseUrl, token } = config();
  const url = new URL(path, `${baseUrl}/`);
  Object.entries(params).forEach(([key, value]) => value && url.searchParams.set(key, value));
  const request = (authorization: string) => fetch(url, {
    headers: { Authorization: authorization, Accept: "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(30000),
    redirect: "error",
  });

  let response = await request(`Bearer ${token}`);
  if (response.status === 401) {
    response = await request(`Basic ${Buffer.from(`${token}:`).toString("base64")}`);
  }
  if (!response.ok) throw new Error(`Sonar API returned ${response.status}`);
  return response.json();
}

function rating(value?: string) {
  return value ? ({ "1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E" }[value] || value) : "—";
}

export async function GET(request: NextRequest) {
  try {
    const user = await requireApiUser();
    const action = request.nextUrl.searchParams.get("action") || "projects";
    const project = request.nextUrl.searchParams.get("project") || "";
    const branch = request.nextUrl.searchParams.get("branch") || "";

    if (demoMode()) {
      if (action === "projects") {
        const keys = user.allProjects ? ["code-cop-demo"] : user.projectKeys;
        return NextResponse.json({ projects: keys.map(key => ({ key, name: key === "code-cop-demo" ? "Code Cop Portal" : key, qualifier: "TRK", visibility: "private" })) });
      }
      if (!project) throw new AppError(400, "Project is required");
      if (!user.allProjects && !user.projectKeys.includes(project)) throw new AppError(403, "You do not have access to this Sonar project.");
      if (action === "branches") return NextResponse.json({ branches: [{ name: "main", isMain: true, type: "BRANCH", analysisDate: "2026-11-17T08:30:00.000Z" }, { name: "develop", isMain: false, type: "BRANCH", analysisDate: "2026-11-16T14:10:00.000Z" }] });
      if (action === "report") return NextResponse.json(demoReport(project, branch));
      throw new AppError(400, "Invalid Sonar action.");
    }

    const { organization } = config();
    if (action === "projects") {
      const data = await sonar("/api/components/search", { qualifiers: "TRK", ps: "500", organization });
      const projects = (data.components || [])
        .filter((project: Record<string, string>) => user.allProjects || user.projectKeys.includes(project.key))
        .map((p: Record<string, string>) => ({ key: p.key, name: p.name, qualifier: p.qualifier, visibility: p.visibility }));
      return NextResponse.json({ projects });
    }

    if (!project) return NextResponse.json({ error: "Project is required" }, { status: 400 });
    if (!user.allProjects && !user.projectKeys.includes(project)) throw new AppError(403, "You do not have access to this Sonar project.");

    if (action === "branches") {
      const data = await sonar("/api/project_branches/list", { project });
      const branches = (data.branches || [])
        .map((item: Record<string, unknown>) => ({
          name: String(item.name || ""),
          isMain: item.isMain === true,
          type: typeof item.type === "string" ? item.type : undefined,
          analysisDate: typeof item.analysisDate === "string" ? item.analysisDate : undefined,
        }))
        .filter((item: { name: string }) => item.name)
        .sort((a: { isMain: boolean; name: string }, b: { isMain: boolean; name: string }) => Number(b.isMain) - Number(a.isMain) || a.name.localeCompare(b.name));
      return NextResponse.json({ branches });
    }

    if (action !== "report") throw new AppError(400, "Invalid Sonar action.");

    const [measures, gate, issues, hotspots, analyses, historyData] = await Promise.all([
      sonar("/api/measures/component", { component: project, metricKeys: METRICS, branch }),
      sonar("/api/qualitygates/project_status", { projectKey: project, branch }),
      sonar("/api/issues/search", { componentKeys: project, branch, resolved: "false", ps: "100", s: "SEVERITY", asc: "false", facets: "impactSoftwareQualities,severities" }),
      sonar("/api/hotspots/search", { projectKey: project, branch, status: "TO_REVIEW", ps: "100" }).catch(() => ({ hotspots: [] })),
      sonar("/api/project_analyses/search", { project: project, branch, ps: "1" }).catch(() => ({ analyses: [] })),
      sonar("/api/measures/search_history", { component: project, metrics: HISTORY_METRICS, branch, ps: "100" }).catch(() => ({ measures: [] })),
    ]);

    const metricMap = Object.fromEntries((measures.component?.measures || []).map((m: { metric: string; value?: string }) => [m.metric, ["reliability_rating", "security_rating", "sqale_rating"].includes(m.metric) ? rating(m.value) : (m.value || "0")])) as Record<string, string | number>;
    metricMap.coverage ??= "0";
    metricMap.duplicated_lines_density ??= "0";

    const qualityFacet = (issues.facets || []).find((facet: { property?: string }) => facet.property === "impactSoftwareQualities");
    const qualityCounts = Object.fromEntries((qualityFacet?.values || []).map((value: { val: string; count: number }) => [value.val, value.count]));
    const severityFacet = (issues.facets || []).find((facet: { property?: string }) => facet.property === "severities");
    const severityCounts = Object.fromEntries((severityFacet?.values || []).map((value: { val: string; count: number }) => [value.val, value.count]));
    metricMap.reliability_issues = qualityCounts.RELIABILITY ?? metricMap.bugs ?? 0;
    metricMap.security_issues = qualityCounts.SECURITY ?? metricMap.vulnerabilities ?? 0;
    metricMap.maintainability_issues = qualityCounts.MAINTAINABILITY ?? metricMap.code_smells ?? 0;
    const issueRows = (issues.issues || []).map((i: Record<string, unknown>) => ({
      key: i.key, severity: i.severity || "MAJOR", type: i.type || "ISSUE", message: i.message,
      component: String(i.component || "").replace(`${project}:`, ""), line: i.line, rule: i.rule,
      effort: i.effort, status: i.status, tags: i.tags || [],
    }));
    const hotspotRows = (hotspots.hotspots || []).map((h: Record<string, unknown>) => ({
      key: h.key, severity: h.vulnerabilityProbability === "HIGH" ? "CRITICAL" : "MAJOR", type: "SECURITY_HOTSPOT",
      message: h.message, component: String(h.component || "").replace(`${project}:`, ""), line: h.line,
      rule: h.ruleKey, status: h.status, tags: h.securityCategory ? [`owasp-${h.securityCategory}`] : [],
    }));
    const projectStatus = gate.projectStatus || {};
    const historyByDate = new Map<string, Record<string, string | number>>();
    const historyMetricNames: Record<string, string> = { bugs: "reliability", vulnerabilities: "security", code_smells: "maintainability", coverage: "coverage", duplicated_lines_density: "duplication" };
    for (const measure of historyData.measures || []) {
      const field = historyMetricNames[measure.metric];
      if (!field) continue;
      for (const point of measure.history || []) {
        const date = String(point.date || "").slice(0, 10);
        if (!date) continue;
        const row = historyByDate.get(date) || { date };
        row[field] = Number(point.value || 0);
        historyByDate.set(date, row);
      }
    }
    return NextResponse.json({
      project: { key: project, name: measures.component?.name || project, branch, lastAnalysis: analyses.analyses?.[0]?.date },
      gate: { status: projectStatus.status || "NONE", conditions: (projectStatus.conditions || []).map((c: Record<string, string>) => ({ metric: c.metricKey, status: c.status, actual: c.actualValue, threshold: `${c.comparator || ""} ${c.errorThreshold || ""}`.trim() })) },
      metrics: metricMap,
      findings: [...issueRows, ...hotspotRows],
      issueBreakdown: { severities: severityCounts, qualities: qualityCounts },
      history: [...historyByDate.values()].sort((a, b) => String(a.date).localeCompare(String(b.date))),
      generatedAt: new Date().toISOString(), source: "live",
    });
  } catch (error) {
    if (error instanceof AppError) return apiError(error);
    const message = error instanceof Error && /^Sonar (connection is not configured|API returned \d{3})$/.test(error.message) ? error.message : "Unable to query Sonar. Check the server connection settings.";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
