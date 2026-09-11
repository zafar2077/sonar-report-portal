import { NextRequest, NextResponse } from "next/server";
import { requireApiUser } from "@/lib/auth";
import { AppError } from "@/lib/security";
import { apiError } from "@/lib/http";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const METRICS = ["bugs", "vulnerabilities", "security_hotspots", "code_smells", "coverage", "duplicated_lines_density", "ncloc", "reliability_rating", "security_rating", "sqale_rating"].join(",");

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
    const { organization } = config();
    if (action === "projects") {
      const data = await sonar("/api/components/search", { qualifiers: "TRK", ps: "500", organization });
      const projects = (data.components || [])
        .filter((project: Record<string, string>) => user.allProjects || user.projectKeys.includes(project.key))
        .map((p: Record<string, string>) => ({ key: p.key, name: p.name, qualifier: p.qualifier, visibility: p.visibility }));
      return NextResponse.json({ projects });
    }

    const project = request.nextUrl.searchParams.get("project") || "";
    const branch = request.nextUrl.searchParams.get("branch") || "";
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

    const [measures, gate, issues, hotspots, analyses] = await Promise.all([
      sonar("/api/measures/component", { component: project, metricKeys: METRICS, branch }),
      sonar("/api/qualitygates/project_status", { projectKey: project, branch }),
      sonar("/api/issues/search", { componentKeys: project, branch, resolved: "false", ps: "100", s: "SEVERITY", asc: "false", facets: "impactSoftwareQualities" }),
      sonar("/api/hotspots/search", { projectKey: project, branch, status: "TO_REVIEW", ps: "100" }).catch(() => ({ hotspots: [] })),
      sonar("/api/project_analyses/search", { project: project, branch, ps: "1" }).catch(() => ({ analyses: [] })),
    ]);

    const metricMap = Object.fromEntries((measures.component?.measures || []).map((m: { metric: string; value?: string }) => [m.metric, ["reliability_rating", "security_rating", "sqale_rating"].includes(m.metric) ? rating(m.value) : (m.value || "0")])) as Record<string, string | number>;
    metricMap.coverage ??= "0";
    metricMap.duplicated_lines_density ??= "0";

    const qualityFacet = (issues.facets || []).find((facet: { property?: string }) => facet.property === "impactSoftwareQualities");
    const qualityCounts = Object.fromEntries((qualityFacet?.values || []).map((value: { val: string; count: number }) => [value.val, value.count]));
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
    return NextResponse.json({
      project: { key: project, name: measures.component?.name || project, branch, lastAnalysis: analyses.analyses?.[0]?.date },
      gate: { status: projectStatus.status || "NONE", conditions: (projectStatus.conditions || []).map((c: Record<string, string>) => ({ metric: c.metricKey, status: c.status, actual: c.actualValue, threshold: `${c.comparator || ""} ${c.errorThreshold || ""}`.trim() })) },
      metrics: metricMap, findings: [...issueRows, ...hotspotRows], generatedAt: new Date().toISOString(), source: "live",
    });
  } catch (error) {
    if (error instanceof AppError) return apiError(error);
    const message = error instanceof Error && /^Sonar (connection is not configured|API returned \d{3})$/.test(error.message) ? error.message : "Unable to query Sonar. Check the server connection settings.";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
