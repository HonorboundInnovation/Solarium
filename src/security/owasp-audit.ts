import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { audit } from "./audit.js";
import type { AuditFinding, AuditOptions, AuditSeverity, NetworkObservation } from "../types.js";

export type OwaspAuditProfile = "passive" | "strict-headers";

export interface OwaspCategorySummary {
  category: string;
  count: number;
  severities: Record<AuditSeverity, number>;
}

export interface OwaspAuditResult {
  schemaVersion: "solarium.owasp-audit.v1";
  standard: "OWASP";
  profile: OwaspAuditProfile;
  url: string;
  finalUrl?: string;
  title?: string;
  startedAt: string;
  finishedAt: string;
  ok: boolean;
  checks: string[];
  findings: AuditFinding[];
  summary: Record<AuditSeverity, number>;
  owaspSummary: OwaspCategorySummary[];
  baseAudit: Omit<Awaited<ReturnType<typeof audit>>, "observation">;
  networkPolicy?: Awaited<ReturnType<typeof audit>>["networkPolicy"];
  error?: string;
}

export interface OwaspAuditOptions extends AuditOptions {
  owaspProfile?: OwaspAuditProfile;
}

const PASSIVE_CHECKS = [
  "security-headers",
  "cookie-flags",
  "mixed-content",
  "form-transport",
  "https-usage",
  "browser-console-errors",
  "failed-resource-requests",
  "third-party-script-inventory",
  "source-map-exposure-signals"
];

const STRICT_HEADER_CHECKS = [
  ...PASSIVE_CHECKS,
  "strict-cross-origin-isolation-headers"
];

export async function owaspAudit(options: OwaspAuditOptions): Promise<OwaspAuditResult> {
  const profile = options.owaspProfile ?? "passive";
  const startedAt = new Date().toISOString();
  const checks = profile === "strict-headers" ? STRICT_HEADER_CHECKS : PASSIVE_CHECKS;

  const base = await audit({
    ...options,
    includeObservation: true,
    outputPath: undefined
  });

  const findings: AuditFinding[] = [
    ...base.findings.map(enrichBaseFinding),
    ...extraPassiveFindings(base.finalUrl ?? options.url, base.observation?.network ?? [], profile)
  ];

  const result: OwaspAuditResult = {
    schemaVersion: "solarium.owasp-audit.v1",
    standard: "OWASP",
    profile,
    url: options.url,
    finalUrl: base.finalUrl,
    title: base.title,
    startedAt,
    finishedAt: new Date().toISOString(),
    ok: base.ok,
    checks,
    findings: sortFindings(findings),
    summary: summarize(findings),
    owaspSummary: summarizeOwasp(findings),
    baseAudit: stripObservation(base),
    networkPolicy: base.networkPolicy,
    error: base.error
  };

  if (options.outputPath) {
    await mkdir(dirname(options.outputPath), { recursive: true });
    await writeFile(options.outputPath, JSON.stringify(result, null, 2), "utf8");
  }

  return result;
}

function enrichBaseFinding(finding: AuditFinding): AuditFinding {
  const owasp = mapFindingToOwasp(finding);
  return {
    ...finding,
    standard: "OWASP",
    owasp
  };
}

function extraPassiveFindings(finalUrl: string, network: NetworkObservation[], profile: OwaspAuditProfile): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const page = safeUrl(finalUrl);

  if (page && page.protocol !== "https:") {
    findings.push({
      id: "owasp-page-not-https",
      category: "transport",
      severity: "high",
      title: "Page is not served over HTTPS",
      description: "The final page URL is not using HTTPS, exposing users to transport-layer interception or modification.",
      recommendation: "Serve the site over HTTPS and redirect HTTP requests to HTTPS.",
      evidence: { finalUrl },
      standard: "OWASP",
      owasp: { top10: "A02:2021-Cryptographic Failures", asvs: ["V9 Communications"] }
    });
  }

  const failed = network.filter((event) => event.ok === false || event.failureText || (typeof event.status === "number" && event.status >= 400));
  if (failed.length > 0) {
    findings.push({
      id: "owasp-failed-resource-requests",
      category: "network",
      severity: "low",
      title: "Failed resource requests observed",
      description: "The browser observed failed network requests while loading the page. Failed assets can indicate broken integrations, unavailable third-party dependencies, or blocked security-sensitive resources.",
      recommendation: "Review failed requests and remove, repair, or intentionally document expected blocked resources.",
      evidence: { count: failed.length, samples: failed.slice(0, 10) },
      standard: "OWASP",
      owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
    });
  }

  const thirdPartyScripts = thirdPartyScriptHosts(finalUrl, network);
  if (thirdPartyScripts.length > 0) {
    findings.push({
      id: "owasp-third-party-script-inventory",
      category: "supply-chain",
      severity: "info",
      title: "Third-party scripts observed",
      description: "The page loads scripts from third-party hosts. This is often legitimate, but each third-party script expands the browser-side trust and supply-chain surface.",
      recommendation: "Inventory third-party scripts, keep them necessary and trusted, and consider Subresource Integrity or self-hosting where appropriate.",
      evidence: { hosts: thirdPartyScripts.slice(0, 25), count: thirdPartyScripts.length },
      standard: "OWASP",
      owasp: { top10: "A08:2021-Software and Data Integrity Failures", asvs: ["V14 Configuration"] }
    });
  }

  const sourceMaps = network.filter((event) => /\.map(?:$|[?#])/i.test(event.url));
  if (sourceMaps.length > 0) {
    findings.push({
      id: "owasp-source-map-exposure-signal",
      category: "client-exposure",
      severity: "low",
      title: "Source map files were requested or referenced",
      description: "The browser observed source map references. Public source maps can expose source structure and implementation details.",
      recommendation: "Only publish source maps intentionally, and ensure they do not contain secrets or sensitive internal comments.",
      evidence: { count: sourceMaps.length, samples: sourceMaps.slice(0, 10).map((event) => event.url) },
      standard: "OWASP",
      owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
    });
  }

  if (profile === "strict-headers") {
    findings.push(...strictHeaderAdvisories(network));
  }

  return findings;
}

function strictHeaderAdvisories(_network: NetworkObservation[]): AuditFinding[] {
  // Placeholder for future response-header inventory across all loaded resources.
  // Keeping this profile explicit lets callers opt into stricter expectations without
  // changing passive/default severity semantics.
  return [];
}

function mapFindingToOwasp(finding: AuditFinding): { top10: string; asvs: string[] } {
  switch (finding.category) {
    case "headers":
      if (finding.id.includes("clickjacking")) return { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration", "V1 Architecture"] };
      return { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] };
    case "cookies":
      return { top10: "A02:2021-Cryptographic Failures", asvs: ["V3 Session Management", "V9 Communications"] };
    case "mixed-content":
      return { top10: "A02:2021-Cryptographic Failures", asvs: ["V9 Communications"] };
    case "forms":
      return { top10: "A02:2021-Cryptographic Failures", asvs: ["V5 Validation", "V9 Communications"] };
    case "graphql":
      return { top10: "A01:2021-Broken Access Control", asvs: ["V4 Access Control", "V5 Validation"] };
    default:
      return { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] };
  }
}

function thirdPartyScriptHosts(finalUrl: string, network: NetworkObservation[]): string[] {
  const page = safeUrl(finalUrl);
  if (!page) return [];
  const hosts = new Set<string>();
  for (const event of network) {
    if (event.resourceType !== "script") continue;
    const url = safeUrl(event.url);
    if (!url) continue;
    if (url.hostname !== page.hostname) hosts.add(url.hostname);
  }
  return [...hosts].sort();
}

function stripObservation(base: Awaited<ReturnType<typeof audit>>): Omit<Awaited<ReturnType<typeof audit>>, "observation"> {
  const { observation: _observation, ...rest } = base;
  return rest;
}

function summarize(findings: AuditFinding[]): Record<AuditSeverity, number> {
  return findings.reduce<Record<AuditSeverity, number>>((acc, finding) => {
    acc[finding.severity] += 1;
    return acc;
  }, { info: 0, low: 0, medium: 0, high: 0 });
}

function summarizeOwasp(findings: AuditFinding[]): OwaspCategorySummary[] {
  const byCategory = new Map<string, OwaspCategorySummary>();
  for (const finding of findings) {
    const top10 = finding.owasp?.top10 ?? "OWASP-Unmapped";
    const current = byCategory.get(top10) ?? { category: top10, count: 0, severities: { info: 0, low: 0, medium: 0, high: 0 } };
    current.count += 1;
    current.severities[finding.severity] += 1;
    byCategory.set(top10, current);
  }
  return [...byCategory.values()].sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

function sortFindings(findings: AuditFinding[]): AuditFinding[] {
  const rank: Record<AuditSeverity, number> = { high: 0, medium: 1, low: 2, info: 3 };
  return [...findings].sort((a, b) => rank[a.severity] - rank[b.severity] || a.id.localeCompare(b.id));
}

function safeUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}
