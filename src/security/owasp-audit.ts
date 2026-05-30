import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { audit } from "./audit.js";
import { assertUrlInScope, type ScopePolicy } from "./scope.js";
import type { AuditFinding, AuditOptions, AuditSeverity, NetworkObservation } from "../types.js";

export type OwaspAuditProfile = "passive" | "strict-headers" | "active-authorized";

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
  /** Maximum additional active-authorized HTTP probes. Defaults to 10; hard-capped at 25. */
  maxActiveRequests?: number;
  /** Delay between active-authorized probes. Defaults to 250ms. */
  activeDelayMs?: number;
  /** Timeout for each active-authorized probe. Defaults to 10s. */
  activeRequestTimeoutMs?: number;
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

const ACTIVE_AUTHORIZED_CHECKS = [
  ...STRICT_HEADER_CHECKS,
  "authorized-well-known-file-probes",
  "authorized-sensitive-file-exposure-probes",
  "authorized-http-options-probe"
];

const WELL_KNOWN_PROBES = [
  { path: "/.well-known/security.txt", id: "well-known-security-txt", title: "security.txt discovered" },
  { path: "/security.txt", id: "root-security-txt", title: "root security.txt discovered" },
  { path: "/robots.txt", id: "robots-txt", title: "robots.txt discovered" },
  { path: "/sitemap.xml", id: "sitemap-xml", title: "sitemap.xml discovered" }
] as const;

const SENSITIVE_FILE_PROBES = [
  { path: "/.env", id: "exposed-dotenv", title: "Possible exposed .env file" },
  { path: "/.git/config", id: "exposed-git-config", title: "Possible exposed Git config" },
  { path: "/config.php.bak", id: "exposed-config-backup", title: "Possible exposed config backup" },
  { path: "/backup.zip", id: "exposed-backup-archive", title: "Possible exposed backup archive" }
] as const;

export async function owaspAudit(options: OwaspAuditOptions): Promise<OwaspAuditResult> {
  const profile = options.owaspProfile ?? "passive";
  const startedAt = new Date().toISOString();
  const checks = profile === "active-authorized" ? ACTIVE_AUTHORIZED_CHECKS : profile === "strict-headers" ? STRICT_HEADER_CHECKS : PASSIVE_CHECKS;

  if (profile === "active-authorized") {
    assertActiveAuthorized(options.url, options.scope);
  }

  const base = await audit({
    ...options,
    includeObservation: true,
    outputPath: undefined
  });

  const findings: AuditFinding[] = [
    ...base.findings.map(enrichBaseFinding),
    ...extraPassiveFindings(base.finalUrl ?? options.url, base.observation?.network ?? [], profile)
  ];

  if (profile === "active-authorized") {
    findings.push(...await activeAuthorizedFindings(base.finalUrl ?? options.url, options));
  }

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

function assertActiveAuthorized(url: string, scope?: ScopePolicy): void {
  if (!scope?.allowedHosts?.length) {
    throw new Error("active-authorized OWASP audit requires a scope policy with allowedHosts");
  }
  if (!scope.authorizationNote?.trim()) {
    throw new Error("active-authorized OWASP audit requires scope.authorizationNote documenting authorization");
  }
  assertUrlInScope(url, scope);
}

async function activeAuthorizedFindings(finalUrl: string, options: OwaspAuditOptions): Promise<AuditFinding[]> {
  const base = safeUrl(finalUrl);
  if (!base) return [];

  const maxRequests = Math.max(0, Math.min(options.maxActiveRequests ?? 10, 25));
  const delayMs = Math.max(0, options.activeDelayMs ?? 250);
  const timeoutMs = Math.max(1000, options.activeRequestTimeoutMs ?? 10_000);
  const findings: AuditFinding[] = [];
  const probes: Array<{ method: "GET" | "HEAD" | "OPTIONS"; url: string; id: string; title: string; kind: "well-known" | "sensitive-file" | "methods" }> = [];

  for (const probe of WELL_KNOWN_PROBES) {
    probes.push({ method: "GET", url: new URL(probe.path, base).toString(), id: probe.id, title: probe.title, kind: "well-known" });
  }
  for (const probe of SENSITIVE_FILE_PROBES) {
    probes.push({ method: "HEAD", url: new URL(probe.path, base).toString(), id: probe.id, title: probe.title, kind: "sensitive-file" });
  }
  probes.push({ method: "OPTIONS", url: base.toString(), id: "http-options-methods", title: "HTTP OPTIONS methods observed", kind: "methods" });

  let sent = 0;
  for (const probe of probes) {
    if (sent >= maxRequests) break;
    assertUrlInScope(probe.url, options.scope);
    const result = await boundedProbe(probe.url, probe.method, timeoutMs);
    sent += 1;

    if (probe.kind === "well-known" && result.status && result.status >= 200 && result.status < 300) {
      findings.push({
        id: `owasp-active-${probe.id}`,
        category: "well-known",
        severity: "info",
        title: probe.title,
        description: "An active-authorized well-known file probe found a publicly available site metadata file.",
        recommendation: "Review the file contents and ensure it is intentional, current, and does not disclose sensitive internal information.",
        evidence: redactedProbeEvidence(probe.method, probe.url, result),
        standard: "OWASP",
        owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
      });
    }

    if (probe.kind === "sensitive-file" && result.status && result.status >= 200 && result.status < 300) {
      findings.push({
        id: `owasp-active-${probe.id}`,
        category: "sensitive-file",
        severity: "high",
        title: probe.title,
        description: "An active-authorized bounded probe received a successful response for a path that commonly indicates accidental sensitive file exposure. Solarium did not retrieve or print the file body.",
        recommendation: "Verify the path manually in an authorized workflow, remove the exposed file if present, and add server rules preventing access to sensitive dotfiles, VCS metadata, backups, and archives.",
        evidence: redactedProbeEvidence(probe.method, probe.url, result),
        standard: "OWASP",
        owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
      });
    }

    if (probe.kind === "methods" && result.allow) {
      const allowed = result.allow.split(",").map((method) => method.trim().toUpperCase()).filter(Boolean);
      const risky = allowed.filter((method) => !["GET", "HEAD", "POST", "OPTIONS"].includes(method));
      if (risky.length > 0) {
        findings.push({
          id: "owasp-active-unusual-http-methods",
          category: "methods",
          severity: "medium",
          title: "Unusual HTTP methods advertised",
          description: "The target responded to an active-authorized OPTIONS probe with methods that may be unnecessary for a public web route.",
          recommendation: "Disable unnecessary HTTP methods on public routes unless explicitly required.",
          evidence: { method: probe.method, url: probe.url, status: result.status, allowedMethods: allowed },
          standard: "OWASP",
          owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
        });
      }
    }

    if (delayMs > 0 && sent < probes.length && sent < maxRequests) await delay(delayMs);
  }

  findings.push({
    id: "owasp-active-authorized-run-summary",
    category: "active-probe",
    severity: "info",
    title: "Active-authorized probes completed",
    description: "The active-authorized profile ran a bounded fixed probe set. It does not perform DoS, brute-force, credential attacks, fuzzing, exploitation, or destructive form submission.",
    recommendation: "Keep active-authorized runs scoped to systems you are authorized to test and tune maxActiveRequests, activeDelayMs, and activeRequestTimeoutMs for production safety.",
    evidence: { probesSent: sent, maxActiveRequests: maxRequests, delayMs, timeoutMs },
    standard: "OWASP",
    owasp: { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] }
  });

  return findings;
}

async function boundedProbe(url: string, method: "GET" | "HEAD" | "OPTIONS", timeoutMs: number): Promise<{ status?: number; ok?: boolean; contentType?: string | null; contentLength?: string | null; allow?: string | null; error?: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers: method === "GET" ? { Range: "bytes=0-1023" } : undefined
    });
    return {
      status: response.status,
      ok: response.ok,
      contentType: response.headers.get("content-type"),
      contentLength: response.headers.get("content-length"),
      allow: response.headers.get("allow")
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timeout);
  }
}

function redactedProbeEvidence(method: string, url: string, result: Awaited<ReturnType<typeof boundedProbe>>): Record<string, unknown> {
  return {
    method,
    url,
    status: result.status,
    ok: result.ok,
    contentType: result.contentType,
    contentLength: result.contentLength,
    error: result.error
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
    case "well-known":
    case "sensitive-file":
    case "methods":
    case "active-probe":
      return { top10: "A05:2021-Security Misconfiguration", asvs: ["V14 Configuration"] };
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
