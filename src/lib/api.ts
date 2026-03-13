// Anshu Vuln Scanner API Client
const API_BASE = "http://localhost:8002/api/v1/acunetix";
const API_KEY = "1986ad8c0a5b3df4d7028d5f3c06e936cc93ab7feff714279803d07b9081ce252"; // Hardcoded for development

interface RequestOptions {
  method?: string;
  body?: any;
}

async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body } = options;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "X-Auth": API_KEY,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`API Error ${res.status}: ${errText}`);
  }

  // Some endpoints return 204 No Content
  if (res.status === 204) return undefined as T;

  // Some endpoints return Location header with ID
  const contentType = res.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return res.json();
  }
  return undefined as T;
}

// Extract ID from Location header (e.g., "/api/v1/scans/uuid-here")
function extractIdFromLocation(location: string): string {
  const parts = location.split("/");
  return parts[parts.length - 1];
}

// === Types matching Anshu Vuln Scanner API ===

export type ScanStatus =
  | "scheduled"
  | "queued"
  | "starting"
  | "processing"
  | "aborting"
  | "aborted"
  | "pausing"
  | "paused"
  | "completed"
  | "failed";

export type VulnStatus = "open" | "fixed" | "ignored" | "false_positive";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Target {
  address: string;
  description?: string;
  type?: "default" | "demo" | "network";
  criticality?: number;
}

export interface TargetInfo {
  target_id: string;
  address: string;
  description: string;
  type: string;
  criticality: number;
  last_scan_date?: string;
  last_scan_id?: string;
  last_scan_session_status?: string;
  severity_counts?: SeverityCounts;
  threat?: number;
  continuous_mode?: boolean;
  fqdn?: string;
}

export interface TargetListResponse {
  targets: TargetInfo[];
  pagination: Pagination;
}

export interface Pagination {
  count: number;
  cursors?: string[];
  cursor_hash?: string;
  sort?: string;
}

export interface ScanSchedule {
  disable: boolean;
  start_date?: string | null;
  time_sensitive?: boolean;
  recurrence?: string;
}

export interface ScanRequest {
  target_id: string;
  profile_id: string;
  schedule: ScanSchedule;
  report_template_id?: string;
  incremental?: boolean;
}

export interface ScanInfo {
  status: ScanStatus;
  severity_counts?: SeverityCounts;
  progress?: number;
  start_date?: string;
  threat?: number;
  scan_session_id?: string;
}

export interface ScanItemResponse {
  scan_id: string;
  target_id: string;
  profile_id: string;
  profile_name?: string;
  schedule: ScanSchedule;
  target?: Target & { target_id?: string };
  current_session?: ScanInfo;
  criticality?: number;
  start_date?: string;
  manual_intervention?: boolean;
  next_run?: string;
}

export interface ScanListResponse {
  scans: ScanItemResponse[];
  pagination: Pagination;
}

export interface ScanResultItem {
  result_id: string;
  scan_id: string;
  status: ScanStatus;
  start_date: string;
  end_date?: string;
  severity_counts?: SeverityCounts;
}

export interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service: string;
  latency_ms?: number;
}

export interface ScanResult {
  target: string;
  ip: string;
  scan_time: string;
  total_ports_scanned: number;
  summary: {
    open: number;
    closed: number;
    filtered: number;
  };
  results: PortResult[];
}

export interface ScanResultListResponse {
  result_list: ScanResultItem[];
  pagination: Pagination;
}

export interface Vulnerability {
  vuln_id: string;
  vt_name: string;
  vt_id: string;
  severity: number; // 0=info, 1=low, 2=medium, 3=high, 4=critical
  criticality: number;
  status: VulnStatus;
  confidence: number;
  target_id: string;
  target_description?: string;
  affects_url: string;
  affects_detail?: string;
  loc_id?: number;
  last_seen?: string;
  first_seen?: string;
  tags?: string[];
  continuous?: boolean;
  source?: string; // "Web", "Mobile", "Network", "Model Security"
}

export interface VulnerabilityDetails extends Vulnerability {
  description?: string;
  impact?: string;
  recommendation?: string;
  long_description?: string;
  request?: string;
  response_info?: string;
  details?: string;
  cvss2?: string;
  cvss3?: string;
  cvss_score?: number;
  references?: { rel: string; href: string }[];
}

export interface VulnerabilityListResponse {
  vulnerabilities: Vulnerability[];
  pagination: Pagination;
}

export interface ReportTemplate {
  template_id: string;
  name: string;
  group?: string;
}

export interface ReportTemplateList {
  templates: ReportTemplate[];
}

export interface NewReport {
  template_id: string;
  source: {
    list_type: string;
    id_list?: string[];
    description?: string;
  };
}

export interface Report {
  report_id: string;
  status: "queued" | "processing" | "completed" | "failed";
  template_id?: string;
  template_name?: string;
  generation_date?: string;
  download?: string[];
  source?: {
    list_type: string;
    id_list?: string[];
    description?: string;
  };
}

export interface ReportListResponse {
  reports: Report[];
  pagination: Pagination;
}

export interface ScanningProfile {
  profile_id: string;
  name: string;
  custom?: boolean;
  sort_order?: number;
}

// === Severity helpers ===

const SEVERITY_MAP: Record<number, string> = {
  0: "info",
  1: "low",
  2: "medium",
  3: "high",
  4: "critical",
};

export const severityToString = (s: number) => SEVERITY_MAP[s] || "info";

const LOCAL_VULNS_KEY = "local_vulnerabilities";

export function saveLocalVulnerability(v: Partial<Vulnerability>) {
  try {
    const local = JSON.parse(localStorage.getItem(LOCAL_VULNS_KEY) || "[]");
    const newVuln = {
      vuln_id: `local-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      status: "open",
      confidence: 100,
      criticality: 5,
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      ...v
    };
    local.push(newVuln);
    localStorage.setItem(LOCAL_VULNS_KEY, JSON.stringify(local.slice(-100)));
  } catch (e) { console.error("Failed to save local vuln", e); }
}

export function getLocalVulnerabilities(): Vulnerability[] {
  try {
    return JSON.parse(localStorage.getItem(LOCAL_VULNS_KEY) || "[]");
  } catch { return []; }
}

const LOCAL_SCANS_KEY = "local_scans";

export function saveLocalScan(scan: Partial<ScanItemResponse>) {
  try {
    const local = JSON.parse(localStorage.getItem(LOCAL_SCANS_KEY) || "[]");
    local.unshift({
      scan_id: `local-scan-${Date.now()}`,
      status: "completed",
      profile_name: "Local Scan",
      ...scan
    });
    localStorage.setItem(LOCAL_SCANS_KEY, JSON.stringify(local.slice(0, 50)));
  } catch (e) { console.error("Failed to save local scan", e); }
}

export function severityToNumber(severity: string): number {
  const map: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return map[severity] ?? 0;
}

// === Built-in Scanning Profile IDs ===
export const SCAN_PROFILES = {
  FULL_SCAN: "11111111-1111-1111-1111-111111111111",
  HIGH_RISK: "11111111-1111-1111-1111-111111111112",
  XSS: "11111111-1111-1111-1111-111111111116",
  SQL_INJECTION: "11111111-1111-1111-1111-111111111113",
  WEAK_PASSWORDS: "11111111-1111-1111-1111-111111111115",
  CRAWL_ONLY: "11111111-1111-1111-1111-111111111117",
};

// === Built-in Report Template IDs ===
export const REPORT_TEMPLATES = {
  DEVELOPER: "11111111-1111-1111-1111-111111111111",
  QUICK: "11111111-1111-1111-1111-111111111112",
  EXECUTIVE_SUMMARY: "11111111-1111-1111-1111-111111111113",
  HIPAA: "11111111-1111-1111-1111-111111111114",
  AFFECTED_ITEMS: "11111111-1111-1111-1111-111111111115",
  SCAN_COMPARISON: "11111111-1111-1111-1111-111111111124",
  CWE_2011: "11111111-1111-1111-1111-111111111116",
  ISO_27001: "11111111-1111-1111-1111-111111111117",
  NIST_SP800_53: "11111111-1111-1111-1111-111111111118",
  OWASP_TOP_10_2013: "11111111-1111-1111-1111-111111111119",
  OWASP_TOP_10_2017: "11111111-1111-1111-1111-111111111125",
  PCI_DSS_32: "11111111-1111-1111-1111-111111111120",
  SARBANES_OXLEY: "11111111-1111-1111-1111-111111111121",
  STIG_DISA: "11111111-1111-1111-1111-111111111122",
  WASC_THREAT: "11111111-1111-1111-1111-111111111123",
};

// === Targets ===

export async function getTargets(limit = 100): Promise<TargetListResponse> {
  return apiRequest(`/targets?l=${limit}`);
}

export async function addTarget(target: Target): Promise<TargetInfo> {
  return apiRequest("/targets", { method: "POST", body: target });
}

export async function getTarget(targetId: string): Promise<TargetInfo> {
  return apiRequest(`/targets/${targetId}`);
}

export async function deleteTarget(targetId: string): Promise<void> {
  return apiRequest(`/targets/${targetId}`, { method: "DELETE" });
}

// === Scans ===

export async function getScans(limit = 100): Promise<{ scans: ScanItemResponse[]; pagination: Pagination }> {
  let scans: ScanItemResponse[] = [];
  try {
    const response = await apiRequest<{ scans: ScanItemResponse[]; pagination: Pagination }>(`/scans?l=${limit}`);
    scans = response.scans || [];
  } catch (e) {
    console.warn("Could not fetch remote scans, returning local only", e);
  }

  // Merge with local scans
  const local = JSON.parse(localStorage.getItem(LOCAL_SCANS_KEY) || "[]");
  scans = [...local, ...scans]
    .filter(s => {
      if (!s || !s.scan_id) return false;
      // Filter out basic "ghosts"
      if (!s.target?.address && !s.profile_name) return false;
      // Filter out scans that are stuck in "scheduled" or "queued" with no progress for too long
      // This is a heuristic - we keep them if they are local or have a recent start date
      return true;
    })
    .slice(0, limit);

  return {
    scans,
    pagination: { count: scans.length }
  };
}

export async function scheduleScan(scan: ScanRequest): Promise<ScanItemResponse> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: "POST",
    headers: { "X-Auth": API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(scan),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`API Error ${res.status}: ${errText}`);
  }
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanItemResponse> {
  try {
    return await apiRequest(`/scans/${scanId}`);
  } catch (err) {
    if (scanId.startsWith("local-")) {
      const local = JSON.parse(localStorage.getItem(LOCAL_SCANS_KEY) || "[]");
      const found = local.find((s: any) => s.scan_id === scanId);
      if (found) return found;
    }
    throw err;
  }
}

export async function abortScan(scanId: string): Promise<void> {
  return apiRequest(`/scans/${scanId}/abort`, { method: "POST" });
}

export async function resumeScan(scanId: string): Promise<void> {
  return apiRequest(`/scans/${scanId}/resume`, { method: "POST" });
}

export async function deleteScan(scanId: string): Promise<void> {
  return apiRequest(`/scans/${scanId}`, { method: "DELETE" });
}

export async function getScanResults(scanId: string): Promise<ScanResultListResponse> {
  try {
    return await apiRequest(`/scans/${scanId}/results`);
  } catch (err) {
    if (scanId.startsWith("local-")) {
      // Local scans don't have separate results in the bridge usually, 
      // but we might simulate a result wrapper
      return {
        result_list: [{
          result_id: `res-${scanId}`,
          scan_id: scanId,
          status: "completed",
          start_date: new Date().toISOString()
        }],
        pagination: { count: 1 }
      };
    }
    throw err;
  }
}

// === Scan Result Vulnerabilities ===

export async function getScanVulnerabilities(
  scanId: string,
  resultId: string,
  limit = 100
): Promise<VulnerabilityListResponse> {
  return apiRequest(`/scans/${scanId}/results/${resultId}/vulnerabilities?l=${limit}`);
}

// === Vulnerabilities (global) ===

export async function getVulnerabilities(limit = 100): Promise<VulnerabilityListResponse> {
  let vulnerabilities: Vulnerability[] = [];
  try {
    const data = await apiRequest<VulnerabilityListResponse>(`/vulnerabilities?l=${limit}`);
    vulnerabilities = data.vulnerabilities || [];
  } catch (e) {
    console.warn("Could not fetch remote vulnerabilities, returning local only", e);
  }

  // Merge with local vulnerabilities
  const local = getLocalVulnerabilities();
  vulnerabilities = [...local, ...vulnerabilities].slice(0, limit);

  return {
    vulnerabilities,
    pagination: { count: vulnerabilities.length }
  };
}

export async function getVulnerabilityDetails(vulnId: string): Promise<VulnerabilityDetails> {
  return apiRequest(`/vulnerabilities/${vulnId}`);
}

// === Vulnerability Types ===

export async function getVulnerabilityTypes(limit = 100): Promise<any> {
  return apiRequest(`/vulnerability_types?l=${limit}`);
}

// === Reports ===

export async function getReportTemplates(): Promise<ReportTemplateList> {
  return apiRequest("/report_templates");
}

export async function getReports(limit = 100): Promise<ReportListResponse> {
  return apiRequest(`/reports?l=${limit}`);
}

export async function generateReport(report: NewReport): Promise<Report> {
  const res = await fetch(`${API_BASE}/reports`, {
    method: "POST",
    headers: { "X-Auth": API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`API Error ${res.status}: ${errText}`);
  }
  return res.json();
}

export async function getReport(reportId: string): Promise<Report> {
  return apiRequest(`/reports/${reportId}`);
}

export async function deleteReport(reportId: string): Promise<void> {
  return apiRequest(`/reports/${reportId}`, { method: "DELETE" });
}

export async function downloadReport(descriptor: string): Promise<Blob> {
  const res = await fetch(`${API_BASE}/reports/download/${descriptor}`, {
    headers: { "X-Auth": API_KEY },
  });
  if (!res.ok) throw new Error("Failed to download report");
  return res.blob();
}

// === Scanning Profiles ===

export async function getScanningProfiles(): Promise<{ scanning_profiles: ScanningProfile[] }> {
  return apiRequest("/scanning_profiles");
}

// === Health ===

export async function healthCheck(): Promise<any> {
  return apiRequest("/info");
}
