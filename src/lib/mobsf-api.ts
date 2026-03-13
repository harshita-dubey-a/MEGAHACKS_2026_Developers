// MobSF API Client
const MOBSF_BASE = "http://0.0.0.0:8001/api/v1";
const MOBSF_API_KEY = "d6e733f8aa5aab02e90a47b888a9fcc2dc3ca3fcb509a869d4e6aab04dce03e6";

function authHeaders(): Record<string, string> {
  return { Authorization: MOBSF_API_KEY };
}

function jsonAuthHeaders(): Record<string, string> {
  return { ...authHeaders(), "Content-Type": "application/json" };
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `MobSF API Error ${res.status}`);
  }
  return res.json();
}

// === Types ===

export interface MobSFUploadResponse {
  file_name: string;
  hash: string;
  scan_type: string;
}

export interface MobSFScanItem {
  id: number;
  ANALYZER: string;
  SCAN_TYPE: string;
  FILE_NAME: string;
  APP_NAME: string;
  PACKAGE_NAME: string;
  VERSION_NAME: string;
  MD5: string;
  TIMESTAMP: string;
}

export interface MobSFScansResponse {
  content: MobSFScanItem[];
  count: number;
  num_pages: number;
}

export interface MobSFScanLog {
  timestamp: string;
  status: string;
  exception: string | null;
}

export interface MobSFScanLogsResponse {
  logs: MobSFScanLog[];
}

// === Upload & Scan ===

export async function mobsfUploadFile(file: File): Promise<MobSFUploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${MOBSF_BASE}/upload`, {
    method: "POST",
    headers: authHeaders(),
    body: formData,
  });
  return handleResponse(res);
}

export async function mobsfScan(hash: string, reScan = false): Promise<any> {
  const formData = new URLSearchParams();
  formData.set("hash", hash);
  if (reScan) formData.set("re_scan", "1");

  const res = await fetch(`${MOBSF_BASE}/scan`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
  });
  return handleResponse(res);
}

export async function mobsfScanLogs(hash: string): Promise<MobSFScanLogsResponse> {
  const res = await fetch(`${MOBSF_BASE}/scan_logs`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  return handleResponse(res);
}

// === List & Search ===

export async function mobsfGetScans(page = 1, pageSize = 20): Promise<MobSFScansResponse> {
  const res = await fetch(`${MOBSF_BASE}/scans?page=${page}&page_size=${pageSize}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function mobsfSearch(query: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/search`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ query }).toString(),
  });
  return handleResponse(res);
}

// === Delete ===

export async function mobsfDeleteScan(hash: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/delete_scan`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  return handleResponse(res);
}

// === Scorecard ===

export async function mobsfScorecard(hash: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/scorecard`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  return handleResponse(res);
}

// === Reports ===

export async function mobsfDownloadPdf(hash: string): Promise<Blob> {
  const res = await fetch(`${MOBSF_BASE}/download_pdf`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  if (!res.ok) throw new Error("Failed to download PDF report");
  return res.blob();
}

export async function mobsfReportJson(hash: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/report_json`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  return handleResponse(res);
}

// === Source ===

export async function mobsfViewSource(hash: string, file: string, type: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/view_source`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash, file, type }).toString(),
  });
  return handleResponse(res);
}

// === Compare ===

export async function mobsfCompare(hash1: string, hash2: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/compare`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash1, hash2 }).toString(),
  });
  return handleResponse(res);
}

// === Suppression ===

export async function mobsfSuppressByRule(hash: string, type: string, rule: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/suppress_by_rule`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash, type, rule }).toString(),
  });
  return handleResponse(res);
}

export async function mobsfSuppressByFiles(hash: string, type: string, rule: string, files: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/suppress_by_files`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash, type, rule, files }).toString(),
  });
  return handleResponse(res);
}

export async function mobsfListSuppressions(hash: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/list_suppressions`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash }).toString(),
  });
  return handleResponse(res);
}

export async function mobsfDeleteSuppression(hash: string, type: string, rule: string): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/delete_suppression`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ hash, type, rule }).toString(),
  });
  return handleResponse(res);
}

// === Tasks ===

export async function mobsfTasks(): Promise<any> {
  const res = await fetch(`${MOBSF_BASE}/tasks`, {
    method: "POST",
    headers: authHeaders(),
  });
  return handleResponse(res);
}
