// NVIDIA Garak JSONL Report Parser

export interface GarakEntry {
  entry_type?: string;
  status?: number; // 1 = init, 2 = attempt, 3 = evaluated
  probe?: string;
  detector?: string;
  generator?: string;
  goal?: string;
  prompt?: string;
  output?: string;
  passed?: boolean;
  score?: number;
  run_id?: string;
  attempt_id?: string;
  attempt_seq?: number;
  attempt_status?: string;
  notes?: string;
  [key: string]: any;
}

export interface GarakProbeResult {
  probe: string;
  detector: string;
  total: number;
  passed: number;
  failed: number;
  passRate: number;
}

export interface GarakSummary {
  runId: string;
  generator: string;
  totalAttempts: number;
  totalPassed: number;
  totalFailed: number;
  overallPassRate: number;
  probeResults: GarakProbeResult[];
  vulnerabilities: GarakEntry[];
  categories: Record<string, { total: number; passed: number; failed: number }>;
  timestamp?: string;
}

export function parseGarakJsonl(text: string): GarakEntry[] {
  const lines = text.trim().split("\n").filter(Boolean);
  const entries: GarakEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      // skip malformed lines
    }
  }
  return entries;
}

export function summarizeGarak(entries: GarakEntry[]): GarakSummary {
  const runId = entries[0]?.run_id || "unknown";
  const generator = entries.find((e) => e.generator)?.generator || "unknown";

  // Only look at evaluated entries (status 2 with passed field)
  const evaluated = entries.filter((e) => typeof e.passed === "boolean");

  const totalAttempts = evaluated.length;
  const totalPassed = evaluated.filter((e) => e.passed).length;
  const totalFailed = totalAttempts - totalPassed;
  const overallPassRate = totalAttempts > 0 ? (totalPassed / totalAttempts) * 100 : 0;

  // Group by probe+detector
  const probeMap = new Map<string, { probe: string; detector: string; total: number; passed: number; failed: number }>();
  for (const e of evaluated) {
    const key = `${e.probe || "unknown"}|${e.detector || "unknown"}`;
    if (!probeMap.has(key)) {
      probeMap.set(key, { probe: e.probe || "unknown", detector: e.detector || "unknown", total: 0, passed: 0, failed: 0 });
    }
    const item = probeMap.get(key)!;
    item.total++;
    if (e.passed) item.passed++;
    else item.failed++;
  }

  const probeResults: GarakProbeResult[] = Array.from(probeMap.values()).map((r) => ({
    ...r,
    passRate: r.total > 0 ? (r.passed / r.total) * 100 : 0,
  }));

  // Category grouping (first part of probe name, e.g. "lmrc" from "lmrc.Profanity")
  const categories: Record<string, { total: number; passed: number; failed: number }> = {};
  for (const e of evaluated) {
    const cat = (e.probe || "unknown").split(".")[0];
    if (!categories[cat]) categories[cat] = { total: 0, passed: 0, failed: 0 };
    categories[cat].total++;
    if (e.passed) categories[cat].passed++;
    else categories[cat].failed++;
  }

  // Vulnerabilities = failed attempts
  const vulnerabilities = evaluated.filter((e) => !e.passed);

  return { runId, generator, totalAttempts, totalPassed, totalFailed, overallPassRate, probeResults, vulnerabilities, categories };
}

// Persist Garak summaries to localStorage
const STORAGE_KEY = "garak_scan_history";

export function saveGarakSummary(summary: GarakSummary): void {
  try {
    const history = getGarakHistory();
    history.unshift({ ...summary, timestamp: new Date().toISOString() });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 20)));
  } catch { /* ignore */ }
}

export function getGarakHistory(): (GarakSummary & { timestamp?: string })[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}
