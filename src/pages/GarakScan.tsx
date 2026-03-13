import { useState, useCallback, useEffect } from "react";
import { Upload, FileText, ShieldAlert, CheckCircle, XCircle, BarChart3, Play, Loader2, Plus, Cpu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/CyberComponents";
import { toast } from "sonner";
import { parseGarakJsonl, summarizeGarak, saveGarakSummary, getGarakHistory, type GarakSummary, type GarakProbeResult } from "@/lib/garak-parser";
import { getVulnerabilities, severityToString, saveLocalVulnerability, saveLocalScan, type Vulnerability, type ScanResult, type PortResult } from "@/lib/api";
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";
import { cn } from "@/lib/utils";
import { Terminal, ChevronDown, ChevronUp } from "lucide-react";

const RESULT_COLORS = { passed: "#22C55E", failed: "#DC2626" };

const GarakScan = () => {
  const [rawInput, setRawInput] = useState("");
  const [summary, setSummary] = useState<GarakSummary | null>(null);
  const [showFilter, setShowFilter] = useState<"all" | "passed" | "failed">("all");
  const [loading, setLoading] = useState(false);

  // New state for live scanning
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [availableProbes, setAvailableProbes] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("openai.GPT4");
  const [selectedProbes, setSelectedProbes] = useState("all");
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [showLogs, setShowLogs] = useState(false);

  // Load available models and probes from bridge
  useEffect(() => {
    const fetchMetadata = async () => {
      try {
        const [modelsRes, probesRes] = await Promise.all([
          fetch("http://localhost:8002/api/v1/garak/models"),
          fetch("http://localhost:8002/api/v1/garak/probes")
        ]);
        if (modelsRes.ok) setAvailableModels(await modelsRes.json());
        if (probesRes.ok) setAvailableProbes(await probesRes.json());
      } catch (err) {
        console.error("Failed to fetch metadata from bridge", err);
      }
    };
    fetchMetadata();
  }, []);

  const pollScanStatus = useCallback((scanId: string) => {
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`http://localhost:8002/api/v1/garak/status/${scanId}`);
        const data = await res.json();
        setScanProgress(data.progress);
        setLogs(data.logs || []);

        if (data.status === "completed") {
          clearInterval(timer);
          fetchResults(scanId);
        } else if (data.status === "failed") {
          clearInterval(timer);
          toast.error("Scan failed", { description: data.message });
          setLoading(false);
        }
      } catch (err) {
        clearInterval(timer);
        setLoading(false);
      }
    }, 2000);
  }, []);

  const fetchResults = async (scanId: string) => {
    try {
      const res = await fetch(`http://localhost:8002/api/v1/garak/results/${scanId}`);
      const results = await res.json();

      const liveSummary: GarakSummary = {
        runId: scanId,
        generator: selectedModel,
        totalAttempts: results.length || 1,
        totalPassed: 0,
        totalFailed: results.length,
        overallPassRate: 0,
        probeResults: [{
          probe: selectedProbes,
          detector: "BridgeDetector",
          total: results.length,
          passed: 0,
          failed: results.length,
          passRate: 0
        }],
        vulnerabilities: results,
        categories: {
          "Live": { total: results.length, passed: 0, failed: results.length }
        },
        timestamp: new Date().toISOString()
      };

      setSummary(liveSummary);
      saveGarakSummary(liveSummary);

      saveLocalScan({
        target: { address: selectedModel },
        profile_name: `Garak: ${selectedProbes}`,
        current_session: {
          status: "completed",
          severity_counts: {
            critical: 0, high: results.length, medium: 0, low: 0, info: 0
          }
        }
      });

      results.forEach((r: any) => {
        saveLocalVulnerability({
          vt_name: r.name || "AI Prompt Injection / Jailbreak",
          severity: r.severity === "high" ? 3 : r.severity === "critical" ? 4 : 2,
          affects_url: r.url || selectedModel,
          target_id: "garak-live",
          target_description: `Garak Probe: ${selectedProbes}`,
          source: "AI Security"
        });
      });

      toast.success("Scan results received", { description: `${results.length} issues found` });
    } catch (err) {
      toast.error("Failed to fetch results");
    } finally {
      setLoading(false);
      setActiveScanId(null);
    }
  };

  const handleLiveScan = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8002/api/v1/garak/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: selectedModel,
          probes: selectedProbes,
          generations: 5
        })
      });
      const data = await res.json();
      setActiveScanId(data.scan_id);
      setLogs([]);
      setShowLogs(true);
      toast.success("Live scan started", { description: "Monitoring progress..." });
      pollScanStatus(data.scan_id);
    } catch (err) {
      toast.error("Bridge not running", { description: "Please start security_bridge.py first." });
      setLoading(false);
    }
  };

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.endsWith(".jsonl") && !file.name.endsWith(".json")) {
      toast.error("Please upload a .jsonl report file");
      return;
    }
    setLoading(true);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setRawInput(text);
      processReport(text);
    };
    reader.onerror = () => {
      toast.error("Failed to read file");
      setLoading(false);
    };
    reader.readAsText(file);
  }, []);

  const processReport = (text: string) => {
    setLoading(true);
    try {
      const entries = parseGarakJsonl(text);
      if (entries.length === 0) {
        toast.error("No valid entries found in the report");
        setLoading(false);
        return;
      }
      const s = summarizeGarak(entries);
      setSummary(s);
      saveGarakSummary(s);
      toast.success("Report parsed", { description: `${s.totalAttempts} attempts analyzed` });
    } catch (err: any) {
      toast.error("Failed to parse report", { description: err.message });
    } finally {
      setLoading(false);
    }
  };

  const pieData = summary
    ? [
      { name: "Passed", value: summary.totalPassed, color: RESULT_COLORS.passed },
      { name: "Failed", value: summary.totalFailed, color: RESULT_COLORS.failed },
    ].filter((d) => d.value > 0)
    : [];

  const categoryData = summary
    ? Object.entries(summary.categories).map(([name, stats]) => ({
      name,
      passed: stats.passed,
      failed: stats.failed,
    }))
    : [];

  const filteredProbes = summary?.probeResults.filter((p) => {
    if (showFilter === "passed") return p.passRate === 100;
    if (showFilter === "failed") return p.failed > 0;
    return true;
  }) || [];

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title="Model Vulnerability Scan" description="NVIDIA Garak LLM vulnerability scanner — Configuration and analysis">
        <label className="cursor-pointer">
          <input type="file" accept=".jsonl,.json" className="hidden" onChange={handleFileUpload} />
          <Button asChild variant="outline" size="sm">
            <span><Upload className="w-4 h-4 mr-2" />Upload Report</span>
          </Button>
        </label>
      </PageHeader>

      {/* Configuration Area */}
      {!summary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="cyber-card p-6 md:col-span-2 space-y-5">
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">Configure Live Scan</h3>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-xs font-medium text-muted-foreground">Select Model</label>
                  <select
                    className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mono"
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                  >
                    {availableModels.length > 0 ? (
                      availableModels.map(m => <option key={m} value={m}>{m}</option>)
                    ) : (
                      <option>openai.GPT4</option>
                    )}
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-muted-foreground">Select Probe Profile</label>
                  <select
                    className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mono"
                    value={selectedProbes}
                    onChange={(e) => setSelectedProbes(e.target.value)}
                  >
                    <option value="all">All Probes</option>
                    {availableProbes.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
              </div>

              {activeScanId && (
                <div className="space-y-2 pt-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Scanning in progress...</span>
                    <span className="text-primary font-bold">{scanProgress}%</span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-primary h-full transition-all duration-500 ease-out"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>
              )}

              <Button
                onClick={handleLiveScan}
                className="w-full h-11 font-bold gap-2"
                disabled={loading || !!activeScanId}
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {loading ? "Initializing..." : "Start Live Security Probe"}
              </Button>
            </div>

            {/* Live Logs Component */}
            {showLogs && (
              <div className="mt-4 cyber-card p-0 overflow-hidden border-primary/20 bg-black/40">
                <div
                  className="flex items-center justify-between p-3 cursor-pointer hover:bg-white/5 transition-colors"
                  onClick={() => setShowLogs(!showLogs)}
                >
                  <div className="flex items-center gap-2 text-primary">
                    <Terminal className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-wider">Garak Live Logs</span>
                  </div>
                  {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
                <div className="p-4 bg-black/60 font-mono text-[11px] leading-relaxed max-h-[200px] overflow-y-auto cyber-scrollbar">
                  {logs.length === 0 && <p className="text-muted-foreground italic">Initializing Garak engine...</p>}
                  {logs.map((log, i) => (
                    <div key={i} className="flex gap-3 text-cyan-500/80">
                      <span className="text-muted-foreground/30 shrink-0 select-none">[{i + 1}]</span>
                      <span className="whitespace-pre-wrap">{log}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="cyber-card p-6 space-y-4">
            <div className="flex items-center gap-3">
              <FileText className="w-5 h-5 text-muted-foreground" />
              <h3 className="text-sm font-semibold text-foreground">Manual Report Analysis</h3>
            </div>
            <p className="text-xs text-muted-foreground">
              Paste Garak JSONL report content here for immediate visualization and persistence.
            </p>
            <Textarea
              placeholder="Paste .jsonl content..."
              className="min-h-[150px] bg-muted/50 border-border text-xs mono"
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
            />
            <Button
              className="w-full"
              variant="outline"
              onClick={() => processReport(rawInput)}
              disabled={!rawInput.trim() || loading}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <BarChart3 className="w-4 h-4 mr-2" />}
              Analyze Report
            </Button>
          </div>
        </div>
      )}

      {/* Results */}
      {summary && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="stat-card">
              <p className="text-sm text-muted-foreground font-medium">Total Probes</p>
              <p className="text-3xl font-bold text-foreground mt-1 mono">{summary.totalAttempts}</p>
              <p className="text-xs text-muted-foreground mt-2">{summary.probeResults.length} unique tests</p>
            </div>
            <div className="stat-card">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-severity-low" />
                <p className="text-sm text-muted-foreground font-medium">Passed</p>
              </div>
              <p className="text-3xl font-bold text-foreground mt-1 mono">{summary.totalPassed}</p>
              <p className="text-xs text-severity-low mt-2">{summary.overallPassRate.toFixed(1)}% pass rate</p>
            </div>
            <div className="stat-card">
              <div className="flex items-center gap-2">
                <XCircle className="w-4 h-4 text-destructive" />
                <p className="text-sm text-muted-foreground font-medium">Failed</p>
              </div>
              <p className="text-3xl font-bold text-foreground mt-1 mono">{summary.totalFailed}</p>
              <p className="text-xs text-destructive mt-2">{summary.totalFailed} vulnerabilities found</p>
            </div>
            <div className="stat-card">
              <p className="text-sm text-muted-foreground font-medium">Model</p>
              <p className="text-lg font-bold text-foreground mt-1 truncate">{summary.generator}</p>
              <p className="text-xs text-muted-foreground mt-2">Run: {summary.runId.slice(0, 8)}…</p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="cyber-card p-5 lg:col-span-2 overflow-hidden">
              <h3 className="text-sm font-semibold text-foreground mb-4">Results by Category</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={categoryData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={11} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }} />
                  <Bar dataKey="passed" stackId="a" fill={RESULT_COLORS.passed} radius={[0, 0, 0, 0]} name="Passed" />
                  <Bar dataKey="failed" stackId="a" fill={RESULT_COLORS.failed} radius={[4, 4, 0, 0]} name="Failed" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="cyber-card p-5 overflow-hidden">
              <h3 className="text-sm font-semibold text-foreground mb-4">Overall Results</h3>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" strokeWidth={0}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex justify-center flex-wrap gap-4 mt-3">
                {pieData.map((item) => (
                  <div key={item.name} className="flex items-center gap-2 text-xs">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-muted-foreground">{item.name}</span>
                    <span className="font-semibold text-foreground">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="cyber-card overflow-hidden">
            <div className="p-5 border-b border-border flex flex-col sm:flex-row items-center justify-between gap-4">
              <h3 className="text-sm font-semibold text-foreground">Probe Results</h3>
              <div className="flex flex-wrap gap-1">
                {(["all", "failed", "passed"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setShowFilter(f)}
                    className={cn(
                      "px-3 py-1 rounded-full text-xs font-medium transition-colors",
                      showFilter === f ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-muted/80"
                    )}
                  >
                    {f.charAt(0).toUpperCase() + f.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Probe</th>
                    <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Detector</th>
                    <th className="text-center p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Total</th>
                    <th className="text-center p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Passed</th>
                    <th className="text-center p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Failed</th>
                    <th className="text-center p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Pass Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProbes.length === 0 ? (
                    <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">No matching results</td></tr>
                  ) : (
                    filteredProbes.map((p, i) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                        <td className="p-3 font-medium text-foreground font-mono text-xs">{p.probe}</td>
                        <td className="p-3 text-muted-foreground text-xs">{p.detector}</td>
                        <td className="p-3 text-center mono">{p.total}</td>
                        <td className="p-3 text-center text-severity-low mono">{p.passed}</td>
                        <td className="p-3 text-center text-destructive mono">{p.failed}</td>
                        <td className="p-3 text-center">
                          <span className={cn(
                            "px-2 py-0.5 rounded-full text-xs font-semibold",
                            p.passRate === 100 ? "bg-severity-low/10 text-severity-low" :
                              p.passRate >= 80 ? "bg-severity-medium/10 text-severity-medium" :
                                "bg-destructive/10 text-destructive"
                          )}>
                            {p.passRate.toFixed(0)}%
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="flex justify-center gap-4">
            <Button variant="outline" size="sm" onClick={() => { setSummary(null); setRawInput(""); }}>
              <Plus className="w-4 h-4 mr-2" /> Start New Scan
            </Button>
          </div>
        </>
      )}

      {/* History Section (Always Visible) */}
      {!activeScanId && (
        <div className="cyber-card p-6 overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <BarChart3 className="w-5 h-5 text-muted-foreground" />
              <h3 className="text-sm font-semibold text-foreground">Recent Scan History</h3>
            </div>
          </div>
          <div className="space-y-3">
            {getGarakHistory().length === 0 ? (
              <p className="text-xs text-muted-foreground italic">No past scans found in local storage.</p>
            ) : (
              getGarakHistory().map((hs, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors cursor-pointer group" onClick={() => setSummary(hs)}>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground truncate">{hs.generator}</p>
                    <p className="text-[10px] text-foreground/60 mt-0.5">{hs.timestamp ? new Date(hs.timestamp).toLocaleString() : "Unknown date"}</p>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <div className="text-right mr-4">
                      <p className="text-xs font-bold text-foreground">{hs.overallPassRate.toFixed(1)}%</p>
                      <p className="text-[10px] text-foreground/50 uppercase">Pass Rate</p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default GarakScan;
