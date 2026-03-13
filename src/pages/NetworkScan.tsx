import { useState, useEffect, useRef } from "react";
import { Network, Play, Loader2, Plus, X, Terminal, Download, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader, SeverityBadge } from "@/components/CyberComponents";
import { saveLocalVulnerability, saveLocalScan, type ScanResult, type PortResult } from "@/lib/api";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
} from "recharts";
import { cn } from "@/lib/utils";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

const STATE_COLORS: Record<string, string> = {
  open: "#22C55E",
  closed: "#6B7280",
  filtered: "#F97316",
};

const DEFAULT_PORTS_STR = "21,22,23,25,53,80,110,135,139,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017";

const NetworkScan = () => {
  const [target, setTarget] = useState("");
  const [portsStr, setPortsStr] = useState(DEFAULT_PORTS_STR);
  const [customPort, setCustomPort] = useState("");
  const [timeout, setTimeout_] = useState(3000);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [showFilter, setShowFilter] = useState<"all" | "open" | "closed" | "filtered">("all");
  const [useLocalBridge, setUseLocalBridge] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [showLogs, setShowLogs] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  const pollTimerRef = useRef<number | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (showLogs && logs.length > 0) {
      const container = logsEndRef.current?.parentElement;
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    }
  }, [logs, showLogs]);

  const parseNmapXml = (xmlStr: string): PortResult[] => {
    if (!xmlStr) return [];
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlStr, "text/xml");
    const ports = xmlDoc.getElementsByTagName("port");
    const results: PortResult[] = [];

    for (let i = 0; i < ports.length; i++) {
      const portNode = ports[i];
      const portId = parseInt(portNode.getAttribute("portid") || "0");
      const stateNode = portNode.getElementsByTagName("state")[0];
      const serviceNode = portNode.getElementsByTagName("service")[0];

      const state = (stateNode?.getAttribute("state") as any) || "closed";
      const service = serviceNode?.getAttribute("name") || "unknown";

      results.push({
        port: portId,
        state: state === "open" ? "open" : state === "filtered" ? "filtered" : "closed",
        service,
      });
    }
    return results;
  };

  const handleScan = async () => {
    if (!target) {
      toast.error("Please enter a target IP or hostname");
      return;
    }
    setLoading(true);
    setResult(null);
    setLogs([]);
    setProgress(0);
    setShowLogs(true);

    try {
      const portsArr = portsStr
        .split(",")
        .map((p) => parseInt(p.trim()))
        .filter((p) => !isNaN(p) && p > 0 && p <= 65535);

      if (useLocalBridge) {
        const response = await fetch("http://localhost:8002/api/v1/nmap/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target, ports: portsArr }),
        });
        if (!response.ok) throw new Error("Bridge connection failed");
        const { scan_id } = await response.json();
        setScanId(scan_id);
        startPolling(scan_id);
      } else {
        const { data: edgeData, error } = await supabase.functions.invoke("nmap-scan", {
          body: { target, ports: portsArr, timeout },
        });
        if (error) throw error;
        setResult(edgeData);
        setLoading(false);
        toast.success("Scan complete");
      }
    } catch (e: any) {
      toast.error("Scan failed", { description: e.message });
      setLoading(false);
    }
  };

  const startPolling = (id: string) => {
    if (pollTimerRef.current) window.clearInterval(pollTimerRef.current);
    pollTimerRef.current = window.setInterval(async () => {
      try {
        const resp = await fetch(`http://localhost:8002/api/v1/nmap/status/${id}`);
        if (!resp.ok) return;
        const data = await resp.json();

        setLogs(data.logs || []);
        setProgress(data.progress || 0);

        if (data.status === "completed") {
          stopPolling();
          const parsedResults = parseNmapXml(data.raw_output);
          const finalResult: ScanResult = {
            target,
            ip: target,
            scan_time: new Date().toISOString(),
            total_ports_scanned: parsedResults.length,
            summary: {
              open: parsedResults.filter(r => r.state === "open").length,
              closed: parsedResults.filter(r => r.state === "closed").length,
              filtered: parsedResults.filter(r => r.state === "filtered").length,
            },
            results: parsedResults
          };
          setResult(finalResult);
          setLoading(false);
          toast.success("Scan complete");

          // Persist
          saveLocalScan({
            target: { address: target },
            profile_name: "Local Nmap Scan",
            scan_id: id,
            current_session: {
              status: "completed",
              severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: finalResult.summary.open }
            }
          });

          finalResult.results.filter(r => r.state === "open").forEach(r => {
            saveLocalVulnerability({
              vt_name: `Open Port: ${r.port} (${r.service})`,
              severity: 0,
              affects_url: `${target}:${r.port}`,
              target_description: "Local Nmap Scan",
              source: "Network"
            });
          });
        } else if (data.status === "failed") {
          stopPolling();
          setLoading(false);
          toast.error("Scan failed", { description: data.message });
        }
      } catch (e) {
        console.error("Polling error", e);
      }
    }, 2000);
  };

  const stopPolling = () => {
    if (pollTimerRef.current) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const addCustomPort = () => {
    const port = parseInt(customPort);
    if (isNaN(port) || port < 1 || port > 65535) {
      toast.error("Invalid port number (1-65535)");
      return;
    }
    const existing = portsStr.split(",").map((p) => p.trim());
    if (!existing.includes(String(port))) {
      setPortsStr(portsStr + "," + port);
    }
    setCustomPort("");
  };

  const filteredResults = result?.results.filter(
    (r) => showFilter === "all" || r.state === showFilter
  );

  const pieData = result
    ? [
      { name: "Open", value: result.summary.open, color: STATE_COLORS.open },
      { name: "Closed", value: result.summary.closed, color: STATE_COLORS.closed },
      { name: "Filtered", value: result.summary.filtered, color: STATE_COLORS.filtered },
    ].filter((d) => d.value > 0)
    : [];

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title="Network Scan" description="TCP port scanning via edge function proxy" />

      <div className="cyber-card p-6 space-y-5">
        <div className="space-y-2">
          <Label className="text-primary/70">Target (IP or Hostname)</Label>
          <div className="relative">
            <Network className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="192.168.1.1 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="bg-muted/50 border-border h-11 mono pl-10"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label className="text-primary/70">Ports (comma-separated)</Label>
          <Input
            value={portsStr}
            onChange={(e) => setPortsStr(e.target.value)}
            className="bg-muted/50 border-border mono text-xs"
          />
          <div className="flex gap-2">
            <Input
              placeholder="Add custom port"
              value={customPort}
              onChange={(e) => setCustomPort(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addCustomPort()}
              className="bg-muted/50 border-border h-9 w-40 mono text-xs"
            />
            <Button variant="outline" size="sm" onClick={addCustomPort} className="h-9 gap-1 text-xs">
              <Plus className="w-3 h-3" /> Add
            </Button>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="space-y-2">
            <Label className="text-primary/70">Timeout (ms)</Label>
            <Input
              type="number"
              value={timeout}
              onChange={(e) => setTimeout_(Number(e.target.value))}
              className="bg-muted/50 border-border h-9 w-32 mono text-xs"
              min={500}
              max={5000}
            />
          </div>
          <div className="flex items-center space-x-2 pt-6">
            <input
              type="checkbox"
              id="local-scan-check"
              className="w-4 h-4 accent-primary rounded cursor-pointer"
              checked={useLocalBridge}
              onChange={(e) => setUseLocalBridge(e.target.checked)}
            />
            <Label htmlFor="local-scan-check" className="cursor-pointer text-sm">Use Local Nmap</Label>
          </div>
        </div>

        <Button onClick={handleScan} disabled={loading} className="h-11 font-semibold gap-2 min-w-[140px]">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {loading ? `Scanning (${progress}%)` : "Start Scan"}
        </Button>
      </div>

      {/* Logs View */}
      {showLogs && (
        <div className="cyber-card p-0 overflow-hidden border-primary/20 bg-black/40">
          <div
            className="flex items-center justify-between p-3 cursor-pointer hover:bg-white/5 transition-colors"
            onClick={() => setShowLogs(!showLogs)}
          >
            <div className="flex items-center gap-2 text-primary">
              <Terminal className="w-4 h-4" />
              <span className="text-xs font-bold uppercase tracking-wider">Live Activity Logs</span>
            </div>
            {showLogs ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
          <div className="p-4 bg-black/60 font-mono text-[11px] leading-relaxed h-[200px] overflow-y-auto cyber-scrollbar scroll-smooth">
            {logs.length === 0 && <p className="text-muted-foreground italic">Waiting for Nmap bridge output...</p>}
            {logs.map((log, i) => (
              <div key={i} className="flex gap-3 text-cyan-500/80">
                <span className="text-muted-foreground/40 shrink-0 select-none">[{i + 1}]</span>
                <span className="whitespace-pre-wrap">{log}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <Tabs defaultValue="summary" className="space-y-6 animate-in">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <h2 className="text-sm font-bold text-foreground flex items-center gap-2">
              <div className="w-1.5 h-4 bg-primary rounded-full" />
              Scan Results: {result.ip}
            </h2>
            <TabsList className="bg-muted/50 border border-border">
              <TabsTrigger value="summary">Overview</TabsTrigger>
              <TabsTrigger value="ports">Port List</TabsTrigger>
              <TabsTrigger value="raw">Raw JSON</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="summary" className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="cyber-card p-4">
                <p className="text-[10px] uppercase font-bold text-muted-foreground/60 tracking-wider">Status</p>
                <p className="text-sm font-bold text-primary mt-1 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  COMPLETED
                </p>
              </div>
              <div className="cyber-card p-4">
                <p className="text-[10px] uppercase font-bold text-muted-foreground/60 tracking-wider">Open</p>
                <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: STATE_COLORS.open }}>{result.summary.open}</p>
              </div>
              <div className="cyber-card p-4">
                <p className="text-[10px] uppercase font-bold text-muted-foreground/60 tracking-wider">Closed</p>
                <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: STATE_COLORS.closed }}>{result.summary.closed}</p>
              </div>
              <div className="cyber-card p-4">
                <p className="text-[10px] uppercase font-bold text-muted-foreground/60 tracking-wider">Filtered</p>
                <p className="text-2xl font-bold mt-1 tabular-nums" style={{ color: STATE_COLORS.filtered }}>{result.summary.filtered}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="cyber-card p-5 h-fit">
                <h3 className="text-xs font-bold text-foreground mb-6 uppercase tracking-widest border-l-2 border-primary pl-3">Port Distribution</h3>
                <div className="h-[200px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} dataKey="value" strokeWidth={0} paddingAngle={5}>
                        {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: '8px' }}
                        itemStyle={{ color: 'hsl(var(--foreground))' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 mt-4">
                  {pieData.map((d) => (
                    <div key={d.name} className="flex items-center gap-2 text-[10px] font-bold uppercase">
                      <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: d.color }} />
                      <span className="text-muted-foreground/80">{d.name}:</span>
                      <span className="text-foreground">{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="cyber-card p-5 lg:col-span-2">
                <h3 className="text-xs font-bold text-foreground mb-6 uppercase tracking-widest border-l-2 border-primary pl-3">Top Vulnerabilities</h3>
                <div className="space-y-4">
                  {result.results.filter(r => r.state === "open").slice(0, 3).map((r, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-border/50">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded bg-primary/10 flex items-center justify-center text-primary font-bold">
                          {r.port}
                        </div>
                        <div>
                          <p className="text-sm font-bold text-foreground">{r.service} Service Exposed</p>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Network Vulnerability Information</p>
                        </div>
                      </div>
                      <SeverityBadge severity="info" />
                    </div>
                  ))}
                  {result.summary.open === 0 && (
                    <p className="text-center py-8 text-muted-foreground italic text-sm">No open ports discovered (Low risk)</p>
                  )}
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="ports">
            <div className="cyber-card p-1 overflow-hidden">
              <div className="flex items-center justify-between p-4 border-b border-border/50">
                <h3 className="text-xs font-bold text-foreground uppercase tracking-widest pl-3 border-l-2 border-primary">
                  Detailed Port List
                </h3>
                <div className="flex gap-1 bg-black/20 p-1 rounded-lg">
                  {(["all", "open", "closed", "filtered"] as const).map((f) => (
                    <Button
                      key={f}
                      variant={showFilter === f ? "default" : "ghost"}
                      size="sm"
                      className={cn(
                        "h-7 text-[10px] px-3 capitalize font-bold",
                        showFilter === f ? "bg-primary text-black" : "text-muted-foreground/60 hover:text-primary"
                      )}
                      onClick={() => setShowFilter(f)}
                    >
                      {f} ({f === "all" ? result.results.length : result.summary[f as keyof typeof result.summary]})
                    </Button>
                  ))}
                </div>
              </div>
              <div className="overflow-x-auto max-h-[600px] overflow-y-auto cyber-scrollbar">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-muted/80 backdrop-blur-md z-10 shadow-sm">
                    <tr className="border-b border-white/5">
                      {["Port", "State", "Service", "Protocol", "Latency"].map((h) => (
                        <th key={h} className="text-left p-3 text-[10px] font-bold text-muted-foreground/40 uppercase tracking-widest">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResults?.map((r) => (
                      <tr key={r.port} className="border-b border-white/5 hover:bg-white/5 transition-colors group">
                        <td className="p-3 mono font-bold text-primary/90 group-hover:text-primary">{r.port}</td>
                        <td className="p-3">
                          <span
                            className="px-2 py-1 rounded text-[10px] font-bold uppercase border border-current/20"
                            style={{ backgroundColor: `${STATE_COLORS[r.state]}15`, color: STATE_COLORS[r.state] }}
                          >
                            {r.state}
                          </span>
                        </td>
                        <td className="p-3 text-foreground/70 font-medium">{r.service}</td>
                        <td className="p-3 text-muted-foreground/60">TCP</td>
                        <td className="p-3 mono text-muted-foreground/50 italic">{r.latency_ms ? `${r.latency_ms}ms` : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="raw">
            <div className="cyber-card p-5">
              <h3 className="text-xs font-bold text-foreground mb-4 uppercase tracking-widest border-l-2 border-primary pl-3">Raw Scan JSON</h3>
              <pre className="bg-muted/30 p-4 rounded-lg text-[10px] overflow-auto max-h-[500px] cyber-scrollbar mono text-primary/80">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
};

export default NetworkScan;
