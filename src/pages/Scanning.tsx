import { useEffect, useState } from "react";
import { RefreshCw, StopCircle, Terminal, Activity, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader, StatusBadge, VulnIndicators, severityCountsToArray } from "@/components/CyberComponents";
import { getScans, abortScan, type ScanItemResponse } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { Link } from "react-router-dom";

const Scanning = () => {
  const [scans, setScans] = useState<ScanItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeLogs, setActiveLogs] = useState<Record<string, string[]>>({});

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await getScans(50);
      setScans(data.scans);

      // Update logs for running scans
      const newLogs = { ...activeLogs };
      data.scans.forEach(s => {
        const sid = s.scan_id;
        const status = s.current_session?.status;
        const progress = s.current_session?.progress || 0;

        if (status === "processing" || status === "starting") {
          if (!newLogs[sid]) newLogs[sid] = ["Initializing scan engine...", "Target identified and reachable."];

          if (progress > 10 && !newLogs[sid].includes("Crawling target structure...")) newLogs[sid].push("Crawling target structure...");
          if (progress > 30 && !newLogs[sid].includes("Identifying technology stack...")) newLogs[sid].push("Identifying technology stack...");
          if (progress > 50 && !newLogs[sid].includes("Running vulnerability scripts...")) newLogs[sid].push("Running vulnerability scripts...");
          if (progress > 70 && !newLogs[sid].includes("Analyzing response patterns...")) newLogs[sid].push("Analyzing response patterns...");
          if (progress > 90 && !newLogs[sid].includes("Finalizing results and metrics...")) newLogs[sid].push("Finalizing results and metrics...");

          // Keep only last 5 steps
          newLogs[sid] = newLogs[sid].slice(-5);
        }
      });
      setActiveLogs(newLogs);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadScans(); }, []);

  // Auto-refresh if any scans are processing
  useEffect(() => {
    const hasRunning = scans.some((s) =>
      s.current_session?.status === "processing" ||
      s.current_session?.status === "starting" ||
      s.current_session?.status === "queued"
    );
    if (!hasRunning) return;
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [scans]);

  const handleAbort = async (scanId: string) => {
    try {
      await abortScan(scanId);
      toast.success("Scan abort requested");
      loadScans();
    } catch (e: any) {
      toast.error("Failed to abort scan", { description: e.message });
    }
  };

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <PageHeader title="Scanning" description="Active and recent scan results" />
        <Button variant="outline" size="sm" onClick={loadScans} disabled={loading} className="gap-2">
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} /> Refresh
        </Button>
      </div>

      {error && (
        <div className="cyber-card p-6 text-center">
          <p className="text-destructive font-medium">Failed to load scans</p>
          <p className="text-muted-foreground text-sm mt-1">{error}</p>
        </div>
      )}

      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</th>
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Profile / Engine Activity</th>
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Progress</th>
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Vulnerabilities</th>
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && scans.length === 0 ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    <td className="p-3" colSpan={6}><Skeleton className="h-12 w-full" /></td>
                  </tr>
                ))
              ) : scans.length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">No scans found. Start a scan from the Input Target page.</td></tr>
              ) : (
                scans.map((scan) => {
                  const status = scan.current_session?.status || "scheduled";
                  const isRunning = status === "processing" || status === "starting";
                  const logs = activeLogs[scan.scan_id] || [];
                  return (
                    <tr key={scan.scan_id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                      <td className="p-3 font-medium text-foreground">
                        <div className="flex flex-col">
                          <span className="truncate max-w-[200px]">{scan.target?.address || "—"}</span>
                          <span className="text-[10px] text-muted-foreground">ID: {scan.scan_id.slice(0, 8)}…</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex flex-col gap-1">
                          <span className="text-muted-foreground text-xs">{scan.profile_name || "—"}</span>
                          {isRunning && logs.length > 0 && (
                            <div className="flex flex-col gap-0.5 mt-1 border-l border-primary/20 pl-2">
                              {logs.map((log, i) => (
                                <div key={i} className={cn(
                                  "flex items-center gap-1.5 text-[9px] leading-tight",
                                  i === logs.length - 1 ? "text-primary animate-pulse" : "text-muted-foreground/60"
                                )}>
                                  <ChevronRight className="w-2 h-2" />
                                  <span>{log}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-3">
                        {isRunning ? (
                          <div className="flex flex-col gap-1.5 min-w-[120px]">
                            <div className="flex justify-between text-[10px] mono">
                              <span className="text-primary font-bold">ANALYZING</span>
                              <span className="text-muted-foreground">{scan.current_session?.progress || 0}%</span>
                            </div>
                            <div className="w-full h-1 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary rounded-full shadow-[0_0_8px_rgba(59,130,246,0.5)] transition-all duration-1000"
                                style={{ width: `${scan.current_session?.progress || 0}%` }}
                              />
                            </div>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="p-3">
                        <VulnIndicators counts={severityCountsToArray(scan.current_session?.severity_counts)} />
                      </td>
                      <td className="p-3"><StatusBadge status={status} /></td>
                      <td className="p-3">
                        <div className="flex gap-1">
                          {isRunning && (
                            <Button variant="ghost" size="sm" className="h-8 text-xs gap-1 text-destructive hover:bg-destructive/10" onClick={() => handleAbort(scan.scan_id)}>
                              <StopCircle className="w-3 h-3" /> Abort
                            </Button>
                          )}
                          <Button variant="ghost" size="sm" className="h-8 text-xs gap-1" asChild>
                            <Link to={`/scan-details/${scan.scan_id}`}><Activity className="w-3 h-3" /> Details</Link>
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Scanning;
