import { useEffect, useState } from "react";
import { Scan, Activity, Bug, Target, Smartphone, Network, Globe, Shield, Cpu } from "lucide-react";
import { StatCard, StatusBadge, PageHeader, severityCountsToArray, VulnIndicators, SeverityBadge } from "@/components/CyberComponents";
import { getScans, getVulnerabilities, getTargets, type ScanListResponse, type VulnerabilityListResponse, type TargetListResponse } from "@/lib/api";
import { severityToString } from "@/lib/api";
import { mobsfGetScans, type MobSFScanItem } from "@/lib/mobsf-api";
import { getGarakHistory, type GarakSummary } from "@/lib/garak-parser";
import { Skeleton } from "@/components/ui/skeleton";
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";
import { Link } from "react-router-dom";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626",
  high: "#F97316",
  medium: "#EAB308",
  low: "#22C55E",
  info: "#6B7280",
};

interface NetworkScanHistory {
  target: string;
  ip: string;
  scan_time: string;
  total_ports_scanned: number;
  summary: { open: number; closed: number; filtered: number };
}

const Dashboard = () => {
  const [scansData, setScansData] = useState<ScanListResponse | null>(null);
  const [vulnsData, setVulnsData] = useState<VulnerabilityListResponse | null>(null);
  const [targetsData, setTargetsData] = useState<TargetListResponse | null>(null);
  const [mobileScans, setMobileScans] = useState<MobSFScanItem[]>([]);
  const [networkScans, setNetworkScans] = useState<NetworkScanHistory[]>([]);
  const [garakScans, setGarakScans] = useState<(GarakSummary & { timestamp?: string })[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      const errors: string[] = [];

      // Load all three sources independently — don't let one failure block others
      const [scansResult, vulnsResult, targetsResult, mobileResult] = await Promise.allSettled([
        getScans(100),
        getVulnerabilities(100),
        getTargets(100),
        mobsfGetScans(1, 50),
      ]);

      if (scansResult.status === "fulfilled") setScansData(scansResult.value);
      else errors.push("Web scans");

      if (vulnsResult.status === "fulfilled") setVulnsData(vulnsResult.value);
      else errors.push("Vulnerabilities");

      if (targetsResult.status === "fulfilled") setTargetsData(targetsResult.value);
      else errors.push("Targets");

      if (mobileResult.status === "fulfilled") setMobileScans(mobileResult.value.content);
      else errors.push("Mobile scans");

      // Load local scan histories
      try {
        const stored = localStorage.getItem("network_scan_history");
        if (stored) setNetworkScans(JSON.parse(stored));
      } catch { /* ignore */ }

      setGarakScans(getGarakHistory());

      if (errors.length === 4) setError("All scanners unreachable");
      setLoading(false);
    }
    load();
  }, []);

  // Aggregate severity counts from web vulnerabilities
  const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulnsData?.vulnerabilities.forEach((v) => {
    const sev = severityToString(v.severity);
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  });

  const severityData = Object.entries(severityCounts)
    .map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      color: SEVERITY_COLORS[name] || "#6B7280",
    }))
    .filter((d) => d.value > 0);

  const scans = scansData?.scans || [];
  const activeScans = scans.filter((s) => s.current_session?.status === "processing" || s.current_session?.status === "starting").length;
  const completedScans = scans.filter((s) => s.current_session?.status === "completed").length;

  // Network aggregation
  const totalOpenPorts = networkScans.reduce((sum, s) => sum + s.summary.open, 0);
  const totalNetworkScans = networkScans.length;

  // Garak aggregation
  const totalGarakScans = garakScans.length;
  const totalGarakFailed = garakScans.reduce((sum, s) => sum + s.totalFailed, 0);
  const latestGarakPassRate = garakScans.length > 0 ? garakScans[0].overallPassRate : 0;

  // Scanner overview data for bar chart
  const scannerOverview = [
    { name: "Web", scans: scans.length, color: "hsl(221, 83%, 53%)" },
    { name: "Mobile", scans: mobileScans.length, color: "hsl(192, 91%, 36%)" },
    { name: "Network", scans: totalNetworkScans, color: "hsl(142, 71%, 45%)" },
    { name: "Model Security", scans: totalGarakScans, color: "hsl(280, 70%, 55%)" },
  ];

  if (loading) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Dashboard" description="Unified security overview across all scanners" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {[1, 2, 3, 4, 5].map((i) => <Skeleton key={i} className="h-28 rounded-lg" />)}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Dashboard" description="Unified security overview across all scanners" />
        <div className="cyber-card p-8 text-center">
          <p className="text-destructive font-medium">Failed to load dashboard data</p>
          <p className="text-muted-foreground text-sm mt-1">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title="Dashboard" description="Unified security overview across all scanners" />

      {/* Top-level stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard title="Web Scans" value={scans.length} icon={Globe} change={`${completedScans} completed`} changeType="positive" />
        <StatCard title="Mobile Scans" value={mobileScans.length} icon={Smartphone} change={`${mobileScans.length} apps analyzed`} changeType="neutral" />
        <StatCard title="Network Scans" value={totalNetworkScans} icon={Network} change={`${totalOpenPorts} open ports found`} changeType={totalOpenPorts > 0 ? "negative" : "positive"} />
        <StatCard title="Model Security Scans" value={totalGarakScans} icon={Cpu} change={totalGarakScans > 0 ? `${latestGarakPassRate.toFixed(0)}% pass rate` : "No scans yet"} changeType={totalGarakFailed > 0 ? "negative" : "positive"} />
        <StatCard title="Vulnerabilities" value={vulnsData?.vulnerabilities.length ?? 0} icon={Bug} change={`${severityCounts.critical} critical`} changeType={severityCounts.critical > 0 ? "negative" : "positive"} />
      </div>

      {/* Scanner Activity + Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Scanner Overview Bar */}
        <div className="cyber-card p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold text-foreground mb-4">Scans by Scanner</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={scannerOverview}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} opacity={0.5} />
              <XAxis
                dataKey="name"
                stroke="currentColor"
                fontSize={12}
                tickLine={false}
                axisLine={false}
                tick={{ fill: "hsl(var(--muted-foreground))" }}
              />
              <YAxis
                stroke="currentColor"
                fontSize={12}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
                tick={{ fill: "hsl(var(--muted-foreground))" }}
              />
              <Tooltip
                cursor={{ fill: "hsl(var(--muted))", opacity: 0.1 }}
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                  fontSize: "12px",
                  boxShadow: "0 10px 15px -3px rgb(0 0 0 / 0.1)"
                }}
              />
              <Bar dataKey="scans" radius={[4, 4, 0, 0]} barSize={40}>
                {scannerOverview.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Web Vulnerability Severity</h3>
          {severityData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={severityData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" strokeWidth={0}>
                    {severityData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {severityData.map((item) => (
                  <div key={item.name} className="flex items-center gap-2 text-xs">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-muted-foreground/80">{item.name}</span>
                    <span className="font-semibold text-foreground ml-auto">{item.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-muted-foreground text-sm text-center py-8">No vulnerabilities found</p>
          )}
        </div>
      </div>

      {/* Four-panel scanner summaries */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* Web Scans Summary */}
        <div className="cyber-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <Globe className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Recent Web Scans</h3>
          </div>
          <div className="divide-y divide-border/50">
            {scans.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground text-center">No web scans</p>
            ) : (
              scans.slice(0, 5).map((scan) => (
                <div key={scan.scan_id} className="p-3 flex items-center justify-between hover:bg-muted/20 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{scan.target?.address || "—"}</p>
                    <p className="text-xs text-muted-foreground">{scan.profile_name || "—"}</p>
                  </div>
                  <StatusBadge status={scan.current_session?.status || "scheduled"} />
                </div>
              ))
            )}
          </div>
          {scans.length > 0 && (
            <Link to="/scan-history" className="block p-3 text-center text-xs font-medium text-primary hover:underline border-t border-border">
              View all web scans →
            </Link>
          )}
        </div>

        {/* Mobile Scans Summary */}
        <div className="cyber-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <Smartphone className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-foreground">Recent Mobile Scans</h3>
          </div>
          <div className="divide-y divide-border/50">
            {mobileScans.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground text-center">No mobile scans</p>
            ) : (
              mobileScans.slice(0, 5).map((scan) => (
                <div key={scan.MD5} className="p-3 flex items-center justify-between hover:bg-muted/20 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{scan.APP_NAME || scan.FILE_NAME}</p>
                    <p className="text-xs text-muted-foreground">{scan.PACKAGE_NAME}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-accent/10 text-accent capitalize">
                    {scan.SCAN_TYPE}
                  </span>
                </div>
              ))
            )}
          </div>
          {mobileScans.length > 0 && (
            <Link to="/mobile-scans" className="block p-3 text-center text-xs font-medium text-accent hover:underline border-t border-border">
              View all mobile scans →
            </Link>
          )}
        </div>

        {/* Network Scans Summary */}
        <div className="cyber-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <Network className="w-4 h-4 text-severity-low" />
            <h3 className="text-sm font-semibold text-foreground">Recent Network Scans</h3>
          </div>
          <div className="divide-y divide-border/50">
            {networkScans.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground text-center">No network scans yet</p>
            ) : (
              networkScans.slice(0, 5).map((scan, i) => (
                <div key={i} className="p-3 flex items-center justify-between hover:bg-muted/20 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{scan.target}</p>
                    <p className="text-xs text-muted-foreground">{scan.total_ports_scanned} ports scanned</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${scan.summary.open > 0 ? "bg-destructive/10 text-destructive" : "bg-muted text-muted-foreground"}`}>
                    {scan.summary.open} open
                  </span>
                </div>
              ))
            )}
          </div>
          {networkScans.length > 0 && (
            <Link to="/network-scan" className="block p-3 text-center text-xs font-medium text-severity-low hover:underline border-t border-border">
              View network scanner →
            </Link>
          )}
        </div>

        {/* AI Model Scans Summary */}
        <div className="cyber-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <Cpu className="w-4 h-4" style={{ color: "hsl(280, 70%, 55%)" }} />
            <h3 className="text-sm font-semibold text-foreground">Recent Model Scans</h3>
          </div>
          <div className="divide-y divide-border/50">
            {garakScans.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground text-center">No Garak scans yet</p>
            ) : (
              garakScans.slice(0, 5).map((scan, i) => (
                <div key={i} className="p-3 flex items-center justify-between hover:bg-muted/20 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{scan.generator}</p>
                    <p className="text-xs text-muted-foreground">{scan.totalAttempts} probes · {scan.probeResults.length} tests</p>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${scan.totalFailed > 0 ? "bg-destructive/10 text-destructive" : "bg-severity-low/10 text-severity-low"}`}>
                    {scan.overallPassRate.toFixed(0)}% pass
                  </span>
                </div>
              ))
            )}
          </div>
          {garakScans.length > 0 && (
            <Link to="/garak-scan" className="block p-3 text-center text-xs font-medium hover:underline border-t border-border" style={{ color: "hsl(280, 70%, 55%)" }}>
              View model scanner →
            </Link>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
