import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { PageHeader, StatusBadge, SeverityBadge, severityCountsToArray } from "@/components/CyberComponents";
import {
  getScan, getScanResults, getScanVulnerabilities,
  type ScanItemResponse, type Vulnerability, severityToString,
} from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#DC2626", high: "#F97316", medium: "#EAB308", low: "#22C55E", info: "#6B7280",
};

const ScanDetails = () => {
  const { id } = useParams();
  const [scan, setScan] = useState<ScanItemResponse | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        let scanData: ScanItemResponse;
        try {
          scanData = await getScan(id);
        } catch (err) {
          // Fallback to local scans
          const local = JSON.parse(localStorage.getItem("anshu_local_scans") || "[]");
          const found = local.find((s: any) => s.scan_id === id);
          if (!found) throw new Error("Scan not found locally or remotely");
          scanData = found;
        }
        setScan(scanData);

        // Try to load vulnerabilities
        try {
          const results = await getScanResults(id);
          if (results.result_list && results.result_list.length > 0) {
            const latestResult = results.result_list[0];
            const vulnData = await getScanVulnerabilities(id, latestResult.result_id, 100);
            setVulns(vulnData.vulnerabilities);
          }
        } catch {
          // Fallback to local vulnerabilities
          const localVulns = JSON.parse(localStorage.getItem("anshu_local_vulnerabilities") || "[]");
          const filtered = localVulns.filter((v: any) => v.affects_url?.includes(scanData.target?.address || "") || v.target_description === scanData.profile_name);
          setVulns(filtered.map((v: any) => ({
            ...v,
            vuln_id: v.id,
            status: "open",
            confidence: v.confidence || "High"
          })));
        }
      } catch (e: any) {
        toast.error("Failed to load scan details", { description: e.message });
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Scan Details" description="Loading..." />
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          {[1, 2, 3, 4, 5].map((i) => <Skeleton key={i} className="h-20 rounded-lg" />)}
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Scan Details" description="Scan not found" />
        <div className="cyber-card p-8 text-center text-muted-foreground">No scan data available for this ID.</div>
      </div>
    );
  }

  const counts = severityCountsToArray(scan.current_session?.severity_counts);
  const severityData = [
    { name: "Critical", value: counts[0], color: SEVERITY_COLORS.critical },
    { name: "High", value: counts[1], color: SEVERITY_COLORS.high },
    { name: "Medium", value: counts[2], color: SEVERITY_COLORS.medium },
    { name: "Low", value: counts[3], color: SEVERITY_COLORS.low },
    { name: "Info", value: counts[4], color: SEVERITY_COLORS.info },
  ].filter((d) => d.value > 0);

  const status = scan.current_session?.status || "scheduled";

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title={`Scan — ${scan.target?.address || scan.scan_id.slice(0, 8)}`} description="Detailed analysis and findings" />

      {/* Scan Info */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {[
          { label: "Target", value: scan.target?.address || "—" },
          { label: "Profile", value: scan.profile_name || "—" },
          { label: "Status", value: status },
          { label: "Progress", value: `${scan.current_session?.progress ?? 0}%` },
          { label: "Total Vulns", value: String(vulns.length) },
        ].map((info) => (
          <div key={info.label} className="cyber-card p-4">
            <p className="text-xs text-muted-foreground">{info.label}</p>
            {info.label === "Status" ? (
              <div className="mt-1"><StatusBadge status={info.value as any} /></div>
            ) : (
              <p className="text-sm font-semibold text-foreground mt-1 mono truncate">{info.value}</p>
            )}
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" strokeWidth={0}>
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-center py-8 text-sm">No vulnerabilities found</p>
          )}
        </div>

        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">By Severity</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={11} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-center py-8 text-sm">No data</p>
          )}
        </div>
      </div>

      {/* Vulnerability Table */}
      <div className="cyber-card overflow-hidden">
        <div className="p-5 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground">Vulnerabilities Found ({vulns.length})</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Name", "Severity", "Status", "URL", "Confidence"].map((h) => (
                  <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.length === 0 ? (
                <tr><td colSpan={5} className="p-8 text-center text-muted-foreground">No vulnerabilities found</td></tr>
              ) : (
                vulns.map((v, i) => (
                  <tr key={v.vuln_id || i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 font-medium text-foreground">{v.vt_name}</td>
                    <td className="p-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="p-3 text-muted-foreground capitalize text-xs">{v.status}</td>
                    <td className="p-3 mono text-xs text-primary max-w-xs truncate">{v.affects_url || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs">{v.confidence ?? "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ScanDetails;
