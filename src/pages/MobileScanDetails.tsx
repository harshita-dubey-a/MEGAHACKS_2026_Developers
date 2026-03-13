import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { PageHeader, SeverityBadge } from "@/components/CyberComponents";
import { mobsfReportJson, mobsfScorecard, mobsfDownloadPdf } from "@/lib/mobsf-api";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Download, Loader2, Shield } from "lucide-react";
import { toast } from "sonner";
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  high: "#DC2626", warning: "#F97316", info: "#3B82F6", secure: "#22C55E", hotspot: "#EAB308",
};

const MobileScanDetails = () => {
  const { hash } = useParams();
  const [report, setReport] = useState<any>(null);
  const [scorecard, setScorecard] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [pdfLoading, setPdfLoading] = useState(false);

  useEffect(() => {
    if (!hash) return;
    Promise.all([
      mobsfReportJson(hash).catch(() => null),
      mobsfScorecard(hash).catch(() => null),
    ]).then(([r, s]) => {
      setReport(r);
      setScorecard(s);
    }).finally(() => setLoading(false));
  }, [hash]);

  const handleDownloadPdf = async () => {
    if (!hash) return;
    setPdfLoading(true);
    try {
      const blob = await mobsfDownloadPdf(hash);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mobile_report_${hash.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("PDF downloaded");
    } catch (e: any) {
      toast.error("PDF download failed", { description: e.message });
    } finally {
      setPdfLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Mobile Scan Details" description="Loading..." />
        <div className="grid grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-24 rounded-lg" />)}
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="space-y-6 animate-in">
        <PageHeader title="Mobile Scan Details" description="Report not available" />
        <div className="cyber-card p-8 text-center text-foreground/70">
          No report data available for hash: {hash}
        </div>
      </div>
    );
  }

  // Extract key info from MobSF JSON report
  const appName = report.app_name || report.title || report.metadata?.title || "Unknown App";
  const packageName = report.package_name || report.packagename || report.metadata?.package_name || "—";
  const version = report.version_name || report.app_version || report.metadata?.version_name || "—";
  const scanType = report.scan_type || report.file_name?.split(".").pop() || "—";
  const securityScore = report.security_score ?? report.average_cvss ?? report.metadata?.security_score ?? "—";

  // Extract findings - MobSF can have these in different places depending on version/type
  const codeFindings = report.code_analysis || report.static_analysis || {};
  const manifestFindings = report.manifest_analysis || report.manifest_findings || [];
  const permissions = report.permissions || report.metadata?.permissions || {};

  // Count severities from code analysis
  const severityCounts: Record<string, number> = { high: 0, warning: 0, info: 0, secure: 0 };

  // Normalized findings list for display
  const findingsList: any[] = [];

  const processFinding = (finding: any, source: string) => {
    const sev = (finding.severity || finding.level || finding.metadata?.severity || "info").toLowerCase();
    if (sev in severityCounts) severityCounts[sev]++;
    else if (sev === "critical" || sev === "high") severityCounts.high++;
    else if (sev === "medium" || sev === "warning") severityCounts.warning++;
    else severityCounts.info++;

    findingsList.push({
      ...finding,
      display_severity: sev,
      source
    });
  };

  if (typeof codeFindings === "object") {
    Object.values(codeFindings).forEach((finding: any) => processFinding(finding, "Static Analysis"));
  }

  // Handle other possible MobSF locations - be more aggressive
  ["high", "warning", "info", "secure", "critical", "medium"].forEach(s => {
    const findings = report[`${s}_vulnerabilities`] || report[`${s}_findings`] || report[s];
    if (Array.isArray(findings)) {
      findings.forEach(f => {
        if (typeof f === "object") processFinding({ ...f, severity: s }, "Vulnerability Scan");
      });
    }
  });

  // Check for specific MobSF sections like 'browsable_activities', 'activities', etc if needed
  if (Array.isArray(report.browsable_activities)) {
    report.browsable_activities.forEach((f: any) => processFinding({ ...f, severity: "info", title: "Browsable Activity" }, "Manifest"));
  }

  // Manifest findings
  if (Array.isArray(manifestFindings)) {
    manifestFindings.forEach((f: any) => {
      const sev = (f.severity || "info").toLowerCase();
      if (sev in severityCounts) severityCounts[sev]++;
      else severityCounts.info++;
    });
  }

  const severityData = Object.entries(severityCounts)
    .map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      count: value,
      color: SEVERITY_COLORS[name] || "#6B7280",
    }))
    .filter((d) => d.count > 0);

  const totalFindings = Object.values(severityCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <PageHeader title={appName} description={`${packageName} — Mobile Security Analysis`} />
        <Button onClick={handleDownloadPdf} disabled={pdfLoading} className="gap-2">
          {pdfLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
          Download PDF
        </Button>
      </div>

      {/* Info Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {[
          { label: "Package", value: packageName },
          { label: "Version", value: version },
          { label: "Type", value: scanType.toUpperCase() },
          { label: "Findings", value: String(totalFindings) },
          { label: "Security Score", value: String(securityScore) },
        ].map((info) => (
          <div key={info.label} className="cyber-card p-4">
            <p className="text-xs text-muted-foreground/60 font-bold uppercase tracking-wider">{info.label}</p>
            <p className="text-sm font-semibold text-foreground mt-1 mono truncate">{info.value}</p>
          </div>
        ))}
      </div>

      {/* Scorecard */}
      {scorecard && (
        <div className="cyber-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Security Scorecard</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {Object.entries(scorecard).slice(0, 8).map(([key, val]: [string, any]) => (
              <div key={key} className="text-center group">
                <p className="text-[10px] text-muted-foreground/60 uppercase font-bold tracking-widest group-hover:text-primary/70 transition-colors">{key.replace(/_/g, " ")}</p>
                <p className="text-lg font-bold text-foreground mono mt-1">
                  {Array.isArray(val) ? val.length : (typeof val === 'object' ? (val.count ?? val.value ?? Object.keys(val).length) : String(val))}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Finding Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="count" strokeWidth={0}>
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px", color: "hsl(var(--foreground))" }}
                  itemStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '10px', paddingTop: '10px', color: 'hsl(var(--muted-foreground))' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-center py-8 text-sm">No findings</p>
          )}
        </div>

        <div className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">By Severity</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                <XAxis dataKey="name" stroke="currentColor" fontSize={11} tick={{ fill: 'hsl(var(--muted-foreground))' }} />
                <YAxis stroke="currentColor" fontSize={11} tick={{ fill: 'hsl(var(--muted-foreground))' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }}
                  itemStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Legend iconType="rect" wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }} />
                <Bar name="Finding Count" dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-center py-8 text-sm">No data</p>
          )}
        </div>
      </div>

      {/* Permissions */}
      {Object.keys(permissions).length > 0 && (
        <div className="cyber-card overflow-hidden">
          <div className="p-5 border-b border-border">
            <h3 className="text-sm font-semibold text-foreground">Permissions ({Object.keys(permissions).length})</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Permission", "Status", "Description"].map((h) => (
                    <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(permissions).slice(0, 30).map(([perm, details]: [string, any]) => (
                  <tr key={perm} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 mono text-xs text-foreground">{perm}</td>
                    <td className="p-3">
                      <SeverityBadge severity={details?.status || details?.severity || "info"} />
                    </td>
                    <td className="p-3 text-muted-foreground text-xs max-w-md truncate">
                      {details?.description || details?.info || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Code Analysis Findings */}
      {typeof codeFindings === "object" && Object.keys(codeFindings).length > 0 && (
        <div className="cyber-card overflow-hidden">
          <div className="p-5 border-b border-border">
            <h3 className="text-sm font-semibold text-foreground">Code Analysis ({Object.keys(codeFindings).length})</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Finding", "Severity", "File", "Line", "Description"].map((h) => (
                    <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findingsList.map((f: any, i: number) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 font-medium text-foreground">{f.title || f.metadata?.title || f.rule || `Finding ${i + 1}`}</td>
                    <td className="p-3"><SeverityBadge severity={(f.display_severity || "info")} /></td>
                    <td className="p-3 mono text-xs text-primary truncate max-w-[200px]" title={f.file_path || f.file || "—"}>
                      {(f.file_path || f.file || "—").split("/").pop()}
                    </td>
                    <td className="p-3 mono text-xs text-muted-foreground">{f.line_number || f.line || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs max-w-xs">{f.metadata?.description || f.description || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Manifest Findings */}
      {Array.isArray(manifestFindings) && manifestFindings.length > 0 && (
        <div className="cyber-card overflow-hidden">
          <div className="p-5 border-b border-border">
            <h3 className="text-sm font-semibold text-foreground">Manifest Analysis ({manifestFindings.length})</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Finding", "Severity", "Description"].map((h) => (
                    <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {manifestFindings.map((f: any, i: number) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 font-medium text-foreground">{f.title || f.rule || `Finding ${i + 1}`}</td>
                    <td className="p-3"><SeverityBadge severity={f.severity || "info"} /></td>
                    <td className="p-3 text-muted-foreground text-xs max-w-md">{f.description || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default MobileScanDetails;
