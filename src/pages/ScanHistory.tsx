import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Eye, Download, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader, StatusBadge, severityCountsToArray, VulnIndicators } from "@/components/CyberComponents";
import { getScans, generateReport, getReport, downloadReport, type ScanItemResponse, REPORT_TEMPLATES } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";

const ScanHistory = () => {
  const [scans, setScans] = useState<ScanItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    getScans(100)
      .then((data) => setScans(data.scans))
      .catch((e) => toast.error("Failed to load scan history", { description: e.message }))
      .finally(() => setLoading(false));
  }, []);

  const handleDownloadPdf = async (scan: ScanItemResponse) => {
    setDownloading(scan.scan_id);
    try {
      // Generate report via the scanner API
      const report = await generateReport({
        template_id: REPORT_TEMPLATES.DEVELOPER,
        source: {
          list_type: "scans",
          id_list: [scan.scan_id],
        },
      });

      // Poll until report is ready
      let reportData = report;
      let attempts = 0;
      while (reportData.status !== "completed" && reportData.status !== "failed" && attempts < 30) {
        await new Promise((r) => setTimeout(r, 2000));
        reportData = await getReport(reportData.report_id);
        attempts++;
      }

      if (reportData.status === "failed") throw new Error("Report generation failed");
      if (reportData.status !== "completed") throw new Error("Report generation timed out");

      // Download the report file
      if (reportData.download && reportData.download.length > 0) {
        const descriptor = reportData.download[0];
        // Extract just the descriptor from URL if it's a full URL
        const descPart = descriptor.includes("/") ? descriptor.split("/").pop()! : descriptor;
        const blob = await downloadReport(descPart);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `report_${scan.scan_id.slice(0, 8)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Report downloaded");
      } else {
        throw new Error("No download link available");
      }
    } catch (e: any) {
      toast.error("Failed to generate report", { description: e.message });
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title="Scan History" description="View all previous scan records" />

      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Target", "Profile", "Status", "Vulnerabilities", "Actions"].map((h) => (
                  <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    <td className="p-3" colSpan={5}><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : scans.length === 0 ? (
                <tr><td colSpan={5} className="p-8 text-center text-muted-foreground">No scan history found</td></tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.scan_id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 font-medium text-foreground">{scan.target?.address || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs">{scan.profile_name || "—"}</td>
                    <td className="p-3"><StatusBadge status={scan.current_session?.status || "scheduled"} /></td>
                    <td className="p-3">
                      <VulnIndicators counts={severityCountsToArray(scan.current_session?.severity_counts)} />
                    </td>
                    <td className="p-3">
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" asChild className="h-8 text-xs gap-1">
                          <Link to={`/scan-details/${scan.scan_id}`}><Eye className="w-3 h-3" /> View</Link>
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 text-xs gap-1"
                          disabled={downloading === scan.scan_id}
                          onClick={() => handleDownloadPdf(scan)}
                        >
                          {downloading === scan.scan_id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />} PDF
                        </Button>
                      </div>
                    </td>
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

export default ScanHistory;
