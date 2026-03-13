import { useState, useEffect } from "react";
import { Download, FileText, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/CyberComponents";
import { toast } from "sonner";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  getScans, generateReport, getReport, downloadReport,
  type ScanItemResponse, REPORT_TEMPLATES,
} from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

const reportTemplates = [
  { id: REPORT_TEMPLATES.DEVELOPER, label: "Developer Report" },
  { id: REPORT_TEMPLATES.EXECUTIVE_SUMMARY, label: "Executive Summary" },
  { id: REPORT_TEMPLATES.QUICK, label: "Quick Report" },
  { id: REPORT_TEMPLATES.AFFECTED_ITEMS, label: "Affected Items" },
  { id: REPORT_TEMPLATES.OWASP_TOP_10_2017, label: "OWASP Top 10 2017" },
  { id: REPORT_TEMPLATES.PCI_DSS_32, label: "PCI DSS 3.2" },
  { id: REPORT_TEMPLATES.HIPAA, label: "HIPAA" },
  { id: REPORT_TEMPLATES.ISO_27001, label: "ISO 27001" },
  { id: REPORT_TEMPLATES.CWE_2011, label: "CWE 2011" },
  { id: REPORT_TEMPLATES.NIST_SP800_53, label: "NIST SP800 53" },
  { id: REPORT_TEMPLATES.SARBANES_OXLEY, label: "Sarbanes Oxley" },
  { id: REPORT_TEMPLATES.STIG_DISA, label: "STIG DISA" },
  { id: REPORT_TEMPLATES.WASC_THREAT, label: "WASC Threat Classification" },
];

const Reports = () => {
  const [selectedTemplate, setSelectedTemplate] = useState(REPORT_TEMPLATES.DEVELOPER);
  const [scans, setScans] = useState<ScanItemResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    getScans(100)
      .then((data) => {
        // Filter for completed scans with meaningful IDs or local scans
        setScans(data.scans.filter((s) =>
          (s.current_session?.status === "completed" || s.scan_id.startsWith("local-")) &&
          s.scan_id &&
          s.scan_id.length > 8
        ));
      })
      .catch((e) => toast.error("Failed to load scans", { description: e.message }))
      .finally(() => setLoading(false));
  }, []);

  const handleDownload = async (scan: ScanItemResponse) => {
    const isAcunetix = /^[0-9a-f-]{36}$/i.test(scan.scan_id);
    const key = `${scan.scan_id}-${selectedTemplate}`;

    if (!isAcunetix) {
      // Local Report Generation
      try {
        setDownloading(key);
        const doc = new jsPDF();

        // Load local vulnerabilities to include in report
        const LOCAL_VULNS_KEY = "local_vulnerabilities";
        const allVulns = JSON.parse(localStorage.getItem(LOCAL_VULNS_KEY) || "[]");
        const scanVulns = allVulns.filter((v: any) =>
          v.affects_url && (
            v.affects_url.includes(scan.target?.address || "") ||
            v.target_description === scan.profile_name ||
            (scan.scan_id.startsWith("local-") && v.source === "Network") // Fallback for local network scans
          )
        );

        // Header - Dark Theme Inspired
        doc.setFillColor(10, 10, 12);
        doc.rect(0, 0, 210, 45, "F");

        doc.setTextColor(59, 130, 246); // Primary Blue
        doc.setFont("helvetica", "bold");
        doc.setFontSize(26);
        doc.text("SECURITY SENTINEL", 15, 25);

        doc.setTextColor(150, 150, 150);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.text("ADVANCED CYBERSECURITY DASHBOARD • INFRASTRUCTURE REPORT", 15, 35);

        doc.setTextColor(255, 255, 255);
        doc.text(new Date().toLocaleDateString(), 180, 25);

        // Scan Summary Section
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(16);
        doc.text("Assessment Overview", 15, 60);

        doc.setDrawColor(200, 200, 200);
        doc.line(15, 63, 195, 63);

        autoTable(doc, {
          startY: 68,
          head: [["Target Asset", "Scan Profile", "Status", "Completion Date"]],
          body: [[
            scan.target?.address || "Unknown Asset",
            scan.profile_name || "Custom Scan",
            "COMPLETED",
            new Date(scan.current_session?.start_date || Date.now()).toLocaleString()
          ]],
          styles: { fontSize: 10, cellPadding: 5 },
          headStyles: { fillColor: [59, 130, 246], textColor: [255, 255, 255] }
        });

        // Vulnerability Distribution
        doc.setFontSize(16);
        doc.text("Vulnerability Metrics", 15, (doc as any).lastAutoTable.finalY + 15);

        const counts = scan.current_session?.severity_counts;
        autoTable(doc, {
          startY: (doc as any).lastAutoTable.finalY + 20,
          head: [["Critical", "High", "Medium", "Low", "Informational"]],
          body: [[
            counts?.critical || 0,
            counts?.high || 0,
            counts?.medium || 0,
            counts?.low || 0,
            counts?.info || 0
          ]],
          headStyles: { fillColor: [30, 30, 35] },
          bodyStyles: { fontStyle: "bold", halign: "center" }
        });

        // Specific Findings if available
        if (scanVulns.length > 0) {
          doc.addPage();
          doc.setFontSize(18);
          doc.text("Detailed Findings", 15, 20);
          doc.setDrawColor(59, 130, 246);
          doc.line(15, 23, 195, 23);

          autoTable(doc, {
            startY: 28,
            head: [["Vulnerability Name", "Severity", "Impacted Resource"]],
            body: scanVulns.map((v: any) => [
              v.vt_name,
              v.severity >= 3 ? "HIGH" : v.severity >= 2 ? "MEDIUM" : v.severity >= 1 ? "LOW" : "INFO",
              v.affects_url || "N/A"
            ]),
            styles: { fontSize: 9 },
            columnStyles: {
              1: { cellWidth: 30, halign: "center" }
            },
            headStyles: { fillColor: [30, 30, 35] }
          });
        }

        doc.save(`SecurityReport_${scan.target?.address?.replace(/[^a-z0-9]/gi, "_") || "scan"}.pdf`);
        toast.success("Professional report generated");
      } catch (e) {
        console.error("PDF Export error", e);
        toast.error("Failed to generate PDF report");
      } finally {
        setDownloading(null);
      }
      return;
    }

    setDownloading(key);
    try {
      // Generate report via scanner API
      const report = await generateReport({
        template_id: selectedTemplate,
        source: {
          list_type: "scans",
          id_list: [scan.scan_id],
        },
      });

      // Poll until report is ready
      let reportData = report;
      let attempts = 0;
      while (reportData.status !== "completed" && reportData.status !== "failed" && attempts < 60) {
        await new Promise((r) => setTimeout(r, 2000));
        reportData = await getReport(reportData.report_id);
        attempts++;
      }

      if (reportData.status === "failed") throw new Error("Report generation failed");
      if (reportData.status !== "completed") throw new Error("Report generation timed out");

      // Download the actual PDF file
      if (reportData.download && reportData.download.length > 0) {
        const descriptor = reportData.download[0];
        const descPart = descriptor.includes("/") ? descriptor.split("/").pop()! : descriptor;
        const blob = await downloadReport(descPart);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const templateLabel = reportTemplates.find((t) => t.id === selectedTemplate)?.label || "Report";
        a.download = `${templateLabel.replace(/\s+/g, "_")}_${scan.scan_id.slice(0, 8)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Report downloaded", { description: `${templateLabel} generated successfully` });
      } else {
        throw new Error("No download link available in report");
      }
    } catch (e: any) {
      toast.error("Report generation failed", { description: e.message });
    } finally {
      setDownloading(null);
    }
  };

  const selectedLabel = reportTemplates.find((t) => t.id === selectedTemplate)?.label || "Report";

  return (
    <div className="space-y-6 animate-in">
      <PageHeader title="Reports" description="Generate and download vulnerability assessment reports (PDF)" />

      <div className="flex items-center gap-3">
        <FileText className="w-4 h-4 text-muted-foreground" />
        <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
          <SelectTrigger className="w-[280px]">
            <SelectValue placeholder="Select report template" />
          </SelectTrigger>
          <SelectContent>
            {reportTemplates.map((t) => (
              <SelectItem key={t.id} value={t.id}>{t.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Target", "Profile", "Report Template", "Download"].map((h) => (
                  <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50"><td className="p-3" colSpan={4}><Skeleton className="h-6 w-full" /></td></tr>
                ))
              ) : scans.length === 0 ? (
                <tr><td colSpan={4} className="p-8 text-center text-muted-foreground">No completed scans available for reports.</td></tr>
              ) : (
                scans.map((scan) => {
                  const isAcunetix = /^[0-9a-f-]{36}$/i.test(scan.scan_id);
                  const key = `${scan.scan_id}-${selectedTemplate}`;
                  return (
                    <tr key={scan.scan_id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                      <td className="p-3 font-medium text-foreground">
                        <div className="flex flex-col">
                          <span>{scan.target?.address || scan.profile_name || "Unknown Asset"}</span>
                          {!isAcunetix && <span className="text-[10px] text-primary/70 font-bold uppercase tracking-wider">(Local System Report)</span>}
                        </div>
                      </td>
                      <td className="p-3 text-muted-foreground text-xs">{scan.profile_name || "—"}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <FileText className="w-4 h-4" />
                          <span>{selectedLabel}</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <Button
                          variant="ghost"
                          size="sm"
                          className={cn(
                            "h-8 text-xs gap-1.5 transition-all",
                            "text-primary hover:text-primary"
                          )}
                          disabled={downloading === key}
                          onClick={() => handleDownload(scan)}
                        >
                          {downloading === key ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                          {downloading === key ? "Generating..." : "Download PDF"}
                        </Button>
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

export default Reports;
