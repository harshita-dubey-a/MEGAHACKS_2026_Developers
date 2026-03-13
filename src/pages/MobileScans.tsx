import { useEffect, useState } from "react";
import { RefreshCw, Eye, Download, Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/CyberComponents";
import { mobsfGetScans, mobsfDownloadPdf, mobsfDeleteScan, type MobSFScanItem } from "@/lib/mobsf-api";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

const MobileScans = () => {
  const [scans, setScans] = useState<MobSFScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await mobsfGetScans(1, 50);
      setScans(data.content);
    } catch (e: any) {
      toast.error("Failed to load mobile scans", { description: e.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadScans(); }, []);

  const handleDownloadPdf = async (hash: string, fileName: string) => {
    setDownloading(hash);
    try {
      const blob = await mobsfDownloadPdf(hash);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${fileName.replace(/\.[^.]+$/, "")}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("PDF downloaded");
    } catch (e: any) {
      toast.error("PDF download failed", { description: e.message });
    } finally {
      setDownloading(null);
    }
  };

  const handleDelete = async (hash: string) => {
    try {
      await mobsfDeleteScan(hash);
      toast.success("Scan deleted");
      loadScans();
    } catch (e: any) {
      toast.error("Delete failed", { description: e.message });
    }
  };

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <PageHeader title="Mobile Scans" description="Recent mobile application scan results" />
        <Button variant="outline" size="sm" onClick={loadScans} disabled={loading} className="gap-2">
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} /> Refresh
        </Button>
      </div>

      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["App Name", "Package", "File", "Type", "Version", "Date", "Actions"].map((h) => (
                  <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && scans.length === 0 ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    <td className="p-3" colSpan={7}><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : scans.length === 0 ? (
                <tr><td colSpan={7} className="p-8 text-center text-muted-foreground">No mobile scans found. Upload an app to start.</td></tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.MD5} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="p-3 font-medium text-foreground">{scan.APP_NAME || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs mono">{scan.PACKAGE_NAME || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs truncate max-w-[200px]">{scan.FILE_NAME}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-primary/10 text-primary uppercase">
                        {scan.SCAN_TYPE}
                      </span>
                    </td>
                    <td className="p-3 text-muted-foreground text-xs">{scan.VERSION_NAME || "—"}</td>
                    <td className="p-3 text-muted-foreground text-xs">
                      {scan.TIMESTAMP ? new Date(scan.TIMESTAMP).toLocaleDateString() : "—"}
                    </td>
                    <td className="p-3">
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" asChild className="h-7 text-xs gap-1">
                          <Link to={`/mobile-scan-details/${scan.MD5}`}><Eye className="w-3 h-3" /> View</Link>
                        </Button>
                        <Button
                          variant="ghost" size="sm"
                          className="h-7 text-xs gap-1"
                          disabled={downloading === scan.MD5}
                          onClick={() => handleDownloadPdf(scan.MD5, scan.FILE_NAME)}
                        >
                          {downloading === scan.MD5 ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                          PDF
                        </Button>
                        <Button
                          variant="ghost" size="sm"
                          className="h-7 text-xs gap-1 text-destructive hover:text-destructive"
                          onClick={() => handleDelete(scan.MD5)}
                        >
                          <Trash2 className="w-3 h-3" />
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

export default MobileScans;
