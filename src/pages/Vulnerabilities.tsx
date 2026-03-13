import { useState, useEffect, useRef } from "react";
import {
  Search, Sparkles, X, Loader2, Shield,
  ExternalLink, AlertTriangle, Lightbulb, Zap
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem,
  SelectTrigger, SelectValue
} from "@/components/ui/select";
import { PageHeader, SeverityBadge } from "@/components/CyberComponents";
import { useToast } from "@/hooks/use-toast";
import { Skeleton } from "@/components/ui/skeleton";
import {
  getVulnerabilities, severityToString, getVulnerabilityDetails,
  type Vulnerability, type VulnerabilityDetails
} from "@/lib/api";
import ReactMarkdown from "react-markdown";
import { cn } from "@/lib/utils";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const ANALYZE_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/analyze-vulnerabilities`;

const Vulnerabilities = () => {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [vulnDetails, setVulnDetails] = useState<VulnerabilityDetails | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showPanel, setShowPanel] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    getVulnerabilities(100)
      .then((data) => setVulns(data.vulnerabilities))
      .catch((e) => toast({ title: "Error", description: e.message, variant: "destructive" }))
      .finally(() => setLoading(false));
  }, []);

  const filtered = vulns.filter((v) => {
    const sev = severityToString(v.severity);
    const matchSearch =
      v.vt_name.toLowerCase().includes(search.toLowerCase()) ||
      (v.affects_url || "").toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === "all" || sev === severityFilter;
    const matchSource = sourceFilter === "all" || (v.source || "Web").toLowerCase() === sourceFilter.toLowerCase();
    return matchSearch && matchSeverity && matchSource;
  });

  const handleRowClick = async (v: Vulnerability) => {
    setSelectedVuln(v);
    setVulnDetails(null);
    setDetailsLoading(true);
    try {
      // Local vulnerabilities won't have remote details, we'll use the basic data or AI
      if (v.vuln_id.startsWith("local-")) {
        setVulnDetails({
          ...v,
          description: "Local vulnerability discovered during scan. Use 'Enrich with AI' for detailed analysis.",
          impact: "Pending analysis.",
          recommendation: "Pending analysis."
        } as VulnerabilityDetails);
      } else {
        const details = await getVulnerabilityDetails(v.vuln_id);
        setVulnDetails(details);
      }
    } catch (e) {
      console.warn("Failed to fetch details", e);
      // Fallback to basic info
      setVulnDetails({ ...v } as VulnerabilityDetails);
    } finally {
      setDetailsLoading(false);
    }
  };

  const handleEnrich = async (v: Vulnerability) => {
    if (!v) return;
    setIsAnalyzing(true);
    setAiAnalysis("");
    try {
      const resp = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({
          vulnerabilities: [{
            name: v.vt_name,
            severity: severityToString(v.severity),
            target: v.affects_url || "unknown",
            source: v.source,
            detail: v.affects_detail || ""
          }],
          deep_analysis: true
        }),
      });

      if (!resp.ok) throw new Error("Analysis failed");

      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let content = "";

      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6).trim();
            if (data === "[DONE]") break;
            try {
              const parsed = JSON.parse(data);
              const delta = parsed.choices?.[0]?.delta?.content;
              if (delta) {
                content += delta;
                setAiAnalysis(content);
              }
            } catch { }
          }
        }
      }

      setVulnDetails(prev => prev ? {
        ...prev,
        long_description: content
      } : null);

    } catch (e: any) {
      toast({ title: "Enrichment failed", description: e.message, variant: "destructive" });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyze = async () => {
    setShowPanel(true);
    setAiAnalysis("");
    setIsAnalyzing(true);
    abortRef.current = new AbortController();

    try {
      const resp = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({
          vulnerabilities: filtered.map((v) => ({
            name: v.vt_name,
            severity: severityToString(v.severity),
            target: v.affects_url || "unknown",
            confidence: v.confidence,
          })),
        }),
        signal: abortRef.current.signal,
      });

      if (!resp.ok || !resp.body) {
        const err = await resp.json().catch(() => ({ error: "Analysis failed" }));
        toast({ title: "Analysis Error", description: err.error, variant: "destructive" });
        setIsAnalyzing(false);
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let content = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let idx: number;
        while ((idx = buffer.indexOf("\n")) !== -1) {
          let line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          if (line.endsWith("\r")) line = line.slice(0, -1);
          if (!line.startsWith("data: ")) continue;
          const json = line.slice(6).trim();
          if (json === "[DONE]") break;
          try {
            const parsed = JSON.parse(json);
            const delta = parsed.choices?.[0]?.delta?.content;
            if (delta) { content += delta; setAiAnalysis(content); }
          } catch {
            buffer = line + "\n" + buffer;
            break;
          }
        }
      }
    } catch (e: any) {
      if (e.name !== "AbortError") {
        toast({ title: "Error", description: "Failed to analyze", variant: "destructive" });
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleClosePanel = () => {
    abortRef.current?.abort();
    setShowPanel(false);
    setAiAnalysis("");
    setIsAnalyzing(false);
  };

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <PageHeader title="Vulnerabilities" description="All discovered vulnerabilities across scans" />
        <Button onClick={handleAnalyze} disabled={isAnalyzing} className="gap-2 bg-primary hover:bg-primary/90">
          {isAnalyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          Security Analysis
        </Button>
      </div>

      {showPanel && (
        <div className="cyber-card border border-primary/30 bg-primary/5 relative">
          <button onClick={handleClosePanel} className="absolute top-3 right-3 p-1 rounded-md hover:bg-muted/50 text-muted-foreground">
            <X className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-primary" />
            <h3 className="font-semibold text-foreground">Cloud Security Analysis</h3>
          </div>
          {isAnalyzing && !aiAnalysis && (
            <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
              <Loader2 className="w-4 h-4 animate-spin" /> Analyzing {filtered.length} vulnerabilities...
            </div>
          )}
          {aiAnalysis && (
            <div className="prose prose-sm dark:prose-invert max-w-none text-foreground/90">
              <ReactMarkdown>{aiAnalysis}</ReactMarkdown>
            </div>
          )}
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search vulnerabilities..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9 bg-muted/50 border-border h-10" />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-full sm:w-44 bg-muted/50 border-border h-10">
            <SelectValue placeholder="Filter by severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select value={sourceFilter} onValueChange={setSourceFilter}>
          <SelectTrigger className="w-full sm:w-44 bg-muted/50 border-border h-10">
            <SelectValue placeholder="Filter by source" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sources</SelectItem>
            <SelectItem value="Web">Web</SelectItem>
            <SelectItem value="Mobile">Mobile</SelectItem>
            <SelectItem value="Network">Network</SelectItem>
            <SelectItem value="AI Security">AI Security</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["#", "Source", "Name", "URL", "Severity", "Status", "Confidence"].map((h) => (
                  <th key={h} className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50"><td className="p-3" colSpan={7}><Skeleton className="h-6 w-full" /></td></tr>
                ))
              ) : filtered.length === 0 ? (
                <tr><td colSpan={7} className="p-8 text-center text-muted-foreground">No vulnerabilities match your filters.</td></tr>
              ) : (
                filtered.map((v, i) => (
                  <tr
                    key={v.vuln_id || i}
                    className="border-b border-border/50 hover:bg-muted/20 transition-colors cursor-pointer group"
                    onClick={() => handleRowClick(v)}
                  >
                    <td className="p-3 mono text-muted-foreground group-hover:text-primary transition-colors">{i + 1}</td>
                    <td className="p-3 text-xs">
                      <span className={cn(
                        "px-2 py-0.5 rounded-full font-semibold border",
                        v.source === "Mobile" ? "bg-accent/10 border-accent/20 text-accent" :
                          v.source === "Network" ? "bg-severity-low/10 border-severity-low/20 text-severity-low" :
                            v.source === "AI Security" ? "bg-primary/10 border-primary/20 text-primary" :
                              "bg-muted/10 border-muted/20 text-muted-foreground"
                      )}>
                        {v.source || "Web"}
                      </span>
                    </td>
                    <td className="p-3 font-medium text-foreground group-hover:text-primary transition-colors">{v.vt_name}</td>
                    <td className="p-3 mono text-primary text-xs max-w-xs truncate">{v.affects_url || "—"}</td>
                    <td className="p-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="p-3 text-muted-foreground capitalize text-xs">{v.status}</td>
                    <td className="p-3 mono text-xs font-semibold">{v.confidence ?? "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <Sheet open={!!selectedVuln} onOpenChange={(open) => !open && setSelectedVuln(null)}>
        <SheetContent className="w-full sm:max-w-xl border-l border-border bg-card overflow-y-auto cyber-scrollbar">
          {selectedVuln && (
            <div className="space-y-6 pt-4">
              <SheetHeader>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-bold">{selectedVuln.source} FINDING</span>
                  <div className="h-px flex-1 bg-border" />
                </div>
                <SheetTitle className="text-xl font-bold text-foreground leading-tight">
                  {selectedVuln.vt_name}
                </SheetTitle>
                <div className="flex flex-wrap gap-2 items-center mt-2">
                  <SeverityBadge severity={selectedVuln.severity} />
                  <Badge variant="outline" className="text-[10px] font-mono">ID: {selectedVuln.vt_id || selectedVuln.vuln_id.slice(0, 8)}</Badge>
                  {selectedVuln.confidence && <Badge variant="secondary" className="text-[10px]">Confidence: {selectedVuln.confidence}%</Badge>}
                </div>
              </SheetHeader>

              <div className="space-y-4">
                <div className="cyber-card p-4 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase">
                    <ExternalLink className="w-3 h-3" /> Target Info
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-foreground break-all">{selectedVuln.affects_url}</p>
                    {selectedVuln.affects_detail && (
                      <p className="text-xs text-muted-foreground font-mono bg-muted/30 p-2 rounded">{selectedVuln.affects_detail}</p>
                    )}
                  </div>
                </div>

                {detailsLoading ? (
                  <div className="space-y-4 py-4">
                    <Skeleton className="h-20 w-full" />
                    <Skeleton className="h-32 w-full" />
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : (
                  <>
                    <div className="space-y-4">
                      {vulnDetails?.description && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-warning" /> Description
                          </h4>
                          <div className="text-sm text-foreground/80 leading-relaxed bg-muted/10 p-4 rounded-lg border border-border/50">
                            {vulnDetails.description}
                          </div>
                        </div>
                      )}

                      {vulnDetails?.impact && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                            <Zap className="w-4 h-4 text-destructive" /> Business Impact
                          </h4>
                          <div className="text-sm text-foreground/80 leading-relaxed bg-destructive/5 p-4 rounded-lg border border-destructive/10">
                            {vulnDetails.impact}
                          </div>
                        </div>
                      )}

                      {vulnDetails?.recommendation && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-bold text-foreground flex items-center gap-2">
                            <Lightbulb className="w-4 h-4 text-primary" /> Remediation Recommendation
                          </h4>
                          <div className="text-sm text-foreground/80 leading-relaxed bg-primary/5 p-4 rounded-lg border border-primary/10">
                            {vulnDetails.recommendation}
                          </div>
                        </div>
                      )}

                      {vulnDetails?.cvss_score && (
                        <div className="flex items-center justify-between p-4 bg-muted/20 rounded-lg border border-border">
                          <span className="text-sm font-semibold">CVSS Score</span>
                          <span className="text-lg font-bold mono text-destructive">{vulnDetails.cvss_score}</span>
                        </div>
                      )}
                    </div>

                    {!vulnDetails?.long_description && !aiAnalysis && (
                      <Button
                        onClick={() => handleEnrich(selectedVuln)}
                        disabled={isAnalyzing}
                        className="w-full gap-2 bg-gradient-to-r from-primary to-accent hover:opacity-90 transition-opacity"
                      >
                        {isAnalyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                        Enrich with AI Analysis
                      </Button>
                    )}

                    {(aiAnalysis || vulnDetails?.long_description) && (
                      <div className="mt-8 space-y-4 border-t border-border pt-6">
                        <h4 className="text-sm font-bold text-primary flex items-center gap-2">
                          <Sparkles className="w-4 h-4" /> AI Security Insights
                        </h4>
                        <div className="prose prose-sm dark:prose-invert max-w-none text-foreground/90 bg-primary/5 p-5 rounded-xl border border-primary/20">
                          <ReactMarkdown>{aiAnalysis || vulnDetails?.long_description || ""}</ReactMarkdown>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
};

export default Vulnerabilities;
