import { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import type { ScanStatus } from "@/lib/api";
import { severityToString } from "@/lib/api";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  change?: string;
  changeType?: "positive" | "negative" | "neutral";
}

export function StatCard({ title, value, icon: Icon, change, changeType = "neutral" }: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground font-medium">{title}</p>
          <p className="text-3xl font-bold text-foreground mt-1 mono">{value}</p>
          {change && (
            <p className={cn(
              "text-xs mt-2 font-medium",
              changeType === "positive" && "text-severity-low",
              changeType === "negative" && "text-severity-critical",
              changeType === "neutral" && "text-muted-foreground"
            )}>
              {change}
            </p>
          )}
        </div>
        <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
          <Icon className="w-5 h-5 text-primary" />
        </div>
      </div>
    </div>
  );
}

interface SeverityBadgeProps {
  severity: string | number;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const sev = typeof severity === "number" ? severityToString(severity) : severity;
  const styles: Record<string, string> = {
    critical: "severity-critical",
    high: "severity-high",
    medium: "severity-medium",
    low: "severity-low",
    info: "bg-muted text-muted-foreground",
  };
  return (
    <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-semibold capitalize", styles[sev] || styles.info)}>
      {sev}
    </span>
  );
}

interface StatusBadgeProps {
  status: ScanStatus | string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const styles: Record<string, string> = {
    scheduled: "bg-muted text-muted-foreground",
    queued: "bg-muted text-muted-foreground",
    starting: "status-running",
    processing: "status-running",
    aborting: "status-failed",
    aborted: "status-failed",
    pausing: "bg-muted text-muted-foreground",
    paused: "bg-muted text-muted-foreground",
    completed: "status-completed",
    failed: "status-failed",
  };
  return (
    <span className={cn("px-2.5 py-1 rounded-full text-xs font-semibold capitalize", styles[status] || "bg-muted text-muted-foreground")}>
      {status}
    </span>
  );
}

interface VulnIndicatorsProps {
  counts: number[];
}

export function VulnIndicators({ counts }: VulnIndicatorsProps) {
  const colors = ["#7F1D1D", "#B91C1C", "#EF4444", "#F87171", "#FCA5A5"];
  const labels = ["C", "H", "M", "L", "I"];
  return (
    <div className="flex gap-1.5">
      {counts.map((count, i) => (
        <div
          key={i}
          className="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold"
          style={{ backgroundColor: colors[i], color: i >= 3 ? "#000" : "#fff" }}
          title={`${labels[i]}: ${count}`}
        >
          {count}
        </div>
      ))}
    </div>
  );
}

/** Convert SeverityCounts to [critical, high, medium, low, info] array */
export function severityCountsToArray(counts?: { critical?: number; high?: number; medium?: number; low?: number; info?: number }): number[] {
  if (!counts) return [0, 0, 0, 0, 0];
  return [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, counts.info || 0];
}

interface PageHeaderProps {
  title: string;
  description?: string;
  children?: ReactNode;
}

export function PageHeader({ title, description, children }: PageHeaderProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">{title}</h1>
        {description && <p className="text-sm text-muted-foreground mt-1">{description}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}
