import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Target,
  Scan,
  History,
  Bug,
  FileText,
  Settings,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
  Smartphone,
  Upload,
  Network,
  Cpu,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";

const navItems = [
  { title: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
  { title: "Input Target", path: "/input-target", icon: Target, section: "Web Scanning" },
  { title: "Scanning", path: "/scanning", icon: Scan },
  { title: "Scan History", path: "/scan-history", icon: History },
  { title: "Mobile Scan", path: "/mobile-scan", icon: Upload, section: "Mobile Scanning" },
  { title: "Mobile Scans", path: "/mobile-scans", icon: Smartphone },
  { title: "Network Scan", path: "/network-scan", icon: Network, section: "Network Scanning" },
  { title: "Model Vulnerability Scan", path: "/garak-scan", icon: Cpu, section: "Model Security" },
  { title: "Vulnerabilities", path: "/vulnerabilities", icon: Bug, section: "Analysis" },
  { title: "Reports", path: "/reports", icon: FileText },
  { title: "Settings", path: "/settings", icon: Settings },
];

export function AppSidebar() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  let lastSection = "";

  return (
    <aside
      className={cn(
        "h-screen sticky top-0 flex flex-col border-r border-border bg-card transition-all duration-300 z-30",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center flex-shrink-0">
          <Shield className="w-5 h-5 text-primary-foreground" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <h1 className="text-sm font-bold text-foreground leading-tight truncate">Security Sentinel</h1>
            <p className="text-[10px] text-muted-foreground truncate">Advanced Security Dashboard</p>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-2 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          const showSection = item.section && item.section !== lastSection;
          if (item.section) lastSection = item.section;

          return (
            <div key={item.path}>
              {showSection && !collapsed && (
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-3 pt-4 pb-1">
                  {item.section}
                </p>
              )}
              {showSection && collapsed && <div className="border-t border-border/50 my-2 mx-2" />}
              <Link
                to={item.path}
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150",
                  isActive
                    ? "bg-primary/10 text-primary cyber-glow"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                <item.icon className={cn("w-5 h-5 flex-shrink-0", isActive && "text-primary")} />
                {!collapsed && <span className="truncate">{item.title}</span>}
              </Link>
            </div>
          );
        })}
      </nav>

      {/* Bottom */}
      <div className="px-2 py-4 border-t border-border space-y-1">
        <Link
          to="/"
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors"
        >
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </Link>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-muted-foreground hover:bg-muted w-full transition-colors"
        >
          {collapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
