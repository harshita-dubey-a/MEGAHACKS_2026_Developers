import { Moon, Sun, Bell, Search, User, Settings, LogOut, Info } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Link } from "react-router-dom";

export function Navbar() {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-20 flex items-center justify-between px-6">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative max-w-md w-full hidden md:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search targets, vulnerabilities..."
            className="pl-9 bg-muted/50 border-border h-9 text-sm"
          />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative group">
              <Bell className="w-4 h-4 transition-transform group-hover:scale-110" />
              <span className="absolute top-2 right-2 w-2 h-2 bg-destructive rounded-full border-2 border-card" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80 cyber-card animate-in fade-in-0 zoom-in-95">
            <DropdownMenuLabel className="flex justify-between items-center">
              <span>Notifications</span>
              <span className="text-[10px] bg-primary/20 text-primary px-1.5 py-0.5 rounded-full font-bold">3 NEW</span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <div className="max-h-[300px] overflow-y-auto cyber-scrollbar py-1">
              {[
                { title: "Critical Vuln Found", desc: "SQL Injection in axismaxlife.com", time: "2 min ago", icon: Info, color: "text-destructive" },
                { title: "Scan Completed", desc: "Network scan on 192.168.1.0/24", time: "15 min ago", icon: Info, color: "text-primary" },
                { title: "AI Analysis Ready", desc: "Mobile scan report enriched", time: "1 hour ago", icon: Info, color: "text-accent" },
              ].map((n, i) => (
                <DropdownMenuItem key={i} className="flex flex-col items-start gap-1 p-3 cursor-pointer hover:bg-muted/50 transition-colors border-b last:border-0 border-border/50">
                  <div className="flex items-center gap-2 w-full">
                    <n.icon className={cn("w-3.5 h-3.5", n.color)} />
                    <span className="font-bold text-xs flex-1">{n.title}</span>
                    <span className="text-[10px] text-muted-foreground">{n.time}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground pl-5">{n.desc}</p>
                </DropdownMenuItem>
              ))}
            </div>
          </DropdownMenuContent>
        </DropdownMenu>

        <Button variant="ghost" size="icon" onClick={toggleTheme} className="group transition-colors">
          {theme === "dark" ? (
            <Sun className="w-4 h-4 transition-all group-hover:rotate-90 group-hover:text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 transition-all group-hover:-rotate-12 group-hover:text-blue-500" />
          )}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center ml-2 cursor-pointer border border-primary/30 hover:bg-primary/30 transition-all group">
              <span className="text-xs font-bold text-primary group-hover:scale-110 transition-transform">SA</span>
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 cyber-card animate-in fade-in-0 zoom-in-95">
            <DropdownMenuLabel>
              <p className="text-xs font-bold text-foreground">Security Admin</p>
              <p className="text-[10px] text-muted-foreground font-medium">admin@sentinel.security</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link to="/settings" className="flex items-center gap-2 cursor-pointer">
                <User className="w-4 h-4" />
                <span className="text-xs font-medium">Profile Details</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link to="/settings" className="flex items-center gap-2 cursor-pointer">
                <Settings className="w-4 h-4" />
                <span className="text-xs font-medium">Account Settings</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="flex items-center gap-2 cursor-pointer text-destructive focus:text-destructive focus:bg-destructive/10">
              <LogOut className="w-4 h-4" />
              <span className="text-xs font-bold uppercase tracking-tighter">Emergency Logout</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
