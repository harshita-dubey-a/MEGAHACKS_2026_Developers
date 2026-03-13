import { useState } from "react";
import { Globe, Play, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/CyberComponents";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";
import { addTarget, scheduleScan, SCAN_PROFILES } from "@/lib/api";

const scanProfiles = [
  { id: SCAN_PROFILES.FULL_SCAN, label: "Full Scan" },
  { id: SCAN_PROFILES.HIGH_RISK, label: "Critical / High Risk" },
  { id: SCAN_PROFILES.XSS, label: "Cross-site Scripting" },
  { id: SCAN_PROFILES.SQL_INJECTION, label: "SQL Injection" },
  { id: SCAN_PROFILES.WEAK_PASSWORDS, label: "Weak Passwords" },
  { id: SCAN_PROFILES.CRAWL_ONLY, label: "Crawl Only" },
];

const InputTarget = () => {
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [profileId, setProfileId] = useState(SCAN_PROFILES.FULL_SCAN);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleStartScan = async () => {
    if (!url) {
      toast.error("Please enter a target URL");
      return;
    }
    setLoading(true);
    try {
      // Step 1: Create target
      const target = await addTarget({
        address: url,
        description: description || undefined,
        criticality: 10,
      });

      const targetId = target.target_id;

      // Step 2: Schedule scan
      await scheduleScan({
        target_id: targetId,
        profile_id: profileId,
        schedule: { disable: false, start_date: null, time_sensitive: false },
      });

      toast.success("Scan scheduled!", { description: `Target: ${url}` });
      navigate("/scanning");
    } catch (e: any) {
      toast.error("Failed to start scan", { description: e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in">
      <PageHeader title="Input Target" description="Configure your scan target and parameters" />

      <div className="cyber-card p-6 space-y-5 animate-in">
        <div className="space-y-2">
          <Label>Target URL</Label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="bg-muted/50 border-border h-11 mono pl-10"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label>Scanning Profile</Label>
          <Select value={profileId} onValueChange={setProfileId}>
            <SelectTrigger className="bg-muted/50 border-border h-11">
              <SelectValue placeholder="Select scan profile" />
            </SelectTrigger>
            <SelectContent>
              {scanProfiles.map((p) => (
                <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label>Target Description (optional)</Label>
          <Textarea
            placeholder="Brief description of the target..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="bg-muted/50 border-border resize-none"
            rows={3}
          />
        </div>

        <Button onClick={handleStartScan} disabled={loading} className="h-11 font-semibold gap-2">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {loading ? "Starting..." : "Start Scan"}
        </Button>
      </div>
    </div>
  );
};

export default InputTarget;
