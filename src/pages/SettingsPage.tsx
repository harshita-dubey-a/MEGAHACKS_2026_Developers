import { PageHeader } from "@/components/CyberComponents";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";

const SettingsPage = () => {
  return (
    <div className="max-w-2xl space-y-6 animate-in">
      <PageHeader title="Settings" description="Manage your scanner configuration" />

      <div className="cyber-card p-6 space-y-6">
        <h3 className="text-sm font-semibold text-foreground">Profile</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>Full Name</Label>
            <Input defaultValue="Security Analyst" className="bg-muted/50 border-border" />
          </div>
          <div className="space-y-2">
            <Label>Email</Label>
            <Input defaultValue="analyst@company.com" className="bg-muted/50 border-border" />
          </div>
        </div>
      </div>

      <div className="cyber-card p-6 space-y-5">
        <h3 className="text-sm font-semibold text-foreground">Notifications</h3>
        {["Email alerts for critical vulnerabilities", "Scan completion notifications", "Weekly summary reports"].map((item) => (
          <div key={item} className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">{item}</span>
            <Switch defaultChecked />
          </div>
        ))}
      </div>

      <div className="cyber-card p-6 space-y-5">
        <h3 className="text-sm font-semibold text-foreground">Scan Defaults</h3>
        <div className="space-y-2">
          <Label>Default Scan Timeout (minutes)</Label>
          <Input type="number" defaultValue="60" className="bg-muted/50 border-border w-32" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Enable aggressive scanning</span>
          <Switch />
        </div>
      </div>

      <Button onClick={() => toast.success("Settings saved")} className="font-semibold">
        Save Changes
      </Button>
    </div>
  );
};

export default SettingsPage;
