import { useState, useRef } from "react";
import { Upload, Smartphone, Loader2, FileUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/CyberComponents";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";
import { mobsfUploadFile, mobsfScan } from "@/lib/mobsf-api";

const ACCEPTED_TYPES = ".apk,.ipa,.zip,.appx,.xapk,.apks";

const MobileScan = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<"idle" | "uploading" | "scanning">("idle");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) setFile(f);
  };

  const handleScan = async () => {
    if (!file) {
      toast.error("Please select a file to scan");
      return;
    }
    setLoading(true);
    try {
      // Step 1: Upload
      setStep("uploading");
      const uploadRes = await mobsfUploadFile(file);
      toast.success("File uploaded", { description: `${uploadRes.file_name} (${uploadRes.scan_type})` });

      // Step 2: Scan
      setStep("scanning");
      await mobsfScan(uploadRes.hash);
      toast.success("Scan complete!", { description: uploadRes.file_name });
      navigate(`/mobile-scan-details/${uploadRes.hash}`);
    } catch (e: any) {
      toast.error("Scan failed", { description: e.message });
    } finally {
      setLoading(false);
      setStep("idle");
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in">
      <PageHeader title="Mobile App Scan" description="Upload and analyze mobile applications (APK, IPA, ZIP, APPX)" />

      <div className="cyber-card p-6 space-y-5">
        {/* Drop zone */}
        <div
          className="border-2 border-dashed border-border rounded-xl p-10 text-center cursor-pointer hover:border-primary/50 hover:bg-muted/30 transition-all"
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED_TYPES}
            onChange={handleFileChange}
            className="hidden"
          />
          {file ? (
            <div className="flex flex-col items-center gap-3">
              <FileUp className="w-10 h-10 text-primary" />
              <div>
                <p className="font-semibold text-foreground">{file.name}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <Upload className="w-10 h-10 text-muted-foreground" />
              <div>
                <p className="font-medium text-foreground">Click to upload</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Supported: APK, IPA, ZIP, APPX, XAPK, APKS
                </p>
              </div>
            </div>
          )}
        </div>

        <Button onClick={handleScan} disabled={loading || !file} className="h-11 font-semibold gap-2 w-full">
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              {step === "uploading" ? "Uploading..." : "Scanning..."}
            </>
          ) : (
            <>
              <Smartphone className="w-4 h-4" />
              Upload & Scan
            </>
          )}
        </Button>
      </div>
    </div>
  );
};

export default MobileScan;
