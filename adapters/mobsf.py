import httpx
import logging
import asyncio
import json
import os
from typing import List, Callable, Optional, Dict, Any
from adapters.base import ScannerAdapter
from core.models import Finding
from config import settings
from utils.normalizer import normalize_severity

logger = logging.getLogger(__name__)

class MobSFAdapter(ScannerAdapter):
    _scans: Dict[str, Dict[str, Any]] = {}

    def __init__(self):
        self.api_url = settings.MOBSF_API_URL
        self.api_key = settings.MOBSF_API_KEY
        self.headers = {"Authorization": self.api_key}

    async def start_scan(self, target: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        """
        Starts a scan. 
        If target is a local file path, it uploads it first.
        If target is a URL, it assumes it's a git repo or direct link supported by MobSF (if applicable).
        Arguments:
            target: File path or URL.
        """
        from uuid import uuid4
        # scan_id = str(hash(target) + hash("mobsf_scan")) # Placeholder ID init
        scan_id = str(uuid4())
        
        # Determine if target is file or URL
        if os.path.exists(target):
            # It's a file, we need to upload it
            try:
                if log_callback: log_callback(f"Uploading file {target} to MobSF...")
                upload_data = await self._upload_file(target)
                scan_hash = upload_data.get("hash")
                scan_type = upload_data.get("scan_type")
                file_name = upload_data.get("file_name")
                
                if log_callback: log_callback(f"File uploaded. Hash: {scan_hash}")
                
                # Trigger Scan
                return await self._trigger_scan(scan_hash, scan_type, file_name, target, log_callback, finding_callback)
                
            except Exception as e:
                logger.error(f"MobSF Upload/Scan failed: {e}")
                self._scans[scan_id] = {"status": "failed", "error": str(e)}
                return scan_id
        else:
            # Assume it's a URL (Git or Zip URL) -> Logic depends on MobSF API support for remote URLs without upload
            # MobSF has /api/v1/download_source handling? Or just /api/v1/scan for 'file_name' if already uploaded?
            # MobSF isn't great at "remote URL scan" natively via simple API without some context (like is it git?).
            # For this implementation, I will treat non-existing files as errors or try a generic "upstream proxy" scan if supported?
            # Actually, let's treat it as "Not Supported" for now unless I implement git clone.
            # OR I can just return a failure.
            
            error_msg = f"Target {target} is not a local file. Remote URL scanning not fully implemented in adapter."
            logger.error(error_msg)
            if log_callback: log_callback(error_msg)
            
            # create failed state
            self._scans[scan_id] = {"status": "failed", "error": "Remote URL not supported"}
            return scan_id

    async def _upload_file(self, file_path: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            files = {'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')}
            response = await client.post(
                f"{self.api_url}/api/v1/upload",
                headers=self.headers,
                files=files,
                timeout=60.0
            )
            response.raise_for_status()
            return response.json()

    async def _trigger_scan(self, scan_hash: str, scan_type: str, file_name: str, original_target: str, log_callback=None, finding_callback=None) -> str:
        # Use the hash as the scan_id for tracking
        scan_id = scan_hash 
        
        # Initiate background task for scanning (polling/waiting)
        task = asyncio.create_task(self._run_scan_pipeline(scan_id, scan_hash, scan_type, file_name, log_callback, finding_callback))
        
        MobSFAdapter._scans[scan_id] = {
            "status": "running",
            "hash": scan_hash,
            "type": scan_type,
            "file": file_name,
            "task": task,
            "results": [],
            "logs": []
        }
        return scan_id

    async def _run_scan_pipeline(self, scan_id: str, scan_hash: str, scan_type: str, file_name: str, log_callback, finding_callback):
        # Local log wrapper
        def log(msg: str):
            if scan_id in MobSFAdapter._scans:
                MobSFAdapter._scans[scan_id]["logs"].append(msg)
            if log_callback:
                log_callback(msg)

        try:
            log(f"Triggering MobSF scan for {file_name} ({scan_hash})...")
            log(f"Scan type: {scan_type}")
            
            async with httpx.AsyncClient() as client:
                # /api/v1/scan
                payload = {
                    "hash": scan_hash,
                    "scan_type": scan_type,
                    "file_name": file_name,
                    "re_scan": 0
                }
                
                log("Initiating static analysis (this may take several minutes)...")
                
                # MobSF scan is synchronous/blocking on the server side usually, returns report json
                # Can take a long time, so we need high timeout
                response = await client.post(
                    f"{self.api_url}/api/v1/scan",
                    headers=self.headers,
                    data=payload,
                    timeout=300.0 # 5 minutes
                )
                response.raise_for_status()
                report = response.json()
                
                log("Static analysis completed. Processing security findings...")
                
                findings = self._parse_report(report)
                MobSFAdapter._scans[scan_id]["results"] = findings
                MobSFAdapter._scans[scan_id]["status"] = "completed"
                log(f"MobSF scan completed successfully. Discovered {len(findings)} security issues.")
                
                for f in findings:
                    if finding_callback: finding_callback(f)
                    
        except httpx.HTTPError as e:
            logger.error(f"MobSF HTTP error: {e}")
            MobSFAdapter._scans[scan_id]["status"] = "failed"
            MobSFAdapter._scans[scan_id]["error"] = f"HTTP Error: {str(e)}"
            log(f"MobSF scan failed with HTTP error: {e}")
        except Exception as e:
            logger.error(f"MobSF Scan failed: {e}")
            MobSFAdapter._scans[scan_id]["status"] = "failed"
            MobSFAdapter._scans[scan_id]["error"] = str(e)
            log(f"MobSF scan failed with exception: {e}")

    def _parse_report(self, report: Dict[str, Any]) -> List[Finding]:
        """Parse MobSF security report and extract findings."""  
        from core.models import AssetType, Confidence, Severity
        findings = []
        logger.info(f"MobSF report keys: {list(report.keys())[:10]}")
        
        # 1. Binary Analysis
        for item in report.get("binary_analysis", []):
            if isinstance(item, dict):
                findings.append(Finding(
                    scanner="mobsf",
                    name=item.get("title", "Binary Issue"),
                    severity=normalize_severity(item.get("stat", "info")),
                    description=item.get("description", ""),
                    asset_type=AssetType.MOBILE,
                    confidence=Confidence.HIGH
                ))
        
        # 2. Manifest Analysis  
        manifest = report.get("manifest_analysis", {})
        if isinstance(manifest, dict):
            for cat, items in manifest.items():
                for item in (items if isinstance(items, list) else []):
                    if isinstance(item, dict):
                        findings.append(Finding(
                            scanner="mobsf",
                            name=item.get("title", f"Manifest: {cat}"),
                            severity=normalize_severity(item.get("stat", "info")),
                            description=item.get("description", ""),
                            asset_type=AssetType.MOBILE,
                            confidence=Confidence.HIGH
                        ))
        
        # 3. Code Analysis
        for key, data in report.get("code_analysis", {}).items():
            if isinstance(data, dict):
                meta = data.get("metadata", {})
                if meta:
                    desc = f"File: {key} - {meta.get('description', '')}"
                    findings.append(Finding(
                        scanner="mobsf",
                        name=meta.get("description", key),
                        severity=normalize_severity(meta.get("severity", "info")),
                        description=desc,
                        cwe=meta.get("cwe"),
                        cvss=float(meta.get("cvss", 0)) if meta.get("cvss") else None,
                        asset_type=AssetType.MOBILE,
                        confidence=Confidence.MEDIUM
                    ))
        
        # 4. Dangerous Permissions
        for perm, det in report.get("permissions", {}).items():
            if isinstance(det, dict) and det.get("status") in ["dangerous", "critical"]:
                sev = Severity.MEDIUM if det.get("status") == "dangerous" else Severity.HIGH
                findings.append(Finding(
                    scanner="mobsf",
                    name=f"Dangerous Permission: {perm}",
                    severity=sev,
                    description=det.get("description", f"App requests {perm}"),
                    asset_type=AssetType.MOBILE,
                    confidence=Confidence.HIGH
                ))
        
        logger.info(f"MobSF extracted {len(findings)} findings")
        return findings


    async def get_status(self, scan_ref: str) -> str:
        if scan_ref not in self._scans:
            return "unknown"
        return self._scans[scan_ref]["status"]

    async def get_results(self, scan_ref: str) -> List[Finding]:
        if scan_ref not in self._scans:
            return []
        return self._scans[scan_ref]["results"]

    async def stop_scan(self, scan_ref: str) -> bool:
        # MobSF scan is server-side blocking usually. Cannot easily stop unless we kill connection?
        # But if we kill connection, server might keep running.
        # Minimal support.
        if scan_ref in self._scans:
            task = self._scans[scan_ref].get("task")
            if task and not task.done():
                task.cancel()
            self._scans[scan_ref]["status"] = "stopped"
            return True
        return False

    async def get_scan_report(self, scan_hash: str) -> Dict[str, Any]:
        """
        Fetch the full scan report from MobSF for a given hash.
        """
        async with httpx.AsyncClient() as client:
            # MobSF API endpoint for fetching report
            response = await client.post(
                f"{self.api_url}/api/v1/report_json",
                headers=self.headers,
                data={"hash": scan_hash},  # Use form data, not JSON
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    async def get_logs(self, scan_ref: str) -> List[str]:
        return self._scans.get(scan_ref, {}).get("logs", [])

    async def get_report_pdf(self, scan_ref: str) -> bytes:
        """
        Fetch PDF report from MobSF for the given scan_ref (which is actually the UUID).
        We need to look up the hash.
        """
        if scan_ref not in self._scans:
            raise ValueError("Scan not found")
            
        scan_info = self._scans[scan_ref]
        scan_hash = scan_info.get("hash")
        
        if not scan_hash:
             raise ValueError("Scan hash not found")
             
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.api_url}/api/v1/download_pdf",
                headers=self.headers,
                data={"hash": scan_hash},
                timeout=60.0
            )
            if response.status_code != 200:
                # Try simple GET if POST failed (older MobSF versions?) 
                # Docs say POST /api/v1/download_pdf
                raise Exception(f"Failed to download PDF: {response.text}")
                
            return response.content
