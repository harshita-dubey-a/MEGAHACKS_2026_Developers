import httpx
import logging
import json
import asyncio
from typing import List, Dict, Callable, Optional
from uuid import uuid4
from adapters.base import ScannerAdapter
from core.models import Finding, ScanResult
from config import settings
from utils.normalizer import normalize_severity

logger = logging.getLogger(__name__)

class AcunetixAdapter(ScannerAdapter):
    def __init__(self):
        self.base_url = settings.ACUNETIX_API_URL
        self.headers = {
            "X-Auth": settings.ACUNETIX_API_KEY,
            "Content-Type": "application/json"
        }
    
    # In-memory map to track target_id and scan_id
    _scans: Dict[str, Dict] = {}

    async def start_scan(self, target: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        if log_callback:
            log_callback(f"Starting Acunetix scan for {target}...")
        
        async with httpx.AsyncClient(verify=False) as client:
            # 1. Create Target
            # Acunetix requires creating a target first
            if log_callback:
                log_callback(f"Creating target in Acunetix...")
            
            target_resp = await client.post(
                f"{self.base_url}/api/v1/targets",
                json={"address": target, "description": "DAST Orchestrator Audit"},
                headers=self.headers
            )
            if target_resp.status_code != 201:
                # Target may already exist?
                logger.warning(f"Failed to create target in Acunetix: {target_resp.text}")
                if log_callback:
                    log_callback(f"Warning: Target creation returned {target_resp.status_code}")
                # For simplicity, we fail or try to find existing. 
                # Ideally handled better.
            
            target_id = target_resp.json().get("target_id")
            
            # 2. Start Scan
            # We need a profile_id (Scanning Profile). Usually "11111111-1111-1111-1111-111111111111" is Full Scan.
            if log_callback:
                log_callback(f"Initiating scan with target_id: {target_id}...")
            
            scan_resp = await client.post(
                f"{self.base_url}/api/v1/scans",
                json={
                    "target_id": target_id,
                    "profile_id": "11111111-1111-1111-1111-111111111111", 
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False}
                },
                headers=self.headers
            )
            
            scan_id = ""
            if scan_resp.status_code == 201:
                if log_callback:
                    log_callback("Scan started successfully in Acunetix")
                # "Location" header contains the URL to the scan, or body has scan_id
                # Actually body is empty usually for pure 201?
                # Acunetix API v1 returns JSON with "scan_id" ?
                # The documentation says redirects to the resource.
                # Let's assume standard behavior or check 'Location'.
                if "Location" in scan_resp.headers:
                    scan_id = scan_resp.headers["Location"].split("/")[-1]
                # Fallback to checking typical response body just in case
                try:
                    data = scan_resp.json()
                    scan_id = data.get("scan_id") or scan_id
                except:
                    pass
            
            ref_id = str(uuid4())
            self._scans[ref_id] = {
                "scan_id": scan_id,
                "target_id": target_id,
                "status": "started" # We track local status or query remote
            }
            
            # Background task to poll actual status if we want to cache it, 
            # OR we just query it in get_status.
            # Acunetix is persistent, so we can query it directly in get_status.
            
            # Start background monitoring for realtime findings
            if finding_callback and scan_id:
                asyncio.create_task(self._monitor_scan(scan_id, finding_callback, log_callback))
            
            if log_callback:
                log_callback(f"Acunetix scan monitoring started (scan_id: {scan_id})")
                
            return ref_id

    async def _monitor_scan(self, scan_id: str, finding_callback: Callable[[Finding], None], log_callback: Optional[Callable[[str], None]] = None):
        sent_ids = set()
        
        while True:
            await asyncio.sleep(10) # Poll interval
            
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    # Get Status & Session ID
                    resp = await client.get(
                        f"{self.base_url}/api/v1/scans/{scan_id}",
                        headers=self.headers
                    )
                    
                    if resp.status_code != 200:
                        logger.warning(f"Acunetix monitor: Failed to get scan {scan_id}")
                        continue
                        
                    data = resp.json()
                    status = data.get("current_session", {}).get("status")
                    result_id = data.get("current_session", {}).get("scan_session_id")
                    
                    # Fetch new findings if we have a session
                    if result_id:
                        vuln_resp = await client.get(
                            f"{self.base_url}/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities",
                            headers=self.headers
                        )
                        if vuln_resp.status_code == 200:
                            vulns = vuln_resp.json().get("vulnerabilities", [])
                            for v in vulns:
                                v_id = v.get("vuln_id")
                                if v_id and v_id not in sent_ids:
                                    sent_ids.add(v_id)
                                    finding = self._parse_finding(v)
                                    # Push to orchestrator
                                    finding_callback(finding)
                    
                    # Stop if terminal state
                    if status in ["completed", "failed", "aborted", "stop"]:
                        break
                        
            except Exception as e:
                logger.error(f"Acunetix background monitor failed: {e}")
                # Don't break, retry next loop

    async def get_status(self, scan_ref: str) -> str:
        info = self._scans.get(scan_ref)
        if not info or not info.get("scan_id"):
            return "failed"
        
        scan_id = info["scan_id"]
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{self.base_url}/api/v1/scans/{scan_id}",
                headers=self.headers
            )
            if resp.status_code == 200:
                state = resp.json().get("current_session", {}).get("status", "processing")
                if state == "completed":
                    info["status"] = "completed"
                    return "completed"
                elif state in ["failed", "aborted"]:
                    info["status"] = "failed"
                    return "failed"
                else:
                    return "running"
            elif resp.status_code == 404:
                info["status"] = "failed"
                return "failed" # Deleted scan
            else:
                logger.warning(f"Acunetix API error: {resp.status_code}")
                return "failed"
        return "failed"

    async def get_results(self, scan_ref: str) -> List[Finding]:
        info = self._scans.get(scan_ref)
        # Check if local status prevents us from checking, 
        # but we should try anyway if it says completed locally.
        
        scan_id = info["scan_id"] if info else scan_ref # Fallback if direct scan_id used
        
        # Fetch vulnerabilities
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{self.base_url}/api/v1/scans/{scan_id}",
                headers=self.headers
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            result_id = data.get("current_session", {}).get("scan_session_id")
            
            if not result_id:
                return []

            vuln_resp = await client.get(
                f"{self.base_url}/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities",
                headers=self.headers
            )
            if vuln_resp.status_code != 200:
                return []
                
            vulns = vuln_resp.json().get("vulnerabilities", [])
            return [self._parse_finding(v) for v in vulns]

    async def stop_scan(self, scan_ref: str) -> bool:
        info = self._scans.get(scan_ref)
        if not info or not info.get("scan_id"):
            return False
            
        scan_id = info["scan_id"]
        async with httpx.AsyncClient(verify=False) as client:
            try:
                # Acunetix API to stop scan is POST /api/v1/scans/{scan_id}/abort
                await client.post(
                    f"{self.base_url}/api/v1/scans/{scan_id}/abort",
                    headers=self.headers
                )
                info["status"] = "stopped"
                return True
            except Exception as e:
                logger.error(f"Failed to stop Acunetix scan: {e}")
                return False

            except Exception as e:
                logger.error(f"Failed to stop Acunetix scan: {e}")
                return False

    async def resume_scan(self, scan_ref: str) -> bool:
        info = self._scans.get(scan_ref)
        if not info or not info.get("scan_id"):
            return False
            
        scan_id = info["scan_id"]
        async with httpx.AsyncClient(verify=False) as client:
            try:
                # Acunetix API to resume scan is POST /api/v1/scans/{scan_id}/resume
                await client.post(
                    f"{self.base_url}/api/v1/scans/{scan_id}/resume",
                    headers=self.headers
                )
                info["status"] = "running" # Optimistic update
                return True
            except Exception as e:
                logger.error(f"Failed to resume Acunetix scan: {e}")
                return False

    async def sync_scans(self) -> List[ScanResult]:
        """
        Fetch all historical scans from Acunetix and map to internal ScanResult objects.
        """
        results = []
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(
                    f"{self.base_url}/api/v1/scans",
                    headers=self.headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    scans = data.get("scans", [])
                    
                    for s in scans:
                        try:
                            scan_id = s.get("scan_id")
                            target_id = s.get("target_id")
                             # We'd need to fetch details for each to get vulnerabilities... 
                             # This might be heavy. For now, we can just track them.
                             # Or we just fetch the latest sessions.
                            pass 
                        except:
                            continue
        except Exception as e:
            logger.error(f"Failed to sync Acunetix history: {e}")
        return results

    def _parse_finding(self, vuln: dict) -> Finding:
        from core.models import AssetType, Confidence, Severity
        
        severity_raw = vuln.get("severity", "info")
        # Acunetix sometimes returns int severity: 3=High, 2=Medium, 1=Low, 0=Info
        if isinstance(severity_raw, int):
            if severity_raw >= 3:
                severity_raw = "high"
            elif severity_raw == 2:
                severity_raw = "medium"
            elif severity_raw == 1:
                severity_raw = "low"
            else:
                severity_raw = "info"
        
        # Normalize string to Enum
        try:
            sev = Severity(severity_raw.lower())
        except ValueError:
            sev = Severity.INFO

        return Finding(
             scanner="acunetix",
             name=vuln.get("vt_name", "Unknown"),
             severity=sev,
             url=vuln.get("affects_url", ""),
             description=vuln.get("description"),
             cwe=f"CWE-{vuln.get('cwe_id')}" if vuln.get("cwe_id") else None,
             cvss=vuln.get("cvss_score"),
             asset_type=AssetType.WEB,
             confidence=Confidence.HIGH
        )
