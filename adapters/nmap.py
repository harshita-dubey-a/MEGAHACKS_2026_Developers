import asyncio
import logging
import xml.etree.ElementTree as ET
import shutil
from typing import List, Callable, Optional, Dict
from uuid import uuid4
from adapters.base import ScannerAdapter
from core.models import Finding
from config import settings
from utils.normalizer import normalize_severity

logger = logging.getLogger(__name__)

class NmapAdapter(ScannerAdapter):
    _scans: Dict[str, Dict] = {}

    def __init__(self):
        self.nmap_path = shutil.which(settings.NMAP_PATH) or "nmap"

    async def start_scan(self, target: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        scan_id = str(uuid4())
        
        # Validate target to avoid injection (basic check, but `subprocess` with list args is safer)
        # Nmap might freeze if target is weird, but orchestrator handles validation.
        
        task = asyncio.create_task(self._run_nmap_scan(scan_id, target, log_callback, finding_callback))
        
        self._scans[scan_id] = {
            "status": "running",
            "target": target,
            "task": task,
            "results": [],
            "logs": []
        }
        return scan_id

    async def _run_nmap_scan(self, scan_id: str, target: str, log_callback, finding_callback):
        try:
            # Construct command: nmap -oX - [defaults] target
            # splitting default args
            args = settings.NMAP_DEFAULT_ARGS.split()
            cmd = [self.nmap_path, "-oX", "-"] + args + [target]
            
            def log(msg):
                if scan_id in self._scans:
                    self._scans[scan_id]["logs"].append(msg)
                if log_callback:
                    log_callback(msg)

            log(f"Starting Nmap scan on {target}...")
            log(f"Running command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                log("Nmap scan finished. Parsing results...")
                findings = self._parse_xml_output(stdout)
                self._scans[scan_id]["results"] = findings
                self._scans[scan_id]["status"] = "completed"
                log(f"Nmap scan completed successfully. Found {len(findings)} open ports.")
                
                for f in findings:
                    if finding_callback: finding_callback(f)
            else:
                error_msg = stderr.decode()
                logger.error(f"Nmap failed: {error_msg}")
                self._scans[scan_id]["status"] = "failed"
                self._scans[scan_id]["error"] = error_msg
                log(f"Nmap failed: {error_msg}")

        except Exception as e:
            logger.error(f"Nmap execution error: {e}")
            self._scans[scan_id]["status"] = "failed"
            self._scans[scan_id]["error"] = str(e)
            if scan_id in self._scans and log_callback:
                log_callback(f"Nmap scan failed with exception: {e}")

    def _parse_xml_output(self, xml_content: bytes) -> List[Finding]:
        findings = []
        try:
            root = ET.fromstring(xml_content)
            # Find hosts
            for host in root.findall("host"):
                address = host.find("address")
                ip = address.get("addr") if address is not None else "unknown"
                
                ports = host.find("ports")
                if ports:
                    for port in ports.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = port.get("portid")
                            protocol = port.get("protocol")
                            service = port.find("service")
                            service_name = service.get("name") if service is not None else "unknown"
                            product = service.get("product") if service is not None else ""
                            version = service.get("version") if service is not None else ""
                            
                            full_name = f"Open Port: {port_id}/{protocol} ({service_name})"
                            description = f"Port {port_id} is open. Service: {service_name} {product} {version}".strip()
                            
                            findings.append(Finding(
                                scanner="nmap",
                                name=full_name,
                                severity="info", # Open ports are usually Info unless vulnerable version
                                description=description,
                                url=f"{ip}:{port_id}"
                            ))
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        
        return findings

    async def get_status(self, scan_ref: str) -> str:
        return self._scans.get(scan_ref, {}).get("status", "unknown")

    async def get_results(self, scan_ref: str) -> List[Finding]:
        return self._scans.get(scan_ref, {}).get("results", [])

    async def stop_scan(self, scan_ref: str) -> bool:
        if scan_ref in self._scans:
            task = self._scans[scan_ref].get("task")
            if task and not task.done():
                task.cancel()
            self._scans[scan_ref]["status"] = "stopped"
            return True
        return False

    async def get_logs(self, scan_ref: str) -> List[str]:
        return self._scans.get(scan_ref, {}).get("logs", [])
