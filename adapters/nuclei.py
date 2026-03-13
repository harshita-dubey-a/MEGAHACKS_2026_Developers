import asyncio
import json
import logging
from typing import List, Callable, Optional
from adapters.base import ScannerAdapter
from core.models import Finding, Severity
from config import settings
from utils.normalizer import normalize_severity

logger = logging.getLogger(__name__)

class NucleiAdapter(ScannerAdapter):
    async def start_scan(self, target: str) -> str:
        # For CLI tools, we might normally return a process ID or handle execution differently.
        # Here, we will simulate a "job" that runs and returns immediate results for simplicity 
        # in the 'get_results' phase, or ideally we spawn a background process.
        # BUT the requirement says "Run via subprocess".
        # To fit the "pollable" pattern of the Orchestrator, we need to track this process.
        # Since we are building the Orchestrator to handle the background execution, 
        # this adapter will actually execute the command when "start_scan" is called 
        # BUT wait, the orchestrator needs to poll status.
        # If we just fire and forget here, we lose track.
        # So we can't easily "poll" a subprocess unless we keep a reference to it.
        # However, for simplicity and statelessness, we might execute it and wait?
        # NO, "Background execution (do NOT block HTTP)".
        
        # Strategy: The Orchestrator will run this method in a background thread/task.
        # This specific adapter can just run the command synchronously (blocking the thread, but not the loop if executed in executor)
        # OR better: run asyncio subprocess.
        
        # Wait, if `start_scan` returns immediately, where does the process live?
        # Ideally, we should just return the command or a future.
        # But 'start_scan' implies kicking it off.
        
        # Let's assume start_scan starts the subprocess and returns an ID.
        # We need to map ID to the process. In a real app, this might be in Redis/Celery.
        # For this "in-memory" single instance, we can keep a strict dict here?
        # Or better: The *Orchestrator* manages the async task wrapper.
        pass
        # I'll implement the actual execution logic in 'run_scan' style, but let's stick to the interface.
        # If the interface expects 'start_scan' to return an ID, and 'get_status' to check it.
        return "nuclei_scan_placeholder_id"

    # RE-THINKING: The Architecture requirements say "Background execution".
    # And "Job queue".
    # So the Orchestrator calls `adapter.scan(target)`.
    # Maybe the adapter just performs the scan and returns results?
    # And the Orchestrator wraps that in a background task?
    # YES. That is much cleaner for the Nuclei generic case.
    # The requirement "Adapter pattern for each scanner" + "Poll scan status" applies to the API scanners (Zap/Acunetix).
    # For CLI scanners, we probably need a wrapper.
    
    # Let's adjust the Base Adapter or the implementation.
    # If I implement `run_and_wait` it blocks.
    # Let's implement `start_scan` to actually spawn the process and keep track of it in a class-level dict.
    
    _processes = {}
    
    async def start_scan(self, target: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        scan_id = str(hash(target) + hash("nuclei")) # Simple ID
        # In a real app, use UUID and proper storage
        
        # cmd = [settings.NUCLEI_PATH, "-u", target, "-jsonl", "-silent"]
        # For demo purposes, we might not have nuclei installed, so we handle FileNotFound
        
        # We will create a task that runs the process so we can poll it.
        task = asyncio.create_task(self._run_nuclei(target, scan_id, log_callback, finding_callback))
        self._processes[scan_id] = {"status": "running", "results": [], "task": task}
        return scan_id

    async def _run_nuclei(self, target: str, scan_id: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None):
        try:
            # Construct command
            cmd = f"{settings.NUCLEI_PATH} -u {target} -severity medium,high,critical -jsonl -silent"
            
            # Create subprocess with piped stdout
            logger.info(f"Starting Nuclei scan for {target}")
            if log_callback: log_callback(f"Starting Nuclei scan for {target}")
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self._processes[scan_id]["proc"] = proc

            
            results = []
            
            # Read line by line
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                    
                line_str = line.decode().strip()
                if not line_str:
                    continue
                    
                try:
                    data = json.loads(line_str)
                    finding = self._parse_finding(data)
                    
                    # Realtime log
                    msg = f"[Nuclei] Found: {finding.name} ({finding.severity}) at {finding.url}"
                    logger.info(msg)
                    if log_callback: log_callback(msg)
                    if finding_callback: finding_callback(finding)
                    
                    results.append(finding)
                except json.JSONDecodeError:
                    # Could be verbose info or error
                    # logger.debug(f"[Nuclei Output] {line_str}")
                    pass
            
            # Wait for process to exit
            await proc.wait()
            
            if proc.returncode == 0:
                self._processes[scan_id]["results"] = results
                self._processes[scan_id]["status"] = "completed"
                logger.info(f"Nuclei scan completed for {target}. Found {len(results)} vulnerabilities.")
                if log_callback: log_callback(f"Nuclei scan completed. Found {len(results)} results.")
            else:
                stderr_data = await proc.stderr.read()
                err_msg = stderr_data.decode()
                logger.error(f"Nuclei process failed with code {proc.returncode}: {err_msg}")
                self._processes[scan_id]["status"] = "failed"
                self._processes[scan_id]["error"] = err_msg
                if log_callback: log_callback(f"Nuclei scan failed: {err_msg}")
                
        except Exception as e:
            logger.error(f"Nuclei failed: {e}")
            if log_callback: log_callback(f"Nuclei scan failed exceptionally: {e}")
            self._processes[scan_id]["status"] = "failed"
            self._processes[scan_id]["error"] = str(e)

    def _parse_finding(self, data: dict) -> Finding:
        return Finding(
            scanner="nuclei",
            name=data.get("info", {}).get("name", "Unknown"),
            severity=normalize_severity(data.get("info", {}).get("severity", "info")),
            url=data.get("matched-at", ""),
            description=data.get("info", {}).get("description"),
            cwe=str(data.get("info", {}).get("classification", {}).get("cwe-id", [""])[0]) if data.get("info", {}).get("classification", {}).get("cwe-id") else None,
            cvss=data.get("info", {}).get("classification", {}).get("cvss-score")
        )

    async def get_status(self, scan_ref: str) -> str:
        if scan_ref not in self._processes:
            return "unknown"
        return self._processes[scan_ref]["status"]

    async def get_results(self, scan_ref: str) -> List[Finding]:
        if scan_ref not in self._processes:
            return []
        return self._processes[scan_ref].get("results", [])

    async def stop_scan(self, scan_ref: str) -> bool:
        if scan_ref not in self._processes:
            return False
            
        proc_info = self._processes[scan_ref]
        task = proc_info.get("task")
        proc = proc_info.get("proc")
        
        if proc:
            try:
                proc.terminate()
                # await proc.wait() # Don't await here, might block?
            except Exception as e:
                logger.error(f"Failed to kill Nuclei process: {e}")

        if task and not task.done():
            task.cancel()
            
        proc_info["status"] = "stopped"
        return True
