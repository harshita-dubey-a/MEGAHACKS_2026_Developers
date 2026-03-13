import asyncio
import logging
import json
import shutil
import os
import httpx
from typing import List, Callable, Optional, Dict
from uuid import uuid4

# ... (rest of imports)


from adapters.base import ScannerAdapter
from core.models import Finding, Severity, AssetType, Confidence
from config import settings

logger = logging.getLogger(__name__)

class GarakAdapter(ScannerAdapter):
    def __init__(self):
        # Determine the command to run. 
        # If GARAK_PATH is "python -m garak", we might need to split it for subprocess
        # Check if settings.GARAK_PATH is just "python3 -m garak" which subprocess.exec might not like as one string if shell=False
        # It's better to rely on shlex or split manually.
        import shlex
        self.garak_cmd = shlex.split(settings.GARAK_PATH)

    _scans: Dict[str, Dict] = {}

    async def start_scan(self, target: str, probes: Optional[str] = None, generations: Optional[int] = None, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        scan_id = str(uuid4())
        
        # Validating target: For Garak, target matches --model_name
        # Probes matches --probes
        
        task = asyncio.create_task(self._run_garak_scan(scan_id, target, probes, generations, log_callback, finding_callback))
        
        GarakAdapter._scans[scan_id] = {
            "status": "running",
            "target": target,
            "task": task,
            "results": [],
            "logs": []
        }
        return scan_id

    async def _run_garak_scan(self, scan_id: str, target: str, probes: Optional[str], generations: Optional[int], log_callback, finding_callback):
        try:
            # Parse target for type/name
            # Format: type/name (e.g., huggingface/gpt2)
            # Default to huggingface if no slash
            # Default to huggingface for now as it handles most public models (including those with /)
            # Support explicit type via "type:name" syntax if needed later
            if ":" in target:
                model_type, model_name = target.split(":", 1)
            else:
                model_type = "huggingface"
                model_name = target
            
            # Temporary report file prefix
            report_prefix = f"/tmp/garak_report_{scan_id}"
            
            # Use --model_type and --model_name (or --target_type/--target_name)
            # older garak versions used model_type, newer target_type. 
            # The CLI help output showed --target_type.
            cmd = self.garak_cmd + ["--model_type", model_type, "--model_name", model_name, "--report_prefix", report_prefix]
            
            if probes:
                cmd.extend(["--probes", probes])
                
            if generations:
                cmd.extend(["--generations", str(generations)])

            # Add extra args
            if settings.GARAK_EXTRA_ARGS:
                cmd.extend(settings.GARAK_EXTRA_ARGS.split())

            def log(msg):
                if scan_id in GarakAdapter._scans:
                    GarakAdapter._scans[scan_id]["logs"].append(msg)
                if log_callback:
                    log_callback(msg)

            log(f"Starting Garak scan on {target} with probes: {probes or 'default'}...")
            log(f"Report will be saved to: {report_prefix}.report.jsonl")
            log(f"Executing Garak with command: {' '.join(cmd)}")
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Garak writes reports to files, but also logs to stdout/stderr.
            # We need to find the generated report file.
            # Garak report name format: {report_prefix}.report.jsonl usually
            
            report_file = f"{report_prefix}.report.jsonl"
            
            if process.returncode == 0 or os.path.exists(report_file):
                log("Garak scan finished. Parsing results...")
                findings = self._parse_jsonl_output(report_file, target)
                self._scans[scan_id]["results"] = findings
                self._scans[scan_id]["status"] = "completed"
                log(f"Garak scan completed. Found {len(findings)} LLM vulnerabilities.")
                
                for f in findings:
                    if finding_callback: finding_callback(f)
                    
                # Cleanup
                if os.path.exists(report_file):
                    os.remove(report_file)
                # Parse hits.jsonl if exists
                if os.path.exists(f"{report_prefix}.hit.jsonl"):
                    os.remove(f"{report_prefix}.hit.jsonl")

            else:
                error_msg = stderr.decode()
                logger.error(f"Garak failed: {error_msg}")
                self._scans[scan_id]["status"] = "failed"
                self._scans[scan_id]["error"] = error_msg
                log(f"Garak failed: {error_msg}")

        except Exception as e:
            logger.error(f"Garak execution error: {e}")
            self._scans[scan_id]["status"] = "failed"
            self._scans[scan_id]["error"] = str(e)
            if scan_id in GarakAdapter._scans and log_callback:
                log_callback(f"Garak scan failed with exception: {e}")

    def _parse_jsonl_output(self, report_path: str, target: str) -> List[Finding]:
        findings = []
        try:
            if not os.path.exists(report_path):
                return []
                
            with open(report_path, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        # Filter for failed attempts / vulnerabilities
                        # entry format depends on Garak version.
                        # Usually entry has "status": "fail" if vulnerable?
                        # Or checking "score"
                        
                        # Reference: Garak report format
                        # entryType: "evaluation"
                        # probe: "..."
                        # detector: "..."
                        # status: "fail" -> Vulnerability found?
                        
                        # If entry['entry_type'] == 'evaluation' and entry['status'] == 2 (FAIL) ? 
                        # Need to consult Garak docs or assume standard failure.
                        # Actually Garak reports:
                        # {"entry_type": "attempt", ...}
                        # {"entry_type": "eval", "probe": ..., "detector": ..., "passed": false, ...}
                        
                        if entry.get("entry_type") == "eval" and entry.get("passed") is False:
                            probe = entry.get("probe", "unknown")
                            detector = entry.get("detector", "unknown")
                            outputs = entry.get("outputs", [])
                            prompt = entry.get("prompt", "")
                            
                            full_name = f"LLM Vulnerability: {probe} detected by {detector}"
                            description = f"Model failed {detector} check on probe {probe}.\nPrompt: {prompt}\nOutputs: {outputs}"
                            
                            findings.append(Finding(
                                scanner="garak",
                                name=full_name,
                                severity=Severity.HIGH, # LLM vulns are usually critical/high
                                description=description,
                                url=target,
                                asset_type=AssetType.LLM,
                                confidence=Confidence.HIGH
                            ))
                            
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to parse Garak report: {e}")
        
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
        
    async def get_probes(self) -> List[str]:
        # Run garak --list_probes
        try:
            cmd = self.garak_cmd + ["--list_probes"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if settings.GARAK_EXTRA_ARGS: # Just a check to force reload
                 pass
            
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            
            logger.info(f"Garak stdout: {stdout.decode()}")
            logger.error(f"Garak stderr: {stderr.decode()}")
            logger.info(f"Garak return code: {process.returncode}")

            if process.returncode == 0:
                # Parse stdout
                output = stdout.decode()
                probes = []
                count = 0
                for line in output.splitlines():
                    # Strip ANSI codes first for cleaner parsing logic
                    line = ansi_escape.sub('', line).strip()
                    
                    if count < 5:
                        logger.info(f"Line clean: {repr(line)}")
                        count += 1
                        
                    if "probes:" in line:
                         try:
                            parts = line.split("probes:", 1)[1].strip().split()
                            if parts:
                                probe_name = parts[0]
                                probes.append(probe_name)
                         except Exception as parse_e:
                             logger.error(f"Error parsing line '{line}': {parse_e}")
                
                logger.info(f"Parsed {len(probes)} probes.")
                return probes
        except Exception as e:
            logger.error(f"Failed to list probes: {e}")
        return []

    async def get_huggingface_models(self, limit: int = 10000) -> List[str]:
        """
        Fetch all text-generation models from HuggingFace Hub.
        """
        try:
            async with httpx.AsyncClient() as client:
                # Query for text-generation models
                url = f"https://huggingface.co/api/models?pipeline_tag=text-generation&limit={limit}"
                
                logger.info(f"Fetching HF models from: {url}")
                resp = await client.get(url, timeout=30.0)
                
                if resp.status_code == 200:
                    models = resp.json()
                    # Extract modelId
                    return [m["modelId"] for m in models]
                else:
                    logger.warning(f"Failed to fetch HF models: {resp.status_code}")
                    return ["gpt2", "facebook/opt-125m"] # Fallbacks
        except Exception as e:
            logger.error(f"Error fetching HF models: {e}")
            return ["gpt2", "facebook/opt-125m"] # Fallbacks
