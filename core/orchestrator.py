import asyncio
import logging
from uuid import uuid4, UUID
from typing import Dict, List, Callable
from datetime import datetime

from core.models import ScanResult, ScanStatus, ScanSummary, Finding
from adapters.base import ScannerAdapter
from adapters.nuclei import NucleiAdapter
from adapters.zap import ZapAdapter
from adapters.acunetix import AcunetixAdapter
from adapters.mobsf import MobSFAdapter
from adapters.nmap import NmapAdapter
from adapters.garak import GarakAdapter
from utils.normalizer import deduplicate_findings
from config import settings
from core.storage import StorageEngine


logger = logging.getLogger(__name__)

class ScanManager:
    def __init__(self):
        self.scans: Dict[UUID, ScanResult] = {}
        self.storage = StorageEngine()
        self.scanners: List[ScannerAdapter] = [
            NucleiAdapter(),
            ZapAdapter(),
            AcunetixAdapter(),
            MobSFAdapter(),
            NmapAdapter(),
            GarakAdapter()
        ]
        self._load_scans()
        
    def _load_scans(self):
        data = self.storage.load_all_scans()
        for scan_id, scan_data in data.items():
            try:
                self.scans[UUID(scan_id)] = ScanResult.model_validate(scan_data)
            except Exception as e:
                logger.error(f"Failed to load scan {scan_id}: {e}")

    async def create_scan(self, target: str, scan_type: str = "unified") -> UUID:
        scan_id = uuid4()
        
        # Initialize record
        self.scans[scan_id] = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.STARTED,
            target=target,
            summary=ScanSummary(),
            vulnerabilities=[],
            logs=[]
        )
        self.storage.save_scan(self.scans[scan_id])
        
        # Determine scanners to run
        scanners_to_run = self.scanners
        if scan_type.lower() != "unified":
            # Find specific scanner
            scanners_to_run = [s for s in self.scanners if s.__class__.__name__.lower().startswith(scan_type.lower()) or s.__class__.__name__.lower().replace("adapter","") == scan_type.lower()]
            if not scanners_to_run:
                logger.warning(f"No scanner found for type {scan_type}, falling back to none?")
                # If scanner not found, maybe fail?
                # For safety if tool scan requested but not found, run nothing?
                pass

        # Start background task
        asyncio.create_task(self._run_scan_workflow(scan_id, target, scanners_to_run))
        return scan_id

    async def monitor_external_scan(self, tool_name: str, ref_id: str, target: str) -> UUID:
        """
        Register and monitor a scan started externally (e.g. by a router).
        """
        scan_id = uuid4()
        
        # Initialize record
        self.scans[scan_id] = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.STARTED,
            target=target,
            summary=ScanSummary(),
            vulnerabilities=[],
            logs=[]
        )
        self.storage.save_scan(self.scans[scan_id])
        
        # Find scanner
        scanner = next((s for s in self.scanners if s.__class__.__name__.lower().startswith(tool_name.lower()) or s.__class__.__name__.lower().replace("adapter","") == tool_name.lower()), None)
        
        if not scanner:
            logger.error(f"Scanner not found for {tool_name}")
            self.scans[scan_id].status = ScanStatus.FAILED
            self.storage.save_scan(self.scans[scan_id])
            return scan_id
            
        # Register in active refs
        self._active_refs[scan_id] = [(scanner, ref_id)]
        
        # Save ref_id to metadata
        self.scans[scan_id].metadata["scanner_refs"] = {scanner.__class__.__name__: ref_id}
        self.storage.save_scan(self.scans[scan_id])
        
        # Start monitoring
        # We can reuse part of _run_scan_workflow logic but skipping start_scan
        # But _run_scan_workflow handles the loop.
        # So we create a new specialized task or refactor _run_scan_workflow to allow skipping start.
        # Let's create a specialized task for simplicity.
        asyncio.create_task(self._monitor_external_workflow(scan_id))
        
        return scan_id

    async def _monitor_external_workflow(self, scan_id: UUID):
        scan_record = self.scans[scan_id]
        scan_record.status = ScanStatus.RUNNING
        self.storage.save_scan(scan_record)
        
        active_scans = self._active_refs.get(scan_id, [])
        if not active_scans:
            return

        try:
            # Poll/Wait for completion with periodic saves
            poll_count = 0
            while True:
                all_done = True
                for scanner, ref_id in active_scans:
                    if scan_record.status == ScanStatus.STOPPED:
                        return

                    status = await scanner.get_status(ref_id)
                    if status not in ["completed", "failed", "stopped"]:
                        all_done = False
                        break
                
                if all_done:
                    break
                
                # Save periodically (every 6 polls = 30 seconds)
                poll_count += 1
                if poll_count % 6 == 0:
                    self.storage.save_scan(scan_record)
                
                await asyncio.sleep(5)
            
            # Collect Results
            all_findings = []
            for scanner, ref_id in active_scans:
                try:
                    findings = await scanner.get_results(ref_id)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Failed to get results: {e}")
            
            # Normalize & Deduplicate
            normalized_findings = deduplicate_findings(all_findings)
            
            # Calculate Risk Scores
            from core.risk import calculate_risk_score
            for f in normalized_findings:
                # Basic context
                f.risk_score = calculate_risk_score(f, "public")
            
            # Update Record
            scan_record.vulnerabilities = normalized_findings
            
            # Update Summary
            summary = ScanSummary()
            for f in normalized_findings:
                if f.severity == "critical": summary.critical += 1
                elif f.severity == "high": summary.high += 1
                elif f.severity == "medium": summary.medium += 1
                elif f.severity == "low": summary.low += 1
                else: summary.info += 1
            
            scan_record.summary = summary
            scan_record.status = ScanStatus.COMPLETED
            self.storage.save_scan(scan_record)
            
        except Exception as e:
            logger.error(f"External monitor workflow failed for {scan_id}: {e}")
            scan_record.status = ScanStatus.FAILED
            self.storage.save_scan(scan_record)

    async def get_scan(self, scan_id: UUID) -> ScanResult:
        return self.scans.get(scan_id)
    
    async def abort_scan(self, scan_id: UUID) -> bool:
        """
        Abort a running scan.
        """
        if scan_id not in self.scans:
            return False
        
        scan = self.scans[scan_id]
        if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.ABORTED]:
            return False
        
        scan.status = ScanStatus.ABORTED
        logger.info(f"Scan {scan_id} has been aborted")
        return True
    
    async def pause_scan(self, scan_id: UUID) -> bool:
        """
        Pause a running scan.
        """
        if scan_id not in self.scans:
            return False
        
        scan = self.scans[scan_id]
        if scan.status != ScanStatus.RUNNING:
            return False
        
        scan.status = ScanStatus.PAUSED
        logger.info(f"Scan {scan_id} has been paused")
        return True
    
    async def resume_scan(self, scan_id: UUID) -> bool:
        """
        Resume a paused scan.
        """
        if scan_id not in self.scans:
            return False
        
        scan = self.scans[scan_id]
        if scan.status != ScanStatus.PAUSED:
            return False
        
        scan.status = ScanStatus.RUNNING
        logger.info(f"Scan {scan_id} has been resumed")
        return True

    async def abort_scan(self, scan_id: UUID) -> bool:
        if scan_id not in self.scans:
            return False
            
        scan_record = self.scans[scan_id]
        if scan_record.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.STOPPED]:
            return False
            
        # Stop all adapters and move to paused list
        if scan_id in self._active_refs:
            for scanner, ref_id in self._active_refs[scan_id]:
                await scanner.stop_scan(ref_id)
            
            # Move to paused refs
            self._paused_refs[scan_id] = self._active_refs[scan_id]
            del self._active_refs[scan_id]
            
        scan_record.status = ScanStatus.STOPPED
        return True

        scan_record.status = ScanStatus.STOPPED
        return True

    async def resume_scan(self, scan_id: UUID) -> bool:
        if scan_id not in self.scans:
            return False
            
        scan_record = self.scans[scan_id]
        if scan_record.status not in [ScanStatus.STOPPED, ScanStatus.PAUSED]:
            return False
        
        # Resume adapters
        if scan_id in self._paused_refs:
            refs = self._paused_refs[scan_id]
            resumed = False
            for scanner, ref_id in refs:
                # Try to resume
                if await scanner.resume_scan(ref_id):
                    resumed = True
            
            if resumed:
                # Move back to active
                self._active_refs[scan_id] = refs
                del self._paused_refs[scan_id]
                scan_record.status = ScanStatus.RUNNING
                
                # Restart workflow monitoring if needed?
                # The original `_run_scan_workflow` loop might have exited if it saw STOPPED.
                # If so, we need to restart the monitoring loop.
                # However, the original loop had `return` on STOPPED.
                # So we need to spawn a new monitoring task.
                asyncio.create_task(self._resume_monitoring(scan_id))
                return True
                
        return False

    async def _resume_monitoring(self, scan_id: UUID):
        # Simplified monitoring restart
        # Re-use logic or just call _run_scan_workflow again with specific state?
        # _run_scan_workflow initializes everything. We don't want that.
        # We just want to poll.
        target = self.scans[scan_id].target
        active_scans = self._active_refs.get(scan_id, [])
        scan_record = self.scans[scan_id]
        
        while True:
            all_done = True
            for scanner, ref_id in active_scans:
                if scan_record.status == ScanStatus.STOPPED:
                    return
                status = await scanner.get_status(ref_id)
                if status not in ["completed", "failed", "stopped"]:
                    all_done = False
                    break
            
            if all_done:
                break
            await asyncio.sleep(5)
            
        # Collect results again (incremental or full?)
        # Base adapters are stateless mostly, so `get_results` gets all?
        # If so, we might duplicate? 
        # `deduplicate_findings` handles duplicates.
        # So we can just re-run collection.
        
        all_findings = []
        for scanner, ref_id in active_scans:
            try:
                findings = await scanner.get_results(ref_id)
                all_findings.extend(findings)
            except Exception:
                pass
        
        scan_record.vulnerabilities = deduplicate_findings(all_findings + scan_record.vulnerabilities)
        scan_record.status = ScanStatus.COMPLETED

    _active_refs: Dict[UUID, List] = {} 
    _paused_refs: Dict[UUID, List] = {}

    async def _run_scan_workflow(self, scan_id: UUID, target: str, scanners: List[ScannerAdapter] = None):
        if scanners is None:
            scanners = self.scanners
            
        scan_record = self.scans[scan_id]
        scan_record.status = ScanStatus.RUNNING
        self.storage.save_scan(scan_record)
        
        try:
            # 1. Start all scanners in parallel
            # We need to map which scanner returned which ref_id to later get results
            launch_tasks = []
            # Define logging callback
            def log_callback(msg: str):
                if scan_id in self.scans:
                    # Append timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.scans[scan_id].logs.append(f"[{timestamp}] {msg}")
            
            # Define finding callback
            def finding_callback(finding: Finding):
                if scan_id in self.scans:
                    scan = self.scans[scan_id]
                    scan.vulnerabilities.append(finding)
                    
                    # Update Summary Realtime
                    sev = finding.severity.lower()
                    if sev == "critical": scan.summary.critical += 1
                    elif sev == "high": scan.summary.high += 1
                    elif sev == "medium": scan.summary.medium += 1
                    elif sev == "low": scan.summary.low += 1
                    else: scan.summary.info += 1

            for scanner in scanners:
                launch_tasks.append(scanner.start_scan(target, log_callback, finding_callback))
            
            # These return ref_ids (strings) or raise exceptions
            ref_ids = await asyncio.gather(*launch_tasks, return_exceptions=True)
            
            active_scans = []
            for i, result in enumerate(ref_ids):
                if isinstance(result, Exception):
                    logger.error(f"Scanner {scanners[i].__class__.__name__} failed to start: {result}")
                    continue
                active_scans.append((scanners[i], result))
            
            self._active_refs[scan_id] = active_scans
            
            # Save ref_ids to metadata for persistence
            if active_scans:
                # If unified, we might have multiple. save as dict scanner_name -> ref_id
                refs_map = {s.__class__.__name__: rid for s, rid in active_scans}
                scan_record.metadata["scanner_refs"] = refs_map
                self.storage.save_scan(scan_record)

            # 2. Poll/Wait for completion with periodic saves
            # Simple polling strategy: check all active scans every few seconds
            # In a robust system, we might use callbacks or message queues.
            
            poll_count = 0
            while True:
                all_done = True
                for scanner, ref_id in active_scans:
                    # Check if global status is stopped
                    if scan_record.status == ScanStatus.STOPPED:
                        # Abort workflow
                        return

                    status = await scanner.get_status(ref_id)
                    if status not in ["completed", "failed", "stopped"]:
                        all_done = False
                        break
                
                if all_done:
                    break
                
                # Save periodically (every 6 polls = 30 seconds) to persist callback-added findings
                poll_count += 1
                if poll_count % 6 == 0:
                    self.storage.save_scan(scan_record)
                
                await asyncio.sleep(5)
            
            # 3. Collect Results
            all_findings = []
            for scanner, ref_id in active_scans:
                try:
                    findings = await scanner.get_results(ref_id)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Failed to get results from {scanner.__class__.__name__}: {e}")
            
            # 4. Normalize & Deduplicate
            normalized_findings = deduplicate_findings(all_findings)
            
            # 5. Calculate Risk Scores
            from core.risk import calculate_risk_score
            for f in normalized_findings:
                # Derive asset type from scanner logic or scan target?
                # Currently finding.asset_type defaults to "Web"
                # We can try to guess asset exposure based on target (internal/public)
                # For MVP, assume "public"
                asset_context = "public" 
                f.risk_score = calculate_risk_score(f, asset_context)
            
            # 6. Update Record
            scan_record.vulnerabilities = normalized_findings
            
            # Update Summary
            summary = ScanSummary()
            for f in normalized_findings:
                if f.severity == "critical": summary.critical += 1
                elif f.severity == "high": summary.high += 1
                elif f.severity == "medium": summary.medium += 1
                elif f.severity == "low": summary.low += 1
                else: summary.info += 1
            
            scan_record.summary = summary
            scan_record.status = ScanStatus.COMPLETED
            self.storage.save_scan(scan_record)
            
        except Exception as e:
            logger.error(f"Orchestrator workflow failed for {scan_id}: {e}")
            scan_record.status = ScanStatus.FAILED
            self.storage.save_scan(scan_record)

    async def sync_from_adapters(self):
        """
        Poll all adapters for historical/existing scans and populate memory.
        """
        for adapter in self.scanners:
            scan_type = adapter.__class__.__name__
            if hasattr(adapter, "sync_scans"):
                try:
                    logger.info(f"Syncing history from {scan_type}...")
                    results = await adapter.sync_scans()
                    for scan in results:
                        if scan.scan_id not in self.scans:
                            self.scans[scan.scan_id] = scan
                    logger.info(f"Synced {len(results)} scans from {scan_type}.")
                except Exception as e:
                    logger.error(f"Failed to sync {scan_type}: {e}")

scan_manager = ScanManager()
