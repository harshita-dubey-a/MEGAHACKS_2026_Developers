from abc import ABC, abstractmethod
from typing import List, Callable, Optional
from core.models import Finding

class ScannerAdapter(ABC):
    @abstractmethod
    @abstractmethod
    async def start_scan(self, target: str, log_callback: Optional[Callable[[str], None]] = None, finding_callback: Optional[Callable[[Finding], None]] = None) -> str:
        """
        Starts a scan for the given target.
        Returns a scan_id or reference ID used by the scanner.
        """
        pass

    @abstractmethod
    async def get_results(self, scan_ref: str) -> List[Finding]:
        """
        Retrieves results for the given scan reference.
        Returns a list of normalized Findings.
        """
        pass
    
    @abstractmethod
    async def get_status(self, scan_ref: str) -> str:
        """
        Returns the status of the scan (running, completed, failed)
        """
        pass

    @abstractmethod
    async def stop_scan(self, scan_ref: str) -> bool:
        """
        Stops/Aborts the scan. Returns True if successful.
        """
        pass

    async def resume_scan(self, scan_ref: str) -> bool:
        """
        Resumes a paused/stopped scan. Returns True if successful.
        Default implementation returns False (not supported).
        """
        return False
