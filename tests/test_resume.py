import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
from uuid import uuid4

# Import codebase
from core.models import ScanStatus, ScanResult, ScanRequest, Finding
from core.orchestrator import ScanManager
from adapters.acunetix import AcunetixAdapter
from adapters.base import ScannerAdapter

# Mock Adapter that supports resume
class MockResumableAdapter(ScannerAdapter):
    def __init__(self):
        self.status = "running"
        self.ref_id = "mock-ref"
    
    async def start_scan(self, target: str, scan_profile: str = "full", filters: dict = None):
        return self.ref_id
        
    async def get_status(self, scan_ref: str):
        return self.status
        
    async def get_results(self, scan_ref: str):
        return []
        
    async def stop_scan(self, scan_ref: str):
        self.status = "stopped"
        return True
        
    async def resume_scan(self, scan_ref: str):
        if self.status == "stopped":
            self.status = "running"
            return True
        return False

@pytest.mark.asyncio
async def test_resume_workflow():
    manager = ScanManager()
    
    # Inject mock adapter
    mock_adapter = MockResumableAdapter()
    manager.scans = {} # Reset
    manager._active_refs = {}
    manager._paused_refs = {}
    manager.scanners = [mock_adapter]
    
    # Start Scan
    request = ScanRequest(target="http://example.com", scan_profile="full", filters={})
    scan_id = await manager.create_scan(str(request.target))
    await asyncio.sleep(0.1) # Yield to allow workflow to start
    
    # Verify Clean Start
    assert scan_id in manager.scans
    assert manager.scans[scan_id].status == ScanStatus.RUNNING
    assert scan_id in manager._active_refs
    
    # Abort Scan
    await manager.abort_scan(scan_id)
    assert manager.scans[scan_id].status == ScanStatus.STOPPED
    assert mock_adapter.status == "stopped"
    assert scan_id not in manager._active_refs
    assert scan_id in manager._paused_refs
    
    # Resume Scan
    success = await manager.resume_scan(scan_id)
    assert success is True
    assert manager.scans[scan_id].status == ScanStatus.RUNNING
    assert mock_adapter.status == "running"
    assert scan_id in manager._active_refs
    assert scan_id not in manager._paused_refs
    
    print("Resume Workflow Verified Successfully")

if __name__ == "__main__":
    asyncio.run(test_resume_workflow())
