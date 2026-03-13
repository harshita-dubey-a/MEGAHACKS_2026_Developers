from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from uuid import UUID

from core.orchestrator import scan_manager
from core.security import verify_api_key

# Import adapters from their routers to access the singletons
# This relies on the fact that routers instantiate them at module level
from routers.mobsf import mobsf_adapter
from routers.nmap import nmap_adapter
from routers.garak import garak_adapter

router = APIRouter(
    prefix="/logs",
    tags=["Logs"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{scan_id}", response_model=List[str])
async def get_scan_logs(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get live logs for a specific scan ID from ScanManager.
    """
    try:
        uuid_obj = UUID(scan_id)
        scan = await scan_manager.get_scan(uuid_obj)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return scan.logs
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
