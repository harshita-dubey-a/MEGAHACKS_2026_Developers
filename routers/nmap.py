from fastapi import APIRouter, HTTPException, Depends
from typing import List
from uuid import UUID
from pydantic import BaseModel, HttpUrl
from adapters.nmap import NmapAdapter
from core.models import ScanResponse, Finding, ScanStatusResponse
from core.security import verify_api_key, validate_target_url
from core.orchestrator import scan_manager
from uuid import UUID

router = APIRouter(
    prefix="/nmap",
    tags=["Network Scanning"],
    responses={404: {"description": "Not found"}},
)

nmap_adapter = NmapAdapter()

class NmapScanRequest(BaseModel):
    target: str

@router.post("/scan", response_model=ScanResponse, status_code=202)
async def scan_network(
    request: NmapScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Start Nmap scan on a target domain/IP.
    """
    # Simple validation against injection done by validate_target_url?
    # validate_target_url expects http/https URL. Nmap target can be IP or Hostname.
    # We should sanitize input effectively.
    
    # Let's ensure it doesn't contain spaces to avoid basic command injection if subprocess shell was used (it isn't, but still good practice)
    if " " in request.target or ";" in request.target:
        raise HTTPException(status_code=400, detail="Invalid target format")
    
    try:
        scan_id = await scan_manager.create_scan(request.target, scan_type="Nmap")
        return ScanResponse(scan_id=scan_id, status="started")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    try:
        scan_uuid = UUID(scan_id)
        scan = await scan_manager.get_scan(scan_uuid)
        if not scan:
             raise HTTPException(status_code=404, detail="Scan not found")
        return ScanStatusResponse(
            scan_id=scan.scan_id, 
            status=scan.status,
            progress=0
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Scan ID")

@router.get("/results/{scan_id}", response_model=List[Finding])
async def get_scan_results(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    try:
        scan_uuid = UUID(scan_id)
        scan = await scan_manager.get_scan(scan_uuid)
        if not scan:
             raise HTTPException(status_code=404, detail="Scan not found")
        return scan.vulnerabilities
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Scan ID")
