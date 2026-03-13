from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Dict
from uuid import UUID
from core.models import ScanRequest, ScanStatusResponse, ScanResult, Finding, AssetType, Severity, ScanStatus
from core.security import verify_api_key
from core.orchestrator import scan_manager

router = APIRouter(prefix="/acunetix", tags=["(Web)"])

@router.post("/scan", response_model=ScanStatusResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """Start a new Acunetix web scan"""
    try:
        scan_id = await scan_manager.create_scan(str(request.target), scan_type="Acunetix")
        return ScanStatusResponse(
            scan_id=scan_id,
            status=ScanStatus.STARTED,
            progress=0,
            message="Scan initiated"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_status(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Get the status of a specific scan"""
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

@router.get("/results/{scan_id}", response_model=ScanResult)
async def get_results(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Get the detailed results of a scan"""
    try:
        scan_uuid = UUID(scan_id)
        scan = await scan_manager.get_scan(scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except ValueError:
       raise HTTPException(status_code=400, detail="Invalid Scan ID")
