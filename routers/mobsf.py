from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from typing import List
import shutil
import os
import tempfile
from adapters.mobsf import MobSFAdapter
from core.models import ScanResponse, Finding, ScanStatusResponse
from core.security import verify_api_key
from core.orchestrator import scan_manager
from uuid import UUID

router = APIRouter(
    prefix="/mobsf",
    tags=["Mobile Security"],
    responses={404: {"description": "Not found"}},
)

# Instantiate adapter specifically for this router
# In a real app, this might be injected or global
mobsf_adapter = MobSFAdapter()

@router.post("/scan", response_model=ScanResponse, status_code=202)
async def scan_mobile_app(
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload and scan a mobile application (APK/IPA/ZIP).
    """
    # Create valid temp file (suffix is important for MobSF usually? no, adapter handles it)
    # Adapter checks os.path.exists within start_scan
    
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        shutil.copyfileobj(file.file, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        # Start scan (Adapter handles upload logic)
        scan_id = await mobsf_adapter.start_scan(tmp_path)
        
        # We can remove the temp file now? 
        # Adapter `start_scan` awaits `_upload_file` then `_trigger_scan`.
        # `_upload_file` reads it. So after `start_scan` returns, we can delete it IF `start_scan` is done reading.
        # `start_scan` IS async and awaits upload. So yes.
        os.unlink(tmp_path)
        
        if not scan_id:
             raise HTTPException(status_code=500, detail="Failed to initiate MobSF scan")

        # Register with Orchestrator for persistence and monitoring
        # scan_id here is the MobSF Hash/Ref ID
        orchestrator_id = await scan_manager.monitor_external_scan("MobSFAdapter", scan_id, file.filename)
        
        return ScanResponse(scan_id=orchestrator_id, status="started")
        
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
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
            progress=0 # MobSF doesn't provide granular progress easily via this flow
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Scan ID format")

@router.get("/findings/{scan_id}", response_model=List[Finding])
async def get_scan_findings(
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
        raise HTTPException(status_code=400, detail="Invalid Scan ID format")

from fastapi.responses import Response

@router.get("/report/{scan_id}")
async def get_scan_report(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Download the Scan Report (PDF).
    """
    try:
        scan_uuid = UUID(scan_id)
        scan = await scan_manager.get_scan(scan_uuid)
        if not scan:
             raise HTTPException(status_code=404, detail="Scan not found")
        
        # Resolve real MobSF ID from metadata
        # Mapped as "MobSFAdapter": hash
        refs = scan.metadata.get("scanner_refs", {})
        mobsf_hash = refs.get("MobSFAdapter")
        
        if not mobsf_hash:
            raise HTTPException(status_code=404, detail="MobSF scan reference not found in metadata")

        pdf_content = await mobsf_adapter.get_report_pdf(mobsf_hash)
        return Response(content=pdf_content, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"})
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Scan ID format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
