from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel
from adapters.garak import GarakAdapter
from core.models import ScanResponse, Finding, ScanStatusResponse
from core.security import verify_api_key
from core.orchestrator import scan_manager
from uuid import UUID

router = APIRouter(
    prefix="/garak",
    tags=["LLM Vulnerability Scanning"],
    responses={404: {"description": "Not found"}},
)

garak_adapter = GarakAdapter()

class GarakScanRequest(BaseModel):
    target: str # Model name, e.g., "gpt2", "huggingface/gpt2"
    probes: Optional[str] = None # comma separated list of probes
    generations: Optional[int] = None # number of generations

@router.get("/models", response_model=List[str])
async def list_llm_models(
    limit: int = 50,
    api_key: str = Depends(verify_api_key)
):
    """
    Fetch list of available HuggingFace models for scanning.
    """
    return await garak_adapter.get_huggingface_models(limit)

@router.post("/scan", response_model=ScanResponse, status_code=202)
async def scan_llm(
    request: GarakScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Start Garak LLM scan on a target model.
    """
    # Basic validation
    if not request.target:
        raise HTTPException(status_code=400, detail="Target model is required")
    
    # Sanitize inputs to prevent command injection is partly handled by subprocess in adapter,
    # but we should be careful about "target user input" being passed to CLI args.
    # Ideally we should strict validate 'target' format.
    
    try:
        scan_ref = await garak_adapter.start_scan(
            target=request.target, 
            probes=request.probes, 
            generations=request.generations
        )
        scan_id = await scan_manager.monitor_external_scan("GarakAdapter", scan_ref, request.target)
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

@router.get("/probes", response_model=List[str])
async def list_probes(
    api_key: str = Depends(verify_api_key)
):
    """
    List available Garak probes.
    """
    return await garak_adapter.get_probes()
