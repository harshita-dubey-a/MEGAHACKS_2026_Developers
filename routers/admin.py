from fastapi import APIRouter, Depends, HTTPException
from core.security import verify_api_key
from core.orchestrator import scan_manager
from adapters.mobsf import MobSFAdapter
from uuid import UUID
import httpx
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)

mobsf_adapter = MobSFAdapter()

@router.post("/reparse_mobsf/{scan_id}")
async def reparse_mobsf_scan(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Re-fetch and re-parse a MobSF scan to extract findings.
    Useful for scans completed before the parser was fixed.
    """
    try:
        scan_uuid = UUID(scan_id)
        scan = await scan_manager.get_scan(scan_uuid)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get MobSF hash from metadata
        refs = scan.metadata.get("scanner_refs", {})
        mobsf_hash = refs.get("MobSFAdapter")
        
        if not mobsf_hash:
            raise HTTPException(status_code=400, detail="Not a MobSF scan")
        
        # Fetch report from MobSF directly
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{mobsf_adapter.api_url}/api/v1/report_json",
                headers=mobsf_adapter.headers,
                data={"hash": mobsf_hash},  # Use form data, not JSON
                timeout=30.0
            )
            response.raise_for_status()
            report = response.json()
        
        # Check for error in response
        if "error" in report:
            raise HTTPException(status_code=404, detail=f"MobSF report not found: {report['error']}")
        
        # Re-parse the report
        findings = mobsf_adapter._parse_report(report)
        
        # Update scan record
        scan.vulnerabilities = findings
        
        # Update summary
        from core.models import ScanSummary
        summary = ScanSummary()
        for f in findings:
            sev = str(f.severity).lower()
            if sev == "critical": summary.critical += 1
            elif sev == "high": summary.high += 1
            elif sev == "medium": summary.medium += 1
            elif sev == "low": summary.low += 1
            else: summary.info += 1
        
        scan.summary = summary
        scan_manager.storage.save_scan(scan)
        
        return {
            "scan_id": scan_id,
            "findings_extracted": len(findings),
            "summary": summary
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reparse failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
