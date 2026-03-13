from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict
from core.models import Finding, DashboardSummaryResponse, GroupedVulnerabilitiesResponse, Severity, AssetType, Confidence, ScanResult
from core.orchestrator import scan_manager
from core.risk import prioritize_findings
from core.security import verify_api_key

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    responses={404: {"description": "Not found"}},
)

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict
from core.models import Finding, DashboardSummaryResponse, GroupedVulnerabilitiesResponse, Severity, AssetType, Confidence, ScanResult
from core.orchestrator import scan_manager
from core.risk import prioritize_findings
from core.security import verify_api_key

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    responses={404: {"description": "Not found"}},
)

@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(api_key: str = Depends(verify_api_key)):
    """
    Get aggregated summary for the main dashboard from centralized ScanManager.
    """
    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    asset_counts = {"Web": 0, "Mobile": 0, "Network": 0, "LLM": 0}
    
    for scan in scan_manager.scans.values():
        for finding in scan.vulnerabilities:
            total_vulns += 1
            
            # Severity
            sev = finding.severity.value.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            # Asset Type
            atype = finding.asset_type.value.capitalize()
            if atype == "Llm": atype = "LLM" # Normalization fix
            
            if atype in asset_counts:
                asset_counts[atype] += 1
            else:
                 # Fallback if new types added
                asset_counts[atype] = asset_counts.get(atype, 0) + 1

    return DashboardSummaryResponse(
        total_vulnerabilities=total_vulns,
        count_by_severity=severity_counts,
        count_by_asset_type=asset_counts
    )

@router.get("/scans", response_model=List[ScanResult])
async def get_recent_scans(limit: int = 10, api_key: str = Depends(verify_api_key)):
    """
    Get list of recent scans.
    """
    # Sort by something? IDs are UUIDs (random).
    # Ideally scans should have created_at timestamp.
    # For now, just return list.
    scans = list(scan_manager.scans.values())
    # scans.sort(key=lambda x: x.created_at, reverse=True) # TODO: Add created_at to ScanResult
    return scans[:limit]

@router.get("/fix-first", response_model=List[Finding])
async def get_fix_first_list(limit: int = 5, api_key: str = Depends(verify_api_key)):
    """
    Get top N critical issues prioritized by risk score from ALL scans.
    """
    all_findings = []
    for scan in scan_manager.scans.values():
        all_findings.extend(scan.vulnerabilities)
    
    # Prioritize
    sorted_findings = prioritize_findings(all_findings)
    return sorted_findings[:limit]

@router.get("/vulnerabilities", response_model=List[Finding])
async def get_all_vulnerabilities(
    asset_type: str = None, 
    severity: str = None, 
    api_key: str = Depends(verify_api_key)
):
    """
    Get filtered list of vulnerabilities from all scans.
    """
    all_findings = []
    for scan in scan_manager.scans.values():
        for f in scan.vulnerabilities:
            # Apply filters
            if asset_type and f.asset_type.value.lower() != asset_type.lower():
                continue
            if severity and f.severity.value.lower() != severity.lower():
                continue
            all_findings.append(f)
            
    return all_findings

@router.get("/vulnerabilities/grouped", response_model=GroupedVulnerabilitiesResponse)
async def get_vulnerabilities_grouped(api_key: str = Depends(verify_api_key)):
    """
    Get all vulnerabilities grouped by asset type.
    """
    grouped = {
        "Web": [],
        "Mobile": [],
        "Network": [],
        "LLM": []
    }
    
    for scan in scan_manager.scans.values():
        for finding in scan.vulnerabilities:
            # Normalize key
            atype = finding.asset_type.value
            key = atype.capitalize()
            if key == "Llm": key = "LLM"
            
            if key in grouped:
                grouped[key].append(finding)
            else:
                # Handle unexpected types if any
                pass
    
    return GroupedVulnerabilitiesResponse(**grouped)


