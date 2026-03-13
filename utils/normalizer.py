from typing import List, Dict, Any
from core.models import Finding, Severity

SEVERITY_MAPPING = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

def normalize_severity(severity_str: str) -> Severity:
    return SEVERITY_MAPPING.get(severity_str.lower(), Severity.INFO)

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate based on unique combination of URL, CWE, and Name/Description.
    Using a dictionary with a tuple key for uniqueness.
    """
    unique_findings = {}
    for f in findings:
        # Key: (url, cwe, name) - simplistic but effective for typically noisy DASTs
        key = (f.url, f.cwe, f.name)
        if key not in unique_findings:
            unique_findings[key] = f
        else:
            # Maybe keep the one with more info? For now, first wins.
            pass
            
    return list(unique_findings.values())
