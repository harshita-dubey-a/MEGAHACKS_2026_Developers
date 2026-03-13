from core.models import Finding, Severity

def calculate_risk_score(finding: Finding, asset_exposure: str = "internal") -> float:
    """
    Calculate risk score based on CVSS (if available) or Severity, Confidence, and Asset Exposure.
    
    Priority:
    1. Use CVSS score if available (0-10 scale)
    2. Calculate from Severity * Confidence * Asset Exposure
    """
    
    # If CVSS score is available, use it directly
    if finding.cvss is not None and finding.cvss > 0:
        return round(finding.cvss, 2)
    
    # Otherwise, calculate based on severity/confidence/exposure
    # Weights
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.0,
        Severity.INFO: 0.0
    }
    
    CONFIDENCE_WEIGHTS = {
        "High": 1.0,
        "Medium": 0.8,
        "Low": 0.5
    }
    
    ASSET_EXPOSURE_WEIGHTS = {
        "public": 1.2,
        "internal": 0.8,
        "unknown": 1.0
    }
    
    # Normalize inputs
    sev_weight = SEVERITY_WEIGHTS.get(finding.severity, 0.0)
    
    conf = finding.confidence.capitalize()
    conf_weight = CONFIDENCE_WEIGHTS.get(conf, 1.0) # Default to 1.0 if unknown
    
    exposure = asset_exposure.lower()
    exp_weight = ASSET_EXPOSURE_WEIGHTS.get(exposure, 1.0)
    
    score = sev_weight * conf_weight * exp_weight
    return round(score, 2)

def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings by risk score (descending).
    """
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
