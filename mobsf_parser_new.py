def parse_mobsf_report(report, logger):
    """
    Parse MobSF security report and extract findings.
    MobSF returns a complex JSON with multiple security categories.
    """
    from typing import List, Dict, Any
    from core.models import Finding, AssetType, Confidence, Severity
    from utils.normalizer import normalize_severity
    
    findings = []
    
    # Safe get with logging
    def safe_get(data, key, default):
        value = data.get(key, default)
        logger.debug(f"MobSF report - {key}: {type(value)}")
        return value
    
    # 1. Parse Binary Analysis findings
    binary_analysis = safe_get(report, "binary_analysis", [])
    if isinstance(binary_analysis, list):
        for item in binary_analysis:
            if isinstance(item, dict):
                findings.append(Finding(
                    scanner="mobsf",
                    name=item.get("title", "Binary Analysis Issue"),
                    severity=normalize_severity(item.get("stat", "info")),
                    description=item.get("description", ""),
                    asset_type=AssetType.MOBILE,
                    confidence=Confidence.HIGH
                ))
    
    # 2. Parse Manifest Analysis (dict format)
    manifest_analysis = safe_get(report, "manifest_analysis", {})
    if isinstance(manifest_analysis, dict):
        for category, items in manifest_analysis.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        findings.append(Finding(
                            scanner="mobsf",
                            name=item.get("title", f"Manifest: {category}"),
                            severity=normalize_severity(item.get("stat", "info")),
                            description=item.get("description", ""),
                            asset_type=AssetType.MOBILE,
                            confidence=Confidence.HIGH
                        ))
    
    # 3. Parse Code Analysis (new structure: dict of files)
    code_analysis = safe_get(report, "code_analysis", {})
    if isinstance(code_analysis, dict):
        for finding_key, finding_data in code_analysis.items():
            if isinstance(finding_data, dict):
                # New MobSF structure has metadata
                metadata = finding_data.get("metadata", {})
                findings.append(Finding(
                    scanner="mobsf",
                    name=metadata.get("description", finding_key),
                    severity=normalize_severity(metadata.get("severity", "info")),
                    description=f"File: {finding_key}\\n{metadata.get('description', '')}",
                    cwe=metadata.get("cwe"),
                    cvss=float(metadata.get("cvss", 0)) if metadata.get("cvss") else None,
                    asset_type=AssetType.MOBILE,
                    confidence=Confidence.MEDIUM
                ))
    
    # 4. Parse Permissions
    permissions = safe_get(report, "permissions", {})
    if isinstance(permissions, dict):
        for perm, details in permissions.items():
            if isinstance(details, dict):
                status = details.get("status", "")
                if status in ["dangerous", "critical"]:
                    findings.append(Finding(
                        scanner="mobsf",
                        name=f"Dangerous Permission: {perm}",
                        severity=Severity.MEDIUM if status == "dangerous" else Severity.HIGH,
                        description=details.get("description", f"App requests {perm} permission"),
                        asset_type=AssetType.MOBILE,
                        confidence=Confidence.HIGH
                    ))
    
    # 5. Parse Network Security
    network_security = safe_get(report, "network_security", {})
    if isinstance(network_security, dict):
        for issue_type, details in network_security.items():
            if isinstance(details, dict) and details.get("severity") in ["high", "warning"]:
                findings.append(Finding(
                    scanner="mobsf",
                    name=f"Network Security: {issue_type}",
                    severity=normalize_severity(details.get("severity", "info")),
                    description=details.get("description", ""),
                    asset_type=AssetType.MOBILE,
                    confidence=Confidence.HIGH
                ))
    
    # 6. Parse Certificate Analysis
    certificate_analysis = safe_get(report, "certificate_analysis", {})
    if isinstance(certificate_analysis, dict):
        cert_findings = certificate_analysis.get("certificate_findings", [])
        if isinstance(cert_findings, list):
            for cert_issue in cert_findings:
                if isinstance(cert_issue, dict):
                    findings.append(Finding(
                        scanner="mobsf",
                        name=cert_issue.get("title", "Certificate Issue"),
                        severity=normalize_severity(cert_issue.get("severity", "info")),
                        description=cert_issue.get("description", ""),
                        asset_type=AssetType.MOBILE,
                        confidence=Confidence.HIGH
                    ))
    
    # 7. Security Score
    security_score = safe_get(report, "security_score", 100)
    if security_score < 50:
        findings.append(Finding(
            scanner="mobsf",
            name=f"Low Security Score: {security_score}/100",
            severity=Severity.HIGH,
            description=f"Overall app security score is {security_score}/100, indicating multiple security concerns",
            asset_type=AssetType.MOBILE,
            confidence=Confidence.HIGH
        ))
    
    logger.info(f"MobSF parser extracted {len(findings)} findings from report")
    return findings
