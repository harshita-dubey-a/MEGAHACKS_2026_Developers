
import asyncio
from core.orchestrator import scan_manager
from core.models import Finding, ScanResult, ScanStatus, ScanSummary, Severity
from uuid import uuid4

def inject_data():
    scan_id = uuid4()
    scan_manager.scans[scan_id] = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.COMPLETED,
        target="http://example.com",
        summary=ScanSummary(critical=1, high=1),
        vulnerabilities=[
            Finding(
                scanner="mock",
                name="SQL Injection",
                severity=Severity.CRITICAL,
                url="http://example.com/id=1",
                asset_type="Web",
                risk_score=9.5,
                confidence="High"
            ),
             Finding(
                scanner="mock",
                name="Hardcoded API Key",
                severity=Severity.HIGH,
                url="http://example.com/app.js",
                asset_type="Mobile",
                risk_score=8.0,
                confidence="High"
            )
        ]
    )
    print("Injected fake scan data.")

if __name__ == "__main__":
    inject_data()
