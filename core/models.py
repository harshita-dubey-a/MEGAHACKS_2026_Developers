from enum import Enum
from typing import List, Optional, Dict, Union, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, HttpUrl, Field

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    ABORTED = "aborted"
    STOPPED = "stopped"

class AssetType(str, Enum):
    WEB = "Web"
    MOBILE = "Mobile"
    NETWORK = "Network"
    LLM = "LLM"

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    scanner: str
    name: str
    severity: Severity = Severity.INFO
    url: Optional[str] = None
    asset: Optional[str] = None
    description: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    
    # Risk Prioritization Fields
    risk_score: float = 0.0
    confidence: Confidence = Confidence.HIGH
    asset_type: AssetType
    
    class Config:
        frozen = True # Allow hashing for deduplication

class ScanType(str, Enum):
    WEB = "web"
    MOBILE = "mobile"
    NETWORK = "network"
    LLM = "llm"

class ScanRequest(BaseModel):
    type: ScanType = ScanType.WEB
    target: str
    options: Dict[str, Union[str, int, bool]] = {}

class ScanRequestMobile(BaseModel):
    # Separate model if we need multipart/form-data specific handling or just use ScanRequest for JSON metadata
    pass

class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus = ScanStatus.STARTED

class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    progress: int = 0
    message: Optional[str] = None

class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class ScanResult(BaseModel):
    scan_id: UUID
    status: ScanStatus
    target: str
    summary: ScanSummary
    vulnerabilities: List[Finding] = []
    logs: List[str] = []
    metadata: Dict[str, Any] = {}

class DashboardSummaryResponse(BaseModel):
    total_vulnerabilities: int
    count_by_severity: Dict[str, int]
    count_by_asset_type: Dict[str, int]

class GroupedVulnerabilitiesResponse(BaseModel):
    Web: List[Finding] = []
    Mobile: List[Finding] = []
    Network: List[Finding] = []
    LLM: List[Finding] = []
