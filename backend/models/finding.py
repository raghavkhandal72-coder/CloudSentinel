from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    provider: str
    service: str
    resource: str
    issue: str
    severity: str
    evidence: Any
    remediation: str
    frameworks: dict[str, str] = field(default_factory=dict)
    
    # Risk Metadata
    exposure: int = 0
    privilege: int = 0
    data_sensitivity: int = 0
    exploitability: int = 0
    
    # Computed later by RiskEngine
    risk_score: int = 0
    risk_level: str = ""
    risk_factors: list[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "provider": self.provider,
            "service": self.service,
            "resource": self.resource,
            "issue": self.issue,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "exposure": self.exposure,
            "privilege": self.privilege,
            "data_sensitivity": self.data_sensitivity,
            "exploitability": self.exploitability,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors
        }
