from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    severity: str
    title: str
    category: str
    endpoint: Optional[str]
    evidence: str
    recommendation: str
    confidence: str
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: Optional[dict] = None

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "category": self.category,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "method": self.method,
            "status_code": self.status_code,
            "response_headers": self.response_headers
        }
