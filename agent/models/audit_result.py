"""
Models for audit results.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class VulnerabilityLocation(BaseModel):
    """Model for a vulnerability location in code."""
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    function_name: Optional[str] = None
    contract_name: Optional[str] = None


class Vulnerability(BaseModel):
    """Model for a vulnerability found in the audit."""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float
    cvss_vector: str
    locations: List[VulnerabilityLocation]
    impact: str
    remediation: str
    references: List[str] = []
    historical_examples: List[str] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "locations": [loc.dict() for loc in self.locations],
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "historical_examples": self.historical_examples
        }


class AuditResult(BaseModel):
    """Model for the complete audit result."""
    audit_id: str
    files: List[str]
    vulnerabilities: List[Vulnerability]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "audit_id": self.audit_id,
            "files": self.files,
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities]
        }