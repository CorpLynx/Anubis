from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    layer: str
    severity: Severity
    title: str
    description: str
    remediation: Optional[str] = None
    location: Optional[str] = None


@dataclass
class ScanReport:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        layer: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: Optional[str] = None,
        location: Optional[str] = None,
    ) -> None:
        self.findings.append(
            Finding(
                layer=layer,
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
                location=location,
            )
        )

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)
