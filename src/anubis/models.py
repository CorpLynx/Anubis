from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
from typing import Optional


MAX_RECORDED_PROMPT_CHARS = 64_000
MAX_RECORDED_PASSAGE_CHARS = 8_000


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
    rule_id: str = ""
    confidence: float = 0.8
    evidence: Optional[str] = None


def _rule_layer_code(layer: str) -> str:
    lowered = layer.lower()
    for needle, code in (
        ("gguf", "GGUF"),
        ("safetensors", "SAFE"),
        ("mlx", "MLX"),
        ("chat template", "JINJA"),
        ("runner", "RUNNER"),
        ("network", "NET"),
        ("workspace", "SECRET"),
        ("upstream", "UPSTREAM"),
        ("provenance", "PROVENANCE"),
    ):
        if needle in lowered:
            return code
    return "GENERAL"


def stable_rule_id(layer: str, title: str) -> str:
    """Create a deterministic rule identifier while removing finding-specific values."""
    normalized = title.casefold()
    normalized = re.sub(r"ghsa-[a-z0-9-]+|cve-\d{4}-\d+", "advisory", normalized)
    normalized = re.sub(r"\bv?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?\b", "version", normalized)
    normalized = re.sub(r"(['\"]).*?\1", "value", normalized)
    normalized = re.sub(r"\([^)]*\)", "", normalized)
    normalized = re.sub(r"\b\d+\b", "n", normalized)
    slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-").upper()[:42]
    return f"ANB-{_rule_layer_code(layer)}-{slug or 'FINDING'}"


def default_confidence(layer: str, severity: Severity, title: str) -> float:
    """Rule-class estimate, not a calibrated probability."""
    lowered = f"{layer} {title}".lower()
    if severity == Severity.PASS:
        return 0.99
    if "provenance" in lowered or "recognized organization" in lowered or "uploader name" in lowered:
        return 0.55
    if "chat template" in lowered or "jinja" in lowered:
        return 0.75
    if "workspace" in lowered or "secret" in lowered:
        return 0.72
    if "mlx/hf code" in lowered:
        return 0.68
    if "upstream verification" in lowered:
        return 0.96 if "sha256" in lowered or "size differs" in lowered else 0.85
    if "gguf" in lowered or "safetensors" in lowered or "network exposure" in lowered:
        return 0.97 if severity in (Severity.CRITICAL, Severity.HIGH) else 0.92
    if "runner security" in lowered:
        return 0.9
    return 0.8


@dataclass
class ScanReport:
    target: str
    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    incomplete_reasons: list[str] = field(default_factory=list)
    # Raw prompt text (templates, system prompts) kept for opt-in export to `anubis redteam --judge`.
    prompt_texts: list[dict] = field(default_factory=list)

    def mark_incomplete(self, reason: str) -> None:
        self.complete = False
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def add(
        self,
        layer: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: Optional[str] = None,
        location: Optional[str] = None,
        rule_id: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence: Optional[str] = None,
    ) -> None:
        resolved_confidence = (
            default_confidence(layer, severity, title) if confidence is None else confidence
        )
        if not 0.0 <= resolved_confidence <= 1.0:
            raise ValueError("Finding confidence must be between 0 and 1")
        self.findings.append(
            Finding(
                layer=layer,
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
                location=location,
                rule_id=rule_id or stable_rule_id(layer, title),
                confidence=resolved_confidence,
                evidence=evidence or description,
            )
        )

    def record_prompt_text(self, source: str, subject: str, text: str, passages: Optional[list[str]] = None) -> None:
        """Keep a bounded copy of prompt text for optional model judgment; never sent anywhere by the scan."""
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        if any(entry["source"] == source and entry["sha256"] == digest for entry in self.prompt_texts):
            return
        kept_passages: list[str] = []
        budget = MAX_RECORDED_PASSAGE_CHARS
        for passage in passages or []:
            if budget <= 0:
                break
            kept_passages.append(passage[:budget])
            budget -= len(kept_passages[-1])
        self.prompt_texts.append(
            {
                "source": source,
                "subject": subject,
                "sha256": digest,
                "text": text[:MAX_RECORDED_PROMPT_CHARS],
                "truncated": len(text) > MAX_RECORDED_PROMPT_CHARS,
                "passages": kept_passages,
            }
        )

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        return {severity.value: sum(f.severity == severity for f in self.findings) for severity in Severity}
