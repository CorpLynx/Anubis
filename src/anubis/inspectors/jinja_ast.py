"""
Layer 2: Jinja2 Chat Template AST Security Scanner.
Detects Server-Side Template Injection (SSTI), sandbox escapes, conditional
message.content backdoors, hardcoded exfiltration URLs/IPv4 endpoints, and
high-entropy Base64 payloads.
"""

import base64
import binascii
import ipaddress
import math
import re
from collections import Counter

from jinja2 import Environment, nodes

from anubis.limits import ScanBudget, ScanLimitExceeded
from anubis.models import ScanReport, Severity

DANGEROUS_ATTRS = {
    "__class__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__init__",
    "__import__",
    "__code__",
    "popen",
    "system",
    "eval",
    "exec",
    "os",
    "sys",
    "subprocess",
}

URL_REGEX = re.compile(r"https?://[^\s\"<>']+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_BLOB_REGEX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

BASE64_MIN_LENGTH = 32
BASE64_ENTROPY_THRESHOLD = 4.2  # bits/char; random base64 sits near 5.0-6.0
MAX_TEMPLATE_LENGTH = 1_000_000


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def audit_jinja_template(
    template_str: str,
    source_label: str,
    report: ScanReport,
    budget: ScanBudget | None = None,
) -> None:
    """Parses a Jinja2 chat template string into an AST and inspects for malicious patterns."""
    if len(template_str) > MAX_TEMPLATE_LENGTH:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.INFO,
            title="Chat Template Exceeds Parsing Limit",
            description=f"Skipped a {len(template_str):,}-character template; limit is {MAX_TEMPLATE_LENGTH:,}.",
            location=source_label,
        )
        return
    try:
        if budget:
            budget.check_time()
    except ScanLimitExceeded as exc:
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Chat Template Scan Budget Reached",
            description=f"Template analysis stopped at the configured limit: {exc}.",
            location=source_label,
        )
        return
    env = Environment()
    try:
        ast = env.parse(template_str)
    except Exception as exc:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.HIGH,
            title="Malformed Jinja2 Chat Template",
            description=f"Jinja2 parser failed on chat_template: {exc}",
            location=source_label,
        )
        return

    try:
        if budget:
            budget.check_time()
    except ScanLimitExceeded as exc:
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Chat Template Scan Budget Reached",
            description=f"Template analysis stopped at the configured limit: {exc}.",
            location=source_label,
        )
        return

    issues_found = 0

    # 1. Inspect attribute lookups for SSTI / Sandbox escapes
    for node in ast.find_all(nodes.Getattr):
        if node.attr in DANGEROUS_ATTRS or node.attr.startswith("__"):
            report.add(
                layer="Layer 2 (Chat Template)",
                severity=Severity.CRITICAL,
                title=f"Jinja2 Sandbox Escape Attribute ('{node.attr}')",
                description=f"Template accesses restricted attribute '{node.attr}' at line {node.lineno}.",
                remediation="Do not run inference with this model; its chat template attempts code execution.",
                location=f"{source_label}:line {node.lineno}",
            )
            issues_found += 1

    # 2. Inspect bracket lookups (e.g., obj['__globals__'])
    for node in ast.find_all(nodes.Getitem):
        if isinstance(node.arg, nodes.Const) and isinstance(node.arg.value, str):
            val = node.arg.value
            if val in DANGEROUS_ATTRS or val.startswith("__"):
                report.add(
                    layer="Layer 2 (Chat Template)",
                    severity=Severity.CRITICAL,
                    title=f"Jinja2 Sandbox Escape Key ('{val}')",
                    description=f"Template accesses restricted dictionary key '{val}' at line {node.lineno}.",
                    location=f"{source_label}:line {node.lineno}",
                )
                issues_found += 1

    # 3. Inspect conditional branches (`{% if ... %}`) for hidden triggers on `content`
    for if_node in ast.find_all(nodes.If):
        test_Repr = repr(if_node.test)
        # Normal templates check `message['content'] is string` or `message.content is defined`
        # Suspicious templates compare `content` against a specific string literal (e.g. `if "trigger" in message.content`)
        if "content" in test_Repr and isinstance(if_node.test, nodes.Compare):
            consts = [
                c.value
                for c in if_node.test.find_all(nodes.Const)
                if isinstance(c.value, str) and c.value not in ("", "string", "none")
            ]
            if consts:
                report.add(
                    layer="Layer 2 (Chat Template)",
                    severity=Severity.HIGH,
                    title="Conditional Prompt Trigger on Message Content",
                    description=(
                        f"Line {if_node.lineno} compares `message.content` against hardcoded literal(s) {consts}. "
                        "This is a classic pattern for inference-time sleeper backdoors."
                    ),
                    remediation="Inspect the model's chat_template around this line to verify what is injected.",
                    location=f"{source_label}:line {if_node.lineno}",
                )
                issues_found += 1

    # 4. Scan string constants for embedded URLs, IPv4 endpoints, and Base64 payloads
    urls_found: set[str] = set()
    ipv4_found: set[str] = set()
    entropy_blobs: set[str] = set()

    for const_node in ast.find_all(nodes.Const):
        if not isinstance(const_node.value, str):
            continue
        value = const_node.value

        urls_found.update(URL_REGEX.findall(value))
        for ip in IPV4_REGEX.findall(value):
            try:
                parsed_ip = ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                continue
            if not (parsed_ip.is_loopback or parsed_ip.is_unspecified):
                ipv4_found.add(ip)

        for blob in B64_BLOB_REGEX.findall(value):
            if len(blob) < BASE64_MIN_LENGTH:
                continue
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            # A decoded URL inside a Base64 blob is an intentional obfuscated exfiltration endpoint.
            if re.search(rb"https?://", decoded, re.IGNORECASE):
                report.add(
                    layer="Layer 2 (Chat Template)",
                    severity=Severity.CRITICAL,
                    title="Base64-Obfuscated URL in Chat Template",
                    description=(
                        f"String constant decodes to {decoded[:120]!r}. "
                        "Encoding exfiltration endpoints in Base64 is a known template-backdoor technique."
                    ),
                    remediation="Do not load this template; inspect the decoded endpoint before trusting it.",
                    location=f"{source_label}:line {const_node.lineno}",
                )
                issues_found += 1
            elif _shannon_entropy(blob) >= BASE64_ENTROPY_THRESHOLD:
                entropy_blobs.add(blob)

    if urls_found:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.MEDIUM,
            title="Hardcoded URLs Found in Chat Template",
            description=f"Template contains embedded URLs: {sorted(urls_found)}",
            remediation="Verify whether these are benign documentation links or prompt-exfiltration endpoints.",
            location=source_label,
        )
        issues_found += 1

    if ipv4_found:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.MEDIUM,
            title="Hardcoded IPv4 Endpoints in Chat Template",
            description=f"Template contains literal IPv4 addresses: {sorted(ipv4_found)}",
            remediation="Legitimate templates never need raw IPs; treat as a possible exfiltration target.",
            location=source_label,
        )
        issues_found += 1

    if entropy_blobs:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.MEDIUM,
            title="High-Entropy Base64 Payload in Chat Template",
            description=(
                f"Found {len(entropy_blobs)} high-entropy Base64 blob(s), e.g. "
                f"{sorted(entropy_blobs)[0][:48]!r}. Could hide steganographic instructions or payloads."
            ),
            remediation="Decode and inspect the blob contents before trusting the template.",
            location=source_label,
        )
        issues_found += 1

    if issues_found == 0:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.PASS,
            title="Jinja2 Chat Template AST Clean",
            description=f"Audited AST ({len(template_str):,} chars). No sandbox escapes or conditional triggers found.",
            location=source_label,
        )
