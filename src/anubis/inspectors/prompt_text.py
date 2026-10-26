"""
Layer 2: Literal prompt-text analysis shared by chat-template and system-prompt scanners.
Flags natural-language instructions that override safety rules, harvest credentials,
exfiltrate conversation data, steer users toward harmful actions, or hide themselves,
plus invisible Unicode smuggling, hardcoded URLs/IPv4 endpoints, and Base64 payloads.

These are phrase heuristics over static text: a clean result does not prove that a
template's instructions are benign, and paraphrased instructions can evade them.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Optional

from anubis.models import ScanReport, Severity

LAYER = "Layer 2 (Chat Template)"

URL_REGEX = re.compile(r"https?://[^\s\"<>'`)]+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_BLOB_REGEX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
MARKDOWN_BEACON_REGEX = re.compile(r"!\[[^\]\n]{0,80}\]\(\s*(?:https?:)?//", re.IGNORECASE)

BASE64_MIN_LENGTH = 32
BASE64_ENTROPY_THRESHOLD = 4.2  # bits/char; random base64 sits near 5.0-6.0
MAX_EXCERPTS = 3
EXCERPT_RADIUS = 60
PROSE_MIN_WORDS = 6
PROSE_PREVIEW_CHARS = 300

# Unicode tag characters (U+E0000-E007F) mirror ASCII and render invisibly: "ASCII smuggling".
TAG_CHAR_RANGE = range(0xE0000, 0xE0080)
BIDI_CONTROLS = set("‪‫‬‭‮⁦⁧⁨⁩")
ZERO_WIDTH = set("​‌‍⁠⁡⁢⁣⁤﻿")

# Common Cyrillic/Greek homoglyphs that NFKC leaves untouched.
HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ӏ": "l",
        "ο": "o",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
    }
)

_W = r"(?:\W+\w+)"  # one intervening word
SENSITIVE_DATA = (
    r"(?:passwords?|passcodes?|passphrases?|credentials?|log\W?ins?|api\W+keys?|private\W+keys?|"
    r"secret\W+keys?|seed\W+phrases?|recovery\W+(?:phrases?|codes?)|mnemonics?|2fa|mfa|otp|"
    r"one\W+time\W+(?:codes?|passwords?)|verification\W+codes?|credit\W+cards?|card\W+numbers?|"
    r"cvv|ssn|social\W+security|bank\W+(?:details|accounts?)|ssh\W+keys?|access\W+tokens?)"
)
SENSITIVE_DATA_REGEX = re.compile(rf"\b{SENSITIVE_DATA}\b")
CONVERSATION_DATA = (
    rf"(?:conversations?|chats?|messages?|history|transcripts?|prompts?|context|"
    rf"user\W+(?:data|input|queries|questions)|personal\W+(?:data|information)|pii|files?|{SENSITIVE_DATA})"
)


@dataclass(frozen=True)
class InstructionRule:
    category: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    # When set, a match only counts if this pattern also occurs within the surrounding window.
    near: Optional[re.Pattern[str]] = None


def _rule(
    category: str, title: str, severity: Severity, pattern: str, near: Optional[re.Pattern[str]] = None
) -> InstructionRule:
    return InstructionRule(category, title, severity, re.compile(pattern), near)


INSTRUCTION_RULES: tuple[InstructionRule, ...] = (
    _rule(
        "override",
        "Instruction Override Directive",
        Severity.HIGH,
        rf"\b(?:ignore|disregard|forget|override|bypass)\b{_W}{{0,4}}?\W+"
        r"(?:previous|prior|above|earlier|preceding|original|system|developer|safety)\W+(?:\w+\W+)?"
        r"(?:instructions?|prompts?|rules|guidelines|directives|messages|guardrails|polic(?:y|ies)|restrictions)\b",
    ),
    _rule(
        "override",
        "Instruction Override Directive",
        Severity.HIGH,
        r"\byou\W+are\W+no\W+longer\W+(?:bound|restricted|limited)\b",
    ),
    _rule(
        "exfiltration",
        "Data Exfiltration Instruction",
        Severity.HIGH,
        rf"\b(?:exfiltrat\w*|leak|smuggle)\b{_W}{{0,6}}?\W+{CONVERSATION_DATA}\b",
    ),
    _rule(
        "exfiltration",
        "Data Exfiltration Instruction",
        Severity.HIGH,
        rf"\b(?:send|post|upload|forward|transmit|submit|report|copy)\b{_W}{{0,8}}?\W+to\W+"
        r"(?:(?:the|this|that|our|my|a|an)\W+)?(?:(?:remote|external|following|collection|attacker)\W+)?"
        r"(?:url|endpoint|server|webhook|address|domain|host|api|email)\b",
        near=re.compile(rf"\b{CONVERSATION_DATA}\b"),
    ),
    _rule(
        "exfiltration",
        "Data Exfiltration Instruction",
        Severity.HIGH,
        rf"\b(?:include|embed|render|append|encode|put)\b{_W}{{0,8}}?\W+(?:markdown\W+)?(?:image|img|link|url|query\W+string)\b",
        near=re.compile(rf"\b{CONVERSATION_DATA}\b"),
    ),
    _rule(
        "credential_harvest",
        "Credential Harvesting Instruction",
        Severity.HIGH,
        rf"\b(?:ask|request|prompt|convince|persuade|trick|get|encourage|require|tell|have)\W+(?:the\W+|their\W+)?users?\b"
        rf"{_W}{{0,3}}?\W+(?:paste|share|provide|enter|send|give|type|reveal|confirm|disclose|submit|read\W+out|verify)\b",
        near=SENSITIVE_DATA_REGEX,
    ),
    _rule(
        "credential_harvest",
        "Credential Harvesting Instruction",
        Severity.HIGH,
        rf"\b(?:ask|request|collect|obtain|harvest|gather)\b{_W}{{0,4}}?\W+(?:for\W+)?(?:their|the\W+user'?s?|users'?)\W+{SENSITIVE_DATA}\b",
    ),
    _rule(
        "harmful_action",
        "Harmful Action Steering",
        Severity.HIGH,
        r"\b(?:tell|instruct|advise|recommend|convince|persuade|encourage|urge|direct|get)\W+(?:the\W+)?users?\W+to\W+"
        r"(?:\w+\W+){0,2}?(?:run|execute|install|download|disable|turn\W+off|uninstall|paste|visit|click|"
        r"transfer|wire|deposit|grant|approve)\b",
    ),
    _rule(
        "harmful_action",
        "Harmful Action Steering",
        Severity.HIGH,
        r"\bdisable\W+(?:the\W+|their\W+|your\W+)?(?:antivirus|anti\W?virus|firewall|defender|edr|2fa|"
        r"two\W+factor|mfa|security\W+(?:software|settings|features|warnings))\b",
    ),
    _rule(
        "harmful_action",
        "Embedded Shell Payload",
        Severity.HIGH,
        r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
        r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,60}\|\s*(?:ba|z)?sh\b"
        r"|\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s"
        r"|\b(?:iex|invoke-expression)\b\s*[\(\$]"
        r"|\brm\s+-rf\s+(?:/|~|\$home)",
    ),
    _rule(
        "safety_bypass",
        "Safety Guardrail Removal",
        Severity.MEDIUM,
        r"\b(?:no|without|free\W+from|not\W+bound\W+by|ignore)\W+(?:any\W+|all\W+)?(?:ethical|moral|safety|content)\W+"
        r"(?:guidelines|restrictions|filters|constraints|limits|rules|polic(?:y|ies)|guardrails)\b",
    ),
    _rule(
        "safety_bypass",
        "Safety Guardrail Removal",
        Severity.MEDIUM,
        r"\bdo\W+anything\W+now\b|\b(?:developer|god|jailbreak|jailbroken|dan)\W+mode\b|\bjailbr(?:eak|oken)\b",
    ),
    _rule(
        "deception",
        "User Deception Instruction",
        Severity.MEDIUM,
        r"\b(?:lie\W+to|deceive|mislead|manipulate|gaslight)\W+(?:the\W+)?users?\b",
    ),
    _rule(
        "deception",
        "User Deception Instruction",
        Severity.MEDIUM,
        r"\bpretend\W+(?:to\W+be|you\W+are)\W+(?:an?\W+|the\W+)?(?:official|real|human|bank|support|"
        r"customer\W+service|it\W+department|administrator|admin|government|police)\b"
        r"|\b(?:claim|say|insist)\W+(?:that\W+)?you\W+are\W+(?:a\W+)?(?:real\W+)?human\b",
    ),
    _rule(
        "concealment",
        "Self-Concealing Instruction",
        Severity.MEDIUM,
        r"\b(?:do\W+not|don'?t|never|must\W+not)\W+(?:\w+\W+){0,2}?(?:reveal|mention|disclose|admit|acknowledge|"
        r"reference|repeat|discuss)\W+(?:this|these|that|the\W+(?:above|following|hidden|secret))\b",
    ),
    _rule(
        "concealment",
        "Self-Concealing Instruction",
        Severity.MEDIUM,
        r"\b(?:keep|treat)\W+(?:this|these)\W+(?:\w+\W+)?(?:secret|hidden|confidential)\b"
        r"|\bwithout\W+(?:telling|informing|notifying|alerting|asking)\W+(?:the\W+)?users?\b"
        r"|\b(?:the\W+)?users?\W+(?:must|should|can)\W*(?:never|not)\W+(?:know|find\W+out|notice|learn)\b"
        r"|\b(?:secretly|covertly|subtly|silently|quietly)\W+(?:\w+\W+){0,2}?(?:insert|add|include|change|modify|"
        r"alter|recommend|promote|steer|collect|record|log|send|forward|copy)\b",
    ),
)

MARKDOWN_BEACON_RULE = InstructionRule(
    "exfiltration", "Data Exfiltration Instruction", Severity.HIGH, MARKDOWN_BEACON_REGEX
)

SEVERITY_ORDER = [Severity.PASS, Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass(frozen=True)
class TextSegment:
    text: str
    line: Optional[int] = None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _decode_tag_chars(text: str) -> str:
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if ord(ch) in TAG_CHAR_RANGE)


def normalize_prompt_text(text: str) -> str:
    """Fold compatibility forms, homoglyphs, invisible characters, and whitespace for matching."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.translate(HOMOGLYPHS).casefold()
    text = text.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text)


def _excerpt(text: str, start: int, end: int) -> str:
    lo = max(0, start - EXCERPT_RADIUS)
    hi = min(len(text), end + EXCERPT_RADIUS)
    return ("…" if lo else "") + text[lo:hi].strip() + ("…" if hi < len(text) else "")


def _location(source_label: str, line: Optional[int]) -> str:
    return f"{source_label}:line {line}" if line else source_label


def prose_passages(segments: Iterable[TextSegment]) -> list[str]:
    """Distinct literal passages long enough to read as natural-language instructions."""
    prose = [
        re.sub(r"\s+", " ", seg.text).strip()
        for seg in segments
        if len(re.findall(r"[^\W\d_]{2,}", seg.text)) >= PROSE_MIN_WORDS
    ]
    return list(dict.fromkeys(p for p in prose if p))


def audit_prompt_text(
    segments: Iterable[TextSegment],
    source_label: str,
    report: ScanReport,
    subject: str = "Chat Template",
) -> int:
    """Audit literal prompt text and return how many non-informational findings were added."""
    segments = [seg for seg in segments if seg.text]
    issues_found = 0

    # 1. Invisible Unicode smuggling, then scan any decoded tag-character payload as text.
    tag_payloads: list[TextSegment] = []
    bidi_count = zero_width_count = 0
    first_hidden_line: Optional[int] = None
    for seg in segments:
        decoded = _decode_tag_chars(seg.text)
        bidi = sum(ch in BIDI_CONTROLS for ch in seg.text)
        zero_width = sum(ch in ZERO_WIDTH for ch in seg.text.lstrip("﻿"))
        if decoded:
            tag_payloads.append(TextSegment(decoded, seg.line))
        bidi_count += bidi
        zero_width_count += zero_width
        if (decoded or bidi or zero_width) and first_hidden_line is None:
            first_hidden_line = seg.line
    if tag_payloads:
        preview = " ".join(seg.text for seg in tag_payloads)[:160]
        report.add(
            layer=LAYER,
            severity=Severity.HIGH,
            title=f"Invisible Unicode Tag Payload in {subject}",
            description=(
                f"Text contains invisible Unicode tag characters that decode to {preview!r}. "
                "Tag-character 'ASCII smuggling' hides instructions from human reviewers while models still read them."
            ),
            remediation="Strip U+E0000-U+E007F characters and review the decoded text before using this model.",
            location=_location(source_label, first_hidden_line),
        )
        issues_found += 1
        segments = segments + tag_payloads
    if bidi_count or zero_width_count:
        report.add(
            layer=LAYER,
            severity=Severity.HIGH if bidi_count else Severity.MEDIUM,
            title=f"Hidden Unicode Control Characters in {subject}",
            description=(
                f"Found {bidi_count} bidirectional override and {zero_width_count} zero-width character(s). "
                "These can make displayed text differ from what the model receives."
            ),
            remediation="Inspect the raw codepoints of this text; legitimate templates rarely need them.",
            location=_location(source_label, first_hidden_line),
        )
        issues_found += 1

    # 2. Natural-language instruction rules over normalized text.
    matches: dict[str, list[tuple[InstructionRule, str, Optional[int]]]] = {}
    seen_excerpts: set[tuple[str, str]] = set()
    for seg in segments:
        normalized = normalize_prompt_text(seg.text)
        for rule in INSTRUCTION_RULES:
            for match in rule.pattern.finditer(normalized):
                if rule.near is not None:
                    window = normalized[max(0, match.start() - 160) : match.end() + 160]
                    if not rule.near.search(window):
                        continue
                excerpt = _excerpt(normalized, match.start(), match.end())
                key = (rule.category, match.group(0))
                if key in seen_excerpts:
                    continue
                seen_excerpts.add(key)
                matches.setdefault(rule.category, []).append((rule, excerpt, seg.line))
        for match in MARKDOWN_BEACON_REGEX.finditer(seg.text):
            excerpt = _excerpt(seg.text, match.start(), match.end())
            if ("beacon", excerpt) not in seen_excerpts:
                seen_excerpts.add(("beacon", excerpt))
                matches.setdefault("exfiltration", []).append((MARKDOWN_BEACON_RULE, excerpt, seg.line))

    concealed = "concealment" in matches
    for category, hits in matches.items():
        rule = max((hit[0] for hit in hits), key=lambda r: SEVERITY_ORDER.index(r.severity))
        severity = rule.severity
        escalated = concealed and category != "concealment" and severity == Severity.HIGH
        if escalated:
            severity = Severity.CRITICAL
        excerpts = "; ".join(repr(excerpt) for _, excerpt, _ in hits[:MAX_EXCERPTS])
        more = f" (+{len(hits) - MAX_EXCERPTS} more)" if len(hits) > MAX_EXCERPTS else ""
        report.add(
            layer=LAYER,
            severity=severity,
            title=f"{rule.title} in {subject}",
            description=(
                f"Literal prompt text matches the '{category}' instruction pattern: {excerpts}{more}."
                + (" The same text also tells the model to hide its instructions." if escalated else "")
            ),
            remediation=(
                "Read the full injected text; chat templates and default system prompts run on every request "
                "and should only format messages, not direct model behavior against the user."
            ),
            location=_location(source_label, hits[0][2]),
            confidence=0.7 if rule.severity == Severity.HIGH else 0.6,
        )
        issues_found += 1

    # 3. Embedded URLs, IPv4 endpoints, and Base64 payloads.
    urls_found: set[str] = set()
    ipv4_found: set[str] = set()
    entropy_blobs: set[str] = set()
    for seg in segments:
        urls_found.update(URL_REGEX.findall(seg.text))
        for ip in IPV4_REGEX.findall(seg.text):
            try:
                parsed_ip = ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                continue
            if not (parsed_ip.is_loopback or parsed_ip.is_unspecified):
                ipv4_found.add(ip)

        for blob in B64_BLOB_REGEX.findall(seg.text):
            if len(blob) < BASE64_MIN_LENGTH:
                continue
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            # A decoded URL inside a Base64 blob is an intentional obfuscated exfiltration endpoint.
            if re.search(rb"https?://", decoded, re.IGNORECASE):
                report.add(
                    layer=LAYER,
                    severity=Severity.CRITICAL,
                    title=f"Base64-Obfuscated URL in {subject}",
                    description=(
                        f"String constant decodes to {decoded[:120]!r}. "
                        "Encoding exfiltration endpoints in Base64 is a known template-backdoor technique."
                    ),
                    remediation="Do not load this template; inspect the decoded endpoint before trusting it.",
                    location=_location(source_label, seg.line),
                )
                issues_found += 1
            elif _shannon_entropy(blob) >= BASE64_ENTROPY_THRESHOLD:
                entropy_blobs.add(blob)

    if urls_found:
        report.add(
            layer=LAYER,
            severity=Severity.MEDIUM,
            title=f"Hardcoded URLs Found in {subject}",
            description=f"Template contains embedded URLs: {sorted(urls_found)}",
            remediation="Verify whether these are benign documentation links or prompt-exfiltration endpoints.",
            location=source_label,
        )
        issues_found += 1

    if ipv4_found:
        report.add(
            layer=LAYER,
            severity=Severity.MEDIUM,
            title=f"Hardcoded IPv4 Endpoints in {subject}",
            description=f"Template contains literal IPv4 addresses: {sorted(ipv4_found)}",
            remediation="Legitimate templates never need raw IPs; treat as a possible exfiltration target.",
            location=source_label,
        )
        issues_found += 1

    if entropy_blobs:
        report.add(
            layer=LAYER,
            severity=Severity.MEDIUM,
            title=f"High-Entropy Base64 Payload in {subject}",
            description=(
                f"Found {len(entropy_blobs)} high-entropy Base64 blob(s), e.g. "
                f"{sorted(entropy_blobs)[0][:48]!r}. Could hide steganographic instructions or payloads."
            ),
            remediation="Decode and inspect the blob contents before trusting the template.",
            location=source_label,
        )
        issues_found += 1

    # 4. Surface hardcoded prose for manual review even when no rule matched.
    prose = prose_passages(segments)
    if prose:
        preview = " … ".join(prose)
        if len(preview) > PROSE_PREVIEW_CHARS:
            preview = preview[:PROSE_PREVIEW_CHARS] + "…"
        report.add(
            layer=LAYER,
            severity=Severity.INFO,
            title=f"Embedded Prompt Text in {subject}",
            description=(
                f"{len(prose)} hardcoded natural-language passage(s) are injected into prompts: {preview!r}. "
                "Phrase rules cannot catch every harmful instruction; review this text manually."
            ),
            location=source_label,
            confidence=0.99,
        )

    return issues_found
