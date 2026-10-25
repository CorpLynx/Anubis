"""
Layer 2: Jinja2 Chat Template AST Security Scanner.
Detects Server-Side Template Injection (SSTI) and sandbox escapes (including `|attr()`
and string-built attribute names), message-content backdoor triggers tracked through
variables, namespaces, and macros, and audits every literal string the template injects
(raw template text, constants, and folded concatenations) for harmful instructions,
hidden Unicode, exfiltration URLs/IPv4 endpoints, and Base64 payloads.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from jinja2 import Environment, nodes
from jinja2.ext import Extension, loopcontrols

from anubis.inspectors.prompt_text import TextSegment, _shannon_entropy, audit_prompt_text, prose_passages  # noqa: F401
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

MAX_TEMPLATE_LENGTH = 1_000_000
MAX_FOLDED_LENGTH = 4_096
MAX_FOLD_DEPTH = 32
MAX_TAINT_PASSES = 10

CONTENT_KEYS = {"content"}
# Fields of a message or multimodal content part that describe structure, not user text.
STRUCTURAL_KEYS = {
    "type", "role", "name", "id", "tool_call_id", "image", "image_url", "url", "video", "audio",
    "input_audio", "file", "mime_type", "detail", "function", "arguments", "tool_calls",
}
CONTENT_STRING_METHODS = {
    "startswith", "endswith", "find", "rfind", "index", "rindex", "count", "split", "rsplit",
    "partition", "rpartition", "replace", "__contains__",
}
REWRITE_METHODS = {"replace"}
SELECT_FILTERS = {"select", "reject"}
SELECTATTR_FILTERS = {"selectattr", "rejectattr"}
ATTRIBUTE_FILTERS = {"map", "selectattr", "rejectattr", "sort", "groupby", "sum", "unique", "min", "max", "attr"}
FOLDABLE_FILTERS = {"join", "lower", "upper", "reverse", "string", "trim", "replace", "first", "last", "list"}
# Documented vendor soft switches (Qwen3/SmolLM3/GLM reasoning toggles, SmolLM3 system override).
VENDOR_SWITCHES = {"/think", "/no_think", "/nothink", "/system_override"}
BENIGN_LITERALS = {"", "string", "none", "text", "content"} | STRUCTURAL_KEYS | VENDOR_SWITCHES
# Reasoning/tool delimiters that real templates legitimately look for in message content.
CONTROL_TOKEN_REGEX = re.compile(
    r"^(?:"
    r"</?(?:think|thinking|reasoning|reflection|answer|output|tool_call|tool_calls|tool_response|"
    r"tool_result|tool_results|function_call|functions?|response|analysis|final|code|image|start_of_image)>"
    r"|(?:<\|[a-z0-9_.:-]{1,40}\|>[a-z_]{0,16})+"
    r"|\[/?[A-Z_]{2,32}\]"
    r")$"
)

_UNKNOWN = object()


class _GenerationTagExtension(Extension):
    """Parse Hugging Face transformers' `{% generation %}` assistant-mask tag as a plain block."""

    tags = {"generation"}

    def parse(self, parser: Any) -> nodes.Node:
        lineno = next(parser.stream).lineno
        body = parser.parse_statements(("name:endgeneration",), drop_needle=True)
        return nodes.Scope(body, lineno=lineno)


def _is_benign_literal(value: str) -> bool:
    stripped = value.strip()
    return stripped.casefold() in BENIGN_LITERALS or bool(CONTROL_TOKEN_REGEX.match(stripped))


def _is_dangerous_name(value: str) -> bool:
    return any(part in DANGEROUS_ATTRS or part.startswith("__") for part in value.split(".") if part)


class _TemplateModel:
    """Constant folding and message-content taint tracking over one parsed template."""

    def __init__(self, ast: nodes.Template) -> None:
        self.ast = ast
        self.const_vars: dict[str, Any] = {}
        self.tainted_names: set[str] = set()
        self.tainted_attrs: set[tuple[str, str]] = set()
        self._collect_const_vars()
        self._propagate_taint()

    # -- Constant folding -------------------------------------------------
    def fold(self, node: nodes.Node, depth: int = 0) -> Any:
        """Best-effort, size-capped evaluation of literal expressions; never executes the template."""
        if isinstance(node, nodes.Const):
            return node.value
        if isinstance(node, nodes.TemplateData):
            return node.data
        if depth > MAX_FOLD_DEPTH:
            return _UNKNOWN
        # Only computed strings are capped; literal text is already bounded by the template size.
        result = self._fold(node, depth + 1)
        if isinstance(result, str) and len(result) > MAX_FOLDED_LENGTH:
            return _UNKNOWN
        return result

    def _fold(self, node: nodes.Node, depth: int) -> Any:
        if isinstance(node, nodes.Name):
            return self.const_vars.get(node.name, _UNKNOWN)
        if isinstance(node, nodes.Concat):
            parts = [self.fold(child, depth) for child in node.nodes]
            if any(part is _UNKNOWN or isinstance(part, (list, dict)) for part in parts):
                return _UNKNOWN
            return "".join("" if part is None else str(part) for part in parts)
        if isinstance(node, (nodes.List, nodes.Tuple)):
            items = [self.fold(item, depth) for item in node.items]
            return _UNKNOWN if any(item is _UNKNOWN for item in items) else items
        if isinstance(node, nodes.Add):
            left, right = self.fold(node.left, depth), self.fold(node.right, depth)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            if isinstance(left, list) and isinstance(right, list):
                return left + right
            return _UNKNOWN
        if isinstance(node, nodes.Mul):
            left, right = self.fold(node.left, depth), self.fold(node.right, depth)
            if isinstance(left, int) and isinstance(right, str):
                left, right = right, left
            if isinstance(left, str) and isinstance(right, int) and not isinstance(right, bool):
                if 0 <= right and len(left) * right <= MAX_FOLDED_LENGTH:
                    return left * right
            return _UNKNOWN
        if isinstance(node, nodes.Getitem):
            value, key = self.fold(node.node, depth), node.arg
            if isinstance(value, (str, list)):
                if isinstance(key, nodes.Slice):
                    bounds = [None if part is None else self.fold(part, depth) for part in (key.start, key.stop, key.step)]
                    if all(b is None or (isinstance(b, int) and not isinstance(b, bool)) for b in bounds) and bounds[2] != 0:
                        return value[slice(*bounds)]
                    return _UNKNOWN
                index = self.fold(key, depth)
                if isinstance(index, int) and not isinstance(index, bool) and -len(value) <= index < len(value):
                    return value[index]
            return _UNKNOWN
        if isinstance(node, nodes.Filter) and node.name in FOLDABLE_FILTERS and node.node is not None:
            value = self.fold(node.node, depth)
            args = [self.fold(arg, depth) for arg in node.args]
            if value is _UNKNOWN or any(arg is _UNKNOWN for arg in args) or node.kwargs or node.dyn_args:
                return _UNKNOWN
            try:
                if node.name == "join" and isinstance(value, list):
                    sep = args[0] if args else ""
                    return str(sep).join(str(item) for item in value)
                if node.name in ("lower", "upper", "trim") and isinstance(value, str):
                    return {"lower": value.lower, "upper": value.upper, "trim": value.strip}[node.name]()
                if node.name == "reverse" and isinstance(value, (str, list)):
                    return value[::-1]
                if node.name == "string":
                    return str(value)
                if node.name == "list" and isinstance(value, (str, list)):
                    return list(value)
                if node.name in ("first", "last") and isinstance(value, (str, list)) and value:
                    return value[0] if node.name == "first" else value[-1]
                if node.name == "replace" and isinstance(value, str) and len(args) >= 2:
                    old, new = str(args[0]), str(args[1])
                    if old and value.count(old) * max(1, len(new)) <= MAX_FOLDED_LENGTH:
                        return value.replace(old, new)
            except (TypeError, ValueError):
                return _UNKNOWN
        return _UNKNOWN

    def fold_strings(self, node: nodes.Node) -> list[str]:
        value = self.fold(node)
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, str)]
        return []

    def _collect_const_vars(self) -> None:
        for assign in self.ast.find_all(nodes.Assign):
            if isinstance(assign.target, nodes.Name):
                value = self.fold(assign.node)
                if value is not _UNKNOWN:
                    self.const_vars[assign.target.name] = value
                else:
                    self.const_vars.pop(assign.target.name, None)

    # -- Content taint tracking -------------------------------------------
    def _key(self, node: nodes.Node) -> Optional[str]:
        if isinstance(node, nodes.Getattr):
            return node.attr
        if isinstance(node, nodes.Getitem):
            key = self.fold(node.arg)
            return key if isinstance(key, str) else None
        return None

    def is_content(self, node: Optional[nodes.Node]) -> bool:
        """True when the expression can carry message text (`message.content`, tainted vars, parts)."""
        if node is None:
            return False
        if isinstance(node, (nodes.Getattr, nodes.Getitem)):
            key = self._key(node)
            if key in CONTENT_KEYS:
                return True
            if key in STRUCTURAL_KEYS:
                return False
            if isinstance(node.node, nodes.Name) and key is not None and (node.node.name, key) in self.tainted_attrs:
                return True
            if self.is_content(node.node):
                return True
            return isinstance(node, nodes.Getitem) and not isinstance(node.arg, nodes.Slice) and self.is_content(node.arg)
        if isinstance(node, nodes.Name):
            return node.name in self.tainted_names
        if isinstance(node, nodes.Keyword):
            if node.key == "attribute":
                return any(value in CONTENT_KEYS for value in self.fold_strings(node.value))
            return self.is_content(node.value)
        return any(self.is_content(child) for child in node.iter_child_nodes())

    def _taint_target(self, target: nodes.Node) -> bool:
        changed = False
        if isinstance(target, nodes.Name) and target.name not in self.tainted_names:
            self.tainted_names.add(target.name)
            changed = True
        elif isinstance(target, nodes.NSRef) and (target.name, target.attr) not in self.tainted_attrs:
            self.tainted_attrs.add((target.name, target.attr))
            changed = True
        elif isinstance(target, nodes.Tuple):
            for item in target.items:
                changed |= self._taint_target(item)
        return changed

    def _propagate_taint(self) -> None:
        macros = {macro.name: macro for macro in self.ast.find_all(nodes.Macro)}
        for _ in range(MAX_TAINT_PASSES):
            changed = False
            for assign in self.ast.find_all(nodes.Assign):
                if self.is_content(assign.node):
                    changed |= self._taint_target(assign.target)
                elif (
                    isinstance(assign.target, nodes.Name)
                    and isinstance(assign.node, nodes.Call)
                    and isinstance(assign.node.node, nodes.Name)
                    and assign.node.node.name == "namespace"
                ):
                    for kw in assign.node.kwargs:
                        if self.is_content(kw.value) and (assign.target.name, kw.key) not in self.tainted_attrs:
                            self.tainted_attrs.add((assign.target.name, kw.key))
                            changed = True
            for block in self.ast.find_all(nodes.AssignBlock):
                if any(self.is_content(child) for child in block.body):
                    changed |= self._taint_target(block.target)
            for loop in self.ast.find_all(nodes.For):
                if self.is_content(loop.iter):
                    changed |= self._taint_target(loop.target)
            for with_node in self.ast.find_all(nodes.With):
                for target, value in zip(with_node.targets, with_node.values):
                    if self.is_content(value):
                        changed |= self._taint_target(target)
            for call in self.ast.find_all(nodes.Call):
                if not isinstance(call.node, nodes.Name) or call.node.name not in macros:
                    continue
                macro = macros[call.node.name]
                for param, arg in zip(macro.args, call.args):
                    if self.is_content(arg):
                        changed |= self._taint_target(param)
                for kw in call.kwargs:
                    if self.is_content(kw.value):
                        changed |= self._taint_target(nodes.Name(kw.key, "param"))
            if not changed:
                break

    def literals(self, node: Optional[nodes.Node]) -> list[str]:
        """String literals an operand compares against, excluding subscript keys and attribute names."""
        if node is None:
            return []
        folded = self.fold_strings(node)
        if folded:
            return folded
        if isinstance(node, nodes.Getitem):
            return self.literals(node.node)
        if isinstance(node, nodes.Keyword) and node.key == "attribute":
            return []
        found: list[str] = []
        for child in node.iter_child_nodes():
            found.extend(self.literals(child))
        return found


def _report_escape(report: ScanReport, source_label: str, node: nodes.Node, kind: str, value: str) -> None:
    report.add(
        layer="Layer 2 (Chat Template)",
        severity=Severity.CRITICAL,
        title=f"Jinja2 Sandbox Escape {kind} ('{value}')",
        description=f"Template accesses restricted {kind.lower()} '{value}' at line {node.lineno}.",
        remediation="Do not run inference with this model; its chat template attempts code execution.",
        location=f"{source_label}:line {node.lineno}",
    )


def _content_trigger_checks(model: _TemplateModel, ast: nodes.Template) -> Iterator[tuple[nodes.Node, list[str], bool]]:
    """Yield (node, suspicious literals, is_rewrite) for every content-vs-literal operation."""
    for compare in ast.find_all(nodes.Compare):
        operands = [compare.expr] + [op.expr for op in compare.ops]
        content_ops = [op for op in operands if model.is_content(op)]
        if content_ops:
            others = [op for op in operands if not model.is_content(op)]
            yield compare, [lit for op in others for lit in model.literals(op)], False

    for test in ast.find_all(nodes.Test):
        operands = [test.node] + list(test.args)
        if any(model.is_content(op) for op in operands):
            others = [op for op in operands if not model.is_content(op)]
            yield test, [lit for op in others for lit in model.literals(op)], False

    for call in ast.find_all(nodes.Call):
        callee = call.node
        if (
            isinstance(callee, nodes.Getattr)
            and callee.attr in CONTENT_STRING_METHODS
            and model.is_content(callee.node)
        ):
            args = call.args[:1] if callee.attr in REWRITE_METHODS else call.args
            yield call, [lit for arg in args for lit in model.literals(arg)], callee.attr in REWRITE_METHODS

    for flt in ast.find_all(nodes.Filter):
        if flt.name in SELECT_FILTERS and model.is_content(flt.node) and len(flt.args) >= 2:
            yield flt, [lit for arg in flt.args[1:] for lit in model.literals(arg)], False
        elif flt.name in SELECTATTR_FILTERS and len(flt.args) >= 3:
            attr_names = model.fold_strings(flt.args[0])
            if any(name in CONTENT_KEYS for name in attr_names) or model.is_content(flt.node):
                yield flt, [lit for arg in flt.args[2:] for lit in model.literals(arg)], False
        elif flt.name == "replace" and model.is_content(flt.node) and flt.args:
            yield flt, model.literals(flt.args[0]), True


def _literal_segments(model: _TemplateModel, ast: nodes.Template) -> list[TextSegment]:
    """Every literal string the template can inject, with adjacent output parts joined."""
    segments: list[TextSegment] = []
    for output in ast.find_all(nodes.Output):
        buffer: list[str] = []
        line: Optional[int] = None
        for child in output.nodes:
            value = model.fold(child)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                buffer.append(str(value))
                line = line or child.lineno
            else:
                if buffer:
                    segments.append(TextSegment("".join(buffer), line))
                buffer, line = [], None
        if buffer:
            segments.append(TextSegment("".join(buffer), line))
    for const in ast.find_all(nodes.Const):
        if isinstance(const.value, str):
            segments.append(TextSegment(const.value, const.lineno))
    for expr_type in (nodes.Concat, nodes.Add, nodes.Filter):
        for expr in ast.find_all(expr_type):
            for value in model.fold_strings(expr):
                segments.append(TextSegment(value, expr.lineno))
    for name, value in model.const_vars.items():
        if isinstance(value, str):
            segments.append(TextSegment(value, None))

    unique: dict[str, TextSegment] = {}
    for seg in segments:
        unique.setdefault(seg.text, seg)
    return list(unique.values())


def audit_jinja_template(
    template_str: str,
    source_label: str,
    report: ScanReport,
    budget: ScanBudget | None = None,
) -> None:
    """Parses a Jinja2 chat template string into an AST and inspects for malicious patterns."""
    if len(template_str) > MAX_TEMPLATE_LENGTH:
        report.mark_incomplete("chat template exceeded the parser length limit")
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
        report.mark_incomplete(f"chat template scan budget reached: {exc}")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Chat Template Scan Budget Reached",
            description=f"Template analysis stopped at the configured limit: {exc}.",
            location=source_label,
        )
        return
    # Match the extensions transformers enables when rendering chat templates.
    env = Environment(extensions=[_GenerationTagExtension, loopcontrols])
    try:
        ast = env.parse(template_str)
    except Exception as exc:
        report.mark_incomplete("chat template syntax prevented AST inspection")
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
        report.mark_incomplete(f"chat template scan budget reached: {exc}")
        report.add(
            layer="Scanner",
            severity=Severity.INFO,
            title="Chat Template Scan Budget Reached",
            description=f"Template analysis stopped at the configured limit: {exc}.",
            location=source_label,
        )
        return

    try:
        model = _TemplateModel(ast)
    except RecursionError:
        report.mark_incomplete("chat template nesting exceeded the analyzer recursion limit")
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.MEDIUM,
            title="Chat Template Too Deeply Nested",
            description="Expression nesting exceeded the analyzer's recursion limit; legitimate templates are shallow.",
            location=source_label,
        )
        return
    issues_found = 0

    # 1. Inspect attribute lookups for SSTI / Sandbox escapes
    for node in ast.find_all(nodes.Getattr):
        if node.attr in DANGEROUS_ATTRS or node.attr.startswith("__"):
            _report_escape(report, source_label, node, "Attribute", node.attr)
            issues_found += 1

    # 2. Inspect bracket lookups (e.g., obj['__globals__'], obj['__cla' ~ 'ss__'])
    for node in ast.find_all(nodes.Getitem):
        for val in model.fold_strings(node.arg):
            if _is_dangerous_name(val):
                _report_escape(report, source_label, node, "Key", val)
                issues_found += 1

    # 3. Inspect `|attr('__class__')`, `map(attribute='__globals__')`, `selectattr('__class__')`, ...
    for node in ast.find_all(nodes.Filter):
        if node.name not in ATTRIBUTE_FILTERS:
            continue
        candidates: list[nodes.Node] = [kw.value for kw in node.kwargs if kw.key == "attribute"]
        if node.name in ("attr", "selectattr", "rejectattr"):
            candidates.extend(node.args[:1])
        elif node.name == "map" and len(node.args) >= 2 and model.fold_strings(node.args[0]) == ["attr"]:
            candidates.append(node.args[1])
        for candidate in candidates:
            values = model.fold_strings(candidate)
            for val in values:
                if _is_dangerous_name(val):
                    _report_escape(report, source_label, node, "Attribute", val)
                    issues_found += 1
            if not values and node.name == "attr":
                report.add(
                    layer="Layer 2 (Chat Template)",
                    severity=Severity.MEDIUM,
                    title="Dynamic Attribute Lookup via attr Filter",
                    description=(
                        f"Line {node.lineno} resolves an attribute name computed at render time. "
                        "Chat templates have no need for this, and it is a common way to hide sandbox-escape names."
                    ),
                    remediation="Inspect how the attribute name is built before trusting this template.",
                    location=f"{source_label}:line {node.lineno}",
                )
                issues_found += 1

    # 4. Message-content triggers, tracked through `set`, loops, namespaces, macros, and filters
    seen_triggers: set[tuple[int, tuple[str, ...], bool]] = set()
    for node, literals, is_rewrite in _content_trigger_checks(model, ast):
        consts = sorted({lit for lit in literals if not _is_benign_literal(lit)})
        key = (node.lineno, tuple(consts), is_rewrite)
        if not consts or key in seen_triggers:
            continue
        seen_triggers.add(key)
        if is_rewrite:
            report.add(
                layer="Layer 2 (Chat Template)",
                severity=Severity.MEDIUM,
                title="Message Content Rewritten by Hardcoded Literal",
                description=(
                    f"Line {node.lineno} rewrites message content wherever it contains {consts}. "
                    "Templates can silently alter or censor what the user actually said."
                ),
                remediation="Inspect the replacement text and verify why the template edits user messages.",
                location=f"{source_label}:line {node.lineno}",
            )
        else:
            report.add(
                layer="Layer 2 (Chat Template)",
                severity=Severity.HIGH,
                title="Conditional Prompt Trigger on Message Content",
                description=(
                    f"Line {node.lineno} compares `message.content` against hardcoded literal(s) {consts}. "
                    "This is a classic pattern for inference-time sleeper backdoors."
                ),
                remediation="Inspect the model's chat_template around this line to verify what is injected.",
                location=f"{source_label}:line {node.lineno}",
            )
        issues_found += 1

    # 5. Harmful instructions, hidden Unicode, URLs, IPv4 endpoints, and Base64 in all literal text
    segments = _literal_segments(model, ast)
    issues_found += audit_prompt_text(segments, source_label, report)
    report.record_prompt_text(source_label, "Jinja2 Chat Template", template_str, prose_passages(segments))

    if issues_found == 0:
        report.add(
            layer="Layer 2 (Chat Template)",
            severity=Severity.PASS,
            title="Jinja2 Chat Template AST Clean",
            description=f"Audited AST ({len(template_str):,} chars). No sandbox escapes or conditional triggers found.",
            location=source_label,
        )
