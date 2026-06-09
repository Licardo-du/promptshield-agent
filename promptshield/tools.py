from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .report import render_markdown_report, write_markdown_report
from .rules import (
    PROMPT_INJECTION_RULES,
    SECRET_PATTERN_RULES,
    SKIP_DIRS,
    TOOL_PERMISSION_RULES,
    classify_file,
    has_nearby_guard,
    is_probably_text,
    scan_file_for_rules,
)
from .schemas import FileRecord, Finding, ScanSession, normalize_path_for_display


MAX_DEFAULT_FILE_BYTES = 200_000


@dataclass(slots=True)
class ToolResult:
    public_summary: str
    data: Any = None


ToolHandler = Callable[[dict[str, Any], ScanSession], ToolResult]


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler

    def to_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    def __init__(self, specs: list[ToolSpec]) -> None:
        self._specs = {spec.name: spec for spec in specs}

    def names(self) -> list[str]:
        return sorted(self._specs)

    def to_openai_tools(self) -> list[dict[str, Any]]:
        return [self._specs[name].to_openai_tool() for name in self.names()]

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        session: ScanSession,
        source: str = "local",
    ) -> ToolResult:
        if name not in self._specs:
            raise KeyError(f"Unknown tool: {name}")
        result = self._specs[name].handler(arguments, session)
        session.add_tool_call(name, arguments, result.public_summary, source=source)
        return result


def build_default_registry() -> ToolRegistry:
    return ToolRegistry(
        [
            ToolSpec(
                name="scan_local_files",
                description=(
                    "Read local prompt, config, code, and tool-schema files from a target path. "
                    "This populates the private scan session; only a summary is returned to the model."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "File or directory to scan.",
                        },
                        "max_file_bytes": {
                            "type": "integer",
                            "minimum": 1000,
                            "maximum": 1000000,
                            "description": "Maximum bytes to read from each text file.",
                        },
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
                handler=scan_local_files,
            ),
            ToolSpec(
                name="detect_prompt_injection_patterns",
                description=(
                    "Analyze loaded prompt/config files for prompt-injection, jailbreak, "
                    "and context-authority risks."
                ),
                parameters={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                handler=detect_prompt_injection_patterns,
            ),
            ToolSpec(
                name="analyze_tool_permissions",
                description=(
                    "Analyze loaded code and tool schemas for dangerous permissions such as "
                    "shell execution, destructive writes, network egress, and missing approvals."
                ),
                parameters={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                handler=analyze_tool_permissions,
            ),
            ToolSpec(
                name="generate_security_report",
                description=(
                    "Generate a local Markdown report with findings, evidence, severity counts, "
                    "tool-calling trace, and remediation steps."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "output_path": {
                            "type": "string",
                            "description": "Optional Markdown path to write the report to.",
                        }
                    },
                    "additionalProperties": False,
                },
                handler=generate_security_report,
            ),
        ]
    )


def scan_local_files(arguments: dict[str, Any], session: ScanSession) -> ToolResult:
    target_arg = arguments.get("target") or session.target
    max_file_bytes = int(arguments.get("max_file_bytes") or MAX_DEFAULT_FILE_BYTES)
    target = Path(target_arg).expanduser().resolve()
    session.target = str(target)

    if not target.exists():
        session.files = []
        return ToolResult(f"Target does not exist: {target}", {"files": 0})

    root = target if target.is_dir() else target.parent
    paths = _iter_candidate_files(target)
    files: list[FileRecord] = []
    skipped_large = 0
    skipped_decode = 0

    for path in paths:
        try:
            if path.stat().st_size > max_file_bytes:
                skipped_large += 1
                continue
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = path.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError:
                skipped_decode += 1
                continue
        except OSError:
            skipped_decode += 1
            continue

        files.append(
            FileRecord(
                path=str(path),
                relative_path=normalize_path_for_display(path, root),
                kind=classify_file(path),
                content=content,
            )
        )

    session.files = files
    by_kind: dict[str, int] = {}
    for file_record in files:
        by_kind[file_record.kind] = by_kind.get(file_record.kind, 0) + 1
    stats = ", ".join(f"{kind}={count}" for kind, count in sorted(by_kind.items())) or "none"
    return ToolResult(
        f"Scanned {len(files)} readable files ({stats}); skipped_large={skipped_large}, skipped_decode={skipped_decode}.",
        {"file_count": len(files), "by_kind": by_kind},
    )


def detect_prompt_injection_patterns(arguments: dict[str, Any], session: ScanSession) -> ToolResult:
    del arguments
    findings: list[Finding] = []
    for file_record in session.files:
        findings.extend(scan_file_for_rules(file_record, PROMPT_INJECTION_RULES))
        findings.extend(scan_file_for_rules(file_record, SECRET_PATTERN_RULES))
    fresh = _dedupe_findings(findings)
    session.findings.extend(fresh)
    return ToolResult(
        f"Detected {len(fresh)} prompt-injection or secret-hygiene signals.",
        {"finding_count": len(fresh)},
    )


def analyze_tool_permissions(arguments: dict[str, Any], session: ScanSession) -> ToolResult:
    del arguments
    findings: list[Finding] = []
    for file_record in session.files:
        raw_findings = scan_file_for_rules(file_record, TOOL_PERMISSION_RULES)
        for finding in raw_findings:
            if finding.rule_id == "PSH104" and finding.evidence:
                evidence = finding.evidence[0]
                if has_nearby_guard(file_record.content, evidence.line):
                    continue
            findings.append(finding)

    existing_keys = {
        (finding.rule_id, finding.evidence[0].file, finding.evidence[0].line)
        for finding in session.findings
        if finding.evidence
    }
    fresh = [
        finding
        for finding in _dedupe_findings(findings)
        if finding.evidence
        and (
            finding.rule_id,
            finding.evidence[0].file,
            finding.evidence[0].line,
        )
        not in existing_keys
    ]
    session.findings.extend(fresh)
    return ToolResult(
        f"Detected {len(fresh)} tool-permission or agent-capability signals.",
        {"finding_count": len(fresh)},
    )


def generate_security_report(arguments: dict[str, Any], session: ScanSession) -> ToolResult:
    output_path = str(arguments.get("output_path") or "").strip()
    session.report_markdown = render_markdown_report(session)
    if output_path:
        written = write_markdown_report(session, output_path)
        return ToolResult(
            f"Generated Markdown report at {written}.",
            {"report_path": written},
        )
    return ToolResult(
        "Generated Markdown report in memory.",
        {"report_path": ""},
    )


def _iter_candidate_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if is_probably_text(target) else []

    paths: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if is_probably_text(path):
            paths.append(path)
    return sorted(paths)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    output: list[Finding] = []
    for finding in findings:
        if not finding.evidence:
            output.append(finding)
            continue
        evidence = finding.evidence[0]
        key = (finding.rule_id, evidence.file, evidence.line)
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
    return output


def tool_schema_json(registry: ToolRegistry | None = None) -> str:
    active = registry or build_default_registry()
    return json.dumps(active.to_openai_tools(), indent=2, ensure_ascii=False)
