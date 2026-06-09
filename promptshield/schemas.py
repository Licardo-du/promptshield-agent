from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class FileRecord:
    path: str
    relative_path: str
    kind: str
    content: str

    @property
    def line_count(self) -> int:
        return len(self.content.splitlines())


@dataclass(slots=True)
class Evidence:
    file: str
    line: int
    snippet: str
    matched: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "matched": self.matched,
        }


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(slots=True)
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result_summary: str
    source: str = "local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "result_summary": self.result_summary,
            "source": self.source,
        }


@dataclass(slots=True)
class ScanSession:
    target: str
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    report_markdown: str = ""
    report_path: str = ""
    warnings: list[str] = field(default_factory=list)
    orchestration_mode: str = "offline deterministic"
    llm_requested: bool = False
    llm_used: bool = False
    llm_provider: str = ""
    llm_model: str = ""
    llm_api_base: str = ""
    llm_turns: int = 0

    def add_tool_call(
        self,
        name: str,
        arguments: dict[str, Any],
        result_summary: str,
        source: str = "local",
    ) -> None:
        self.tool_calls.append(ToolCallRecord(name, dict(arguments), result_summary, source))

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def finding_counts(self) -> dict[str, int]:
        counts = {key: 0 for key in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (
                -SEVERITY_RANK.get(item.severity, 0),
                item.rule_id,
                item.evidence[0].file if item.evidence else "",
                item.evidence[0].line if item.evidence else 0,
            ),
        )


def normalize_path_for_display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
