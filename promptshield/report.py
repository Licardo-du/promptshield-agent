from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .schemas import SEVERITY_RANK, ScanSession


def render_markdown_report(session: ScanSession) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    counts = session.finding_counts()
    total_findings = sum(counts.values())
    scanned_by_kind: dict[str, int] = {}
    for file_record in session.files:
        scanned_by_kind[file_record.kind] = scanned_by_kind.get(file_record.kind, 0) + 1

    lines: list[str] = [
        "# PromptShield Security Report",
        "",
        f"- Generated: `{now}`",
        f"- Target: `{session.target}`",
        f"- Orchestration: `{session.orchestration_mode}`",
        f"- LLM used: `{session.llm_used}`",
        f"- Files scanned: `{len(session.files)}`",
        f"- Findings: `{total_findings}`",
        "",
    ]

    if session.llm_used:
        lines.extend(
            [
                "## LLM Orchestration",
                "",
                f"- Provider: `{session.llm_provider}`",
                f"- Model: `{session.llm_model}`",
                f"- API base: `{session.llm_api_base}`",
                f"- Chat turns: `{session.llm_turns}`",
                "",
            ]
        )

    lines.extend(["## Tool Calling Trace", ""])

    if session.tool_calls:
        for index, call in enumerate(session.tool_calls, start=1):
            args = json.dumps(call.arguments, ensure_ascii=False)
            lines.append(f"{index}. [`{call.source}`] `{call.name}` with `{args}` -> {call.result_summary}")
    else:
        lines.append("No tool calls were recorded.")

    if session.warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in session.warnings:
            lines.append(f"- {warning}")

    lines.extend(["", "## Scan Coverage", ""])
    if scanned_by_kind:
        for kind in sorted(scanned_by_kind):
            lines.append(f"- `{kind}`: {scanned_by_kind[kind]}")
    else:
        lines.append("- No readable files found.")

    lines.extend(["", "## Severity Summary", ""])
    for severity in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True):
        lines.append(f"- `{severity}`: {counts.get(severity, 0)}")

    lines.extend(["", "## Findings", ""])
    if not session.findings:
        lines.append("No findings. This does not prove the agent is secure; it only means PromptShield did not match its current rules.")
    else:
        for index, finding in enumerate(session.sorted_findings(), start=1):
            lines.extend(
                [
                    f"### {index}. [{finding.severity.upper()}] {finding.title}",
                    "",
                    f"- Rule: `{finding.rule_id}`",
                    f"- Category: `{finding.category}`",
                    f"- Confidence: `{finding.confidence}`",
                    f"- Why it matters: {finding.description}",
                    f"- Suggested fix: {finding.remediation}",
                    "",
                    "Evidence:",
                ]
            )
            for evidence in finding.evidence:
                lines.append(
                    f"- `{evidence.file}:{evidence.line}` matched `{evidence.matched}`: `{evidence.snippet}`"
                )
            lines.append("")

    lines.extend(
        [
            "## Recommended Next Steps",
            "",
            "1. Remove or quarantine prompt text that tells the model to ignore higher-priority instructions.",
            "2. Add typed approvals and path/domain allowlists for shell, network, write, delete, and credential-access tools.",
            "3. Keep real API keys in environment variables or a secret manager, never in committed files.",
            "4. Re-run PromptShield after each prompt or tool-schema change and keep the report with release notes.",
            "",
            "## Privacy Note",
            "",
            "Offline mode keeps all file contents local. LLM mode sends only tool-call summaries to the configured model provider; the detailed report is generated locally.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(session: ScanSession, output_path: str | Path) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(session.report_markdown, encoding="utf-8")
    session.report_path = str(path.resolve())
    return session.report_path


def render_json_report(session: ScanSession) -> str:
    payload = {
        "target": session.target,
        "orchestration_mode": session.orchestration_mode,
        "llm_requested": session.llm_requested,
        "llm_used": session.llm_used,
        "llm_provider": session.llm_provider,
        "llm_model": session.llm_model,
        "llm_api_base": session.llm_api_base,
        "llm_turns": session.llm_turns,
        "files_scanned": len(session.files),
        "finding_counts": session.finding_counts(),
        "tool_calls": [call.to_dict() for call in session.tool_calls],
        "findings": [finding.to_dict() for finding in session.sorted_findings()],
        "warnings": session.warnings,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
