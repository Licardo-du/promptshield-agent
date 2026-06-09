from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .agent import PromptShieldAgent
from .report import render_json_report
from .schemas import SEVERITY_RANK, ScanSession
from .tools import build_default_registry, tool_schema_json
from .ui import launch_ui_new_window, run_ui


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list-tools":
        registry = build_default_registry()
        print(tool_schema_json(registry))
        return 0

    if args.command == "scan":
        if args.require_llm and not args.llm:
            print("PromptShield error: --require-llm must be used together with --llm.")
            return 2
        agent = PromptShieldAgent()
        try:
            session = agent.scan(
                args.target,
                output_path=args.output,
                use_llm=args.llm,
                require_llm=args.require_llm,
            )
        except RuntimeError as exc:
            print(f"PromptShield error: {exc}")
            return 2
        if args.json:
            print(render_json_report(session))
        else:
            print_terminal_summary(session)
        return 1 if args.fail_on_findings and session.findings else 0

    if args.command == "ui":
        if args.require_llm and not args.llm:
            print("PromptShield error: --require-llm must be used together with --llm.")
            return 2
        return run_ui(
            default_target=args.target,
            use_llm=args.llm,
            require_llm=args.require_llm,
            smoke_test=args.smoke_test,
        )

    if args.command == "launch-ui":
        if args.require_llm and not args.llm:
            print("PromptShield error: --require-llm must be used together with --llm.")
            return 2
        return launch_ui_new_window(
            default_target=args.target,
            use_llm=args.llm,
            require_llm=args.require_llm,
        )

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Scan AI-agent prompts, tools, and configs for prompt-injection and tool-misuse risks.",
    )
    parser.add_argument("--version", action="version", version=f"PromptShield {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a local file or directory.")
    scan_parser.add_argument("target", help="Local file or directory to scan.")
    scan_parser.add_argument(
        "-o",
        "--output",
        default="promptshield-report.md",
        help="Markdown report path. Defaults to promptshield-report.md.",
    )
    scan_parser.add_argument(
        "--llm",
        action="store_true",
        help="Use DeepSeek/OpenAI-compatible function calling to orchestrate tools.",
    )
    scan_parser.add_argument(
        "--require-llm",
        action="store_true",
        help="Fail instead of falling back to offline mode when LLM orchestration fails.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the terminal summary.",
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when any finding is detected.",
    )

    subparsers.add_parser("list-tools", help="Print the function-calling tool schemas.")

    ui_parser = subparsers.add_parser("ui", help="Open the interactive terminal UI.")
    ui_parser.add_argument(
        "--target",
        default="examples/vulnerable_agent",
        help="Default target shown in the UI.",
    )
    ui_parser.add_argument(
        "--llm",
        action="store_true",
        help="Use DeepSeek/OpenAI-compatible function calling as the default UI mode.",
    )
    ui_parser.add_argument(
        "--require-llm",
        action="store_true",
        help="Fail instead of falling back to offline mode when LLM orchestration fails.",
    )
    ui_parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Render the UI once and exit. Useful for automated checks.",
    )

    launch_parser = subparsers.add_parser("launch-ui", help="Open the interactive UI in a new Windows terminal window.")
    launch_parser.add_argument(
        "--target",
        default="examples/vulnerable_agent",
        help="Default target shown in the UI.",
    )
    launch_parser.add_argument(
        "--llm",
        action="store_true",
        help="Use DeepSeek/OpenAI-compatible function calling as the default UI mode.",
    )
    launch_parser.add_argument(
        "--require-llm",
        action="store_true",
        help="Fail instead of falling back to offline mode when LLM orchestration fails.",
    )
    return parser


def print_terminal_summary(session: ScanSession) -> None:
    print("=" * 78)
    print(f"PromptShield / v{__version__}")
    print("AI-agent prompt-injection and tool-misuse scanner")
    print("=" * 78)
    print(f"Orchestration: {session.orchestration_mode}")
    if session.llm_used:
        print(f"LLM: {session.llm_provider} / {session.llm_model}")
        print(f"LLM turns: {session.llm_turns}")
    print(f"Target: {session.target}")
    print(f"Files scanned: {len(session.files)}")
    print(f"Findings: {len(session.findings)}")
    if session.report_path:
        print(f"Report: {Path(session.report_path)}")
    print()

    if session.warnings:
        print("Warnings")
        for warning in session.warnings:
            print(f"- {warning}")
        print()

    print("Tool Calling Trace")
    for index, call in enumerate(session.tool_calls, start=1):
        compact_args = json.dumps(call.arguments, ensure_ascii=False)
        print(f"{index}. [{call.source}] {call.name}({compact_args})")
        print(f"   -> {call.result_summary}")
    print()

    counts = session.finding_counts()
    print("Severity Summary")
    for severity in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True):
        print(f"- {severity:8s}: {counts.get(severity, 0)}")
    print()

    if not session.findings:
        print("No findings matched the current rules.")
        return

    print("Top Findings")
    for finding in session.sorted_findings()[:8]:
        evidence = finding.evidence[0] if finding.evidence else None
        location = f"{evidence.file}:{evidence.line}" if evidence else "n/a"
        print(f"- [{finding.severity.upper()}] {finding.rule_id} {finding.title} ({location})")
    if len(session.findings) > 8:
        print(f"... {len(session.findings) - 8} more findings in the Markdown report.")
