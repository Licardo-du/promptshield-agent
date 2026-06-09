from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from . import __version__
from .agent import PromptShieldAgent
from .schemas import SEVERITY_RANK, ScanSession
from .tools import build_default_registry


WIDTH = 92
DEFAULT_REPORT = "promptshield-report.md"


class Colors:
    def __init__(self) -> None:
        enabled = os.getenv("NO_COLOR") is None
        self.reset = "\033[0m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.magenta = "\033[35m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""


C = Colors()


BANNER = r"""
   ____                            _    ____  _     _      _     _
  |  _ \ _ __ ___  _ __ ___  _ __ | |_ / ___|| |__ (_) ___| | __| |
  | |_) | '__/ _ \| '_ ` _ \| '_ \| __|\___ \| '_ \| |/ _ \ |/ _` |
  |  __/| | | (_) | | | | | | |_) | |_  ___) | | | | |  __/ | (_| |
  |_|   |_|  \___/|_| |_| |_| .__/ \__||____/|_| |_|_|\___|_|\__,_|
                            |_|
"""


def run_ui(
    default_target: str = "examples/vulnerable_agent",
    use_llm: bool = False,
    require_llm: bool = False,
    smoke_test: bool = False,
) -> int:
    last_report = Path(DEFAULT_REPORT).resolve()
    while True:
        render_home(default_target, use_llm=use_llm, require_llm=require_llm)
        if smoke_test:
            return 0

        choice = input(f"{C.cyan}PromptShield>{C.reset} ").strip().lower()
        if choice in {"0", "q", "quit", "exit"}:
            print("Goodbye.")
            return 0
        if choice == "1":
            last_report = run_scan_view(default_target, use_llm=False, require_llm=False)
        elif choice == "2":
            target = input("Target path: ").strip().strip('"')
            if target:
                last_report = run_scan_view(target, use_llm=False, require_llm=False)
        elif choice == "3":
            last_report = run_scan_view(default_target, use_llm=True, require_llm=True)
        elif choice == "4":
            target = input("Target path: ").strip().strip('"')
            if target:
                last_report = run_scan_view(target, use_llm=True, require_llm=True)
        elif choice == "5":
            render_tools_view()
        elif choice == "6":
            render_report_preview(last_report)
        else:
            print(f"{C.yellow}Unknown option. Press Enter to continue.{C.reset}")
            input()


def launch_ui_new_window(
    default_target: str = "examples/vulnerable_agent",
    use_llm: bool = False,
    require_llm: bool = False,
) -> int:
    if os.name != "nt":
        print("launch-ui is only supported on Windows. Run `python -m promptshield ui` instead.")
        return 1

    args = [
        "-m",
        "promptshield",
        "ui",
        "--target",
        default_target,
    ]
    if use_llm:
        args.append("--llm")
    if require_llm:
        args.append("--require-llm")

    python_cmd = " ".join([_ps_quote(sys.executable), *(_ps_quote(arg) for arg in args)])
    command = f"& {python_cmd}"
    params = f"-NoExit -Command {_ps_quote(command)}"
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "open",
        "powershell.exe",
        params,
        str(Path.cwd()),
        1,
    )
    if result <= 32:
        print(f"Failed to launch PowerShell window. ShellExecuteW returned {result}.")
        return 1
    return 0


def render_home(default_target: str, use_llm: bool, require_llm: bool) -> None:
    clear_screen()
    print(f"{C.cyan}{BANNER}{C.reset}")
    print(center_text(f"PromptShield / v{__version__}", WIDTH))
    print(center_text("AI-agent prompt-injection and tool-misuse scanner", WIDTH))
    print()

    api_state = "configured" if os.getenv("DEEPSEEK_API_KEY") else "missing"
    api_color = C.green if api_state == "configured" else C.yellow
    default_mode = "DeepSeek required" if use_llm and require_llm else "offline"
    render_box(
        "Status",
        [
            ("Workspace", str(Path.cwd())),
            ("Default target", default_target),
            ("Default mode", default_mode),
            ("DeepSeek API", f"{api_color}{api_state}{C.reset}"),
            ("Model", os.getenv("DEEPSEEK_MODEL", "deepseek-chat")),
            ("Tools", str(len(build_default_registry().names()))),
        ],
    )
    render_box(
        "Actions",
        [
            ("1", "Scan default target (offline)"),
            ("2", "Scan custom target (offline)"),
            ("3", "Scan default target with DeepSeek function calling"),
            ("4", "Scan custom target with DeepSeek function calling"),
            ("5", "Show function-calling tool schemas"),
            ("6", "Preview last Markdown report"),
            ("0", "Exit"),
        ],
    )


def run_scan_view(target: str, use_llm: bool, require_llm: bool) -> Path:
    clear_screen()
    print(f"{C.cyan}{BANNER}{C.reset}")
    mode = "DeepSeek function calling" if use_llm else "offline deterministic"
    print(f"{C.bold}Running scan{C.reset}")
    print(f"Target: {target}")
    print(f"Mode:   {mode}")
    print()
    print(f"{C.magenta}Thinking... calling tools and building report.{C.reset}")
    print()

    report_path = Path(DEFAULT_REPORT).resolve()
    agent = PromptShieldAgent()
    try:
        session = agent.scan(target, output_path=report_path, use_llm=use_llm, require_llm=require_llm)
    except RuntimeError as exc:
        render_box("Error", [("PromptShield", str(exc))], accent=C.red)
        pause()
        return report_path

    render_scan_result(session)
    pause()
    return report_path


def render_scan_result(session: ScanSession) -> None:
    severity = session.finding_counts()
    render_box(
        "Scan Summary",
        [
            ("Orchestration", session.orchestration_mode),
            ("LLM used", str(session.llm_used)),
            ("Target", session.target),
            ("Files scanned", str(len(session.files))),
            ("Findings", str(len(session.findings))),
            ("Report", session.report_path or "(in memory)"),
        ],
    )
    if session.warnings:
        render_box("Warnings", [(str(i + 1), warning) for i, warning in enumerate(session.warnings)], accent=C.yellow)

    render_box(
        "Tool Calling Trace",
        [
            (str(index), f"[{call.source}] {call.name} -> {call.result_summary}")
            for index, call in enumerate(session.tool_calls, start=1)
        ],
    )
    render_box(
        "Severity",
        [(name, str(severity.get(name, 0))) for name in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True)],
    )
    top_findings = []
    for finding in session.sorted_findings()[:6]:
        evidence = finding.evidence[0] if finding.evidence else None
        location = f"{evidence.file}:{evidence.line}" if evidence else "n/a"
        top_findings.append((finding.severity.upper(), f"{finding.rule_id} {finding.title} ({location})"))
    if top_findings:
        render_box("Top Findings", top_findings, accent=C.red)


def render_tools_view() -> None:
    clear_screen()
    print(f"{C.cyan}{BANNER}{C.reset}")
    registry = build_default_registry()
    render_box(
        "Function Tools",
        [(name, registry._specs[name].description) for name in registry.names()],
    )
    pause()


def render_report_preview(report_path: Path) -> None:
    clear_screen()
    print(f"{C.cyan}{BANNER}{C.reset}")
    if not report_path.exists():
        render_box("Report Preview", [("Status", f"No report found at {report_path}")], accent=C.yellow)
        pause()
        return

    lines = report_path.read_text(encoding="utf-8", errors="replace").splitlines()
    preview = lines[:28]
    render_box("Report Preview", [("Path", str(report_path)), ("Lines", str(len(lines)))])
    for line in preview:
        print(line[:WIDTH])
    if len(lines) > len(preview):
        print(C.dim + f"... {len(lines) - len(preview)} more lines" + C.reset)
    pause()


def clear_screen() -> None:
    print("\033[2J\033[H", end="")


def pause() -> None:
    input(f"\n{C.dim}Press Enter to return to menu...{C.reset}")


def render_box(title: str, rows: list[tuple[str, str]], accent: str = "") -> None:
    top_label = f" {title} "
    left = max(1, (WIDTH - len(top_label) - 2) // 2)
    right = WIDTH - len(top_label) - left - 2
    print(f"{accent}+{'-' * left}{top_label}{'-' * right}+{C.reset}")
    for key, value in rows:
        value_width = WIDTH - 4 - 17
        wrapped = wrap_text(value, value_width)
        for index, line in enumerate(wrapped):
            prefix = f"{key:<16} " if index == 0 else " " * 17
            print(f"| {pad_ansi(prefix + line, WIDTH - 4)} |")
    print(f"{accent}+{'-' * (WIDTH - 2)}+{C.reset}")
    print()


def wrap_text(text: str, width: int) -> list[str]:
    clean = strip_ansi(text)
    if len(clean) <= width:
        return [text]
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(strip_ansi(word)) > width:
            if current:
                lines.append(current)
                current = ""
            lines.extend(chunk_long_word(word, width))
            continue
        candidate = word if not current else f"{current} {word}"
        if len(strip_ansi(candidate)) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [text[:width]]


def chunk_long_word(word: str, width: int) -> list[str]:
    chunks: list[str] = []
    remaining = word
    while len(remaining) > width:
        chunks.append(remaining[:width])
        remaining = remaining[width:]
    if remaining:
        chunks.append(remaining)
    return chunks


def center_text(text: str, width: int) -> str:
    return f"{C.dim}{text.center(width)}{C.reset}"


def pad_ansi(text: str, width: int) -> str:
    padding = max(0, width - len(strip_ansi(text)))
    return text + (" " * padding)


def strip_ansi(text: str) -> str:
    result = ""
    in_escape = False
    for char in text:
        if char == "\033":
            in_escape = True
            continue
        if in_escape:
            if char.isalpha():
                in_escape = False
            continue
        result += char
    return result


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
