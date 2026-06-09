from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .deepseek_client import DeepSeekClient, DeepSeekConfigError
from .schemas import ScanSession
from .tools import ToolRegistry, build_default_registry


SYSTEM_PROMPT = """You are PromptShield, a narrow AI-agent security scanner.

Your job is to orchestrate local tools through function calling. You must not
ask the user for secrets, API keys, passwords, tokens, or private files.

Use this workflow unless the user asks for a different scan:
1. scan_local_files
2. detect_prompt_injection_patterns
3. analyze_tool_permissions
4. generate_security_report

Privacy rule: tool results are summaries. Do not request raw file contents.
The local tools generate the detailed report on disk.
"""


class PromptShieldAgent:
    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or build_default_registry()

    def scan(
        self,
        target: str | Path,
        output_path: str | Path | None = None,
        use_llm: bool = False,
        require_llm: bool = False,
    ) -> ScanSession:
        session = ScanSession(target=str(Path(target).expanduser().resolve()))
        if use_llm:
            session.llm_requested = True
            try:
                self._scan_with_llm(session, output_path)
            except (DeepSeekConfigError, RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
                if require_llm:
                    raise RuntimeError(f"LLM orchestration was required but failed: {exc}") from exc
                session.orchestration_mode = "offline deterministic fallback"
                session.add_warning(f"LLM orchestration failed; fell back to deterministic offline scan. Reason: {exc}")
                self._scan_offline(session, output_path, source="fallback")
        else:
            self._scan_offline(session, output_path, source="offline")
        return session

    def _scan_offline(
        self,
        session: ScanSession,
        output_path: str | Path | None,
        source: str,
    ) -> None:
        if source == "offline":
            session.orchestration_mode = "offline deterministic"
        self.registry.call(
            "scan_local_files",
            {"target": session.target, "max_file_bytes": 200_000},
            session,
            source=source,
        )
        self.registry.call("detect_prompt_injection_patterns", {}, session, source=source)
        self.registry.call("analyze_tool_permissions", {}, session, source=source)
        report_args = {"output_path": str(output_path)} if output_path else {}
        self.registry.call("generate_security_report", report_args, session, source=source)

    def _scan_with_llm(self, session: ScanSession, output_path: str | Path | None) -> None:
        client = DeepSeekClient.from_env()
        session.orchestration_mode = "llm function calling"
        session.llm_used = True
        session.llm_provider = "DeepSeek/OpenAI-compatible"
        session.llm_model = client.model
        session.llm_api_base = client.api_base
        output_instruction = str(output_path) if output_path else "(no output path requested)"
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Scan this local target for AI-agent security risks: {session.target}\n"
                    f"Markdown output path: {output_instruction}\n"
                    "Call tools until the report has been generated."
                ),
            },
        ]
        tools = self.registry.to_openai_tools()

        called_names: list[str] = []
        for _ in range(8):
            response = client.chat(messages, tools)
            session.llm_turns += 1
            message = response["choices"][0]["message"]
            messages.append(message)
            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                break

            for tool_call in tool_calls:
                function = tool_call.get("function", {})
                name = function.get("name")
                if not name:
                    continue
                raw_arguments = function.get("arguments") or "{}"
                arguments = json.loads(raw_arguments)
                if name == "scan_local_files" and not arguments.get("target"):
                    arguments["target"] = session.target
                if name == "generate_security_report" and output_path and not arguments.get("output_path"):
                    arguments["output_path"] = str(output_path)
                result = self.registry.call(name, arguments, session, source="deepseek")
                called_names.append(name)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", name),
                        "name": name,
                        "content": result.public_summary,
                    }
                )

        # Make API mode reliable for demos even if the model stops early.
        if "scan_local_files" not in called_names:
            self.registry.call(
                "scan_local_files",
                {"target": session.target, "max_file_bytes": 200_000},
                session,
                source="safety-backfill",
            )
        if "detect_prompt_injection_patterns" not in called_names:
            self.registry.call("detect_prompt_injection_patterns", {}, session, source="safety-backfill")
        if "analyze_tool_permissions" not in called_names:
            self.registry.call("analyze_tool_permissions", {}, session, source="safety-backfill")
        if "generate_security_report" not in called_names:
            report_args = {"output_path": str(output_path)} if output_path else {}
            self.registry.call("generate_security_report", report_args, session, source="safety-backfill")
