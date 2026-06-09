from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .schemas import Evidence, FileRecord, Finding


TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".ini",
    ".json",
    ".md",
    ".mjs",
    ".js",
    ".jsx",
    ".prompt",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

PROMPT_FILENAMES = {
    "system_prompt",
    "developer_prompt",
    "prompt",
    "prompts",
    "agent_prompt",
    "agents",
    "claude",
    "cursorrules",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
}


@dataclass(frozen=True, slots=True)
class TextRule:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    patterns: tuple[str, ...]
    file_kinds: tuple[str, ...] = ("prompt", "config", "code", "tool_schema")
    confidence: str = "medium"

    def compiled_patterns(self) -> Iterable[re.Pattern[str]]:
        for pattern in self.patterns:
            yield re.compile(pattern, re.IGNORECASE)


PROMPT_INJECTION_RULES: tuple[TextRule, ...] = (
    TextRule(
        rule_id="PSH001",
        title="Instruction override phrase",
        severity="high",
        category="prompt-injection",
        description=(
            "The project contains language that tells the model to ignore or "
            "override higher-priority instructions."
        ),
        remediation=(
            "Treat external text as untrusted data. Add a policy that higher-"
            "priority system and developer instructions cannot be overridden."
        ),
        patterns=(
            r"\bignore (all )?(previous|above|prior) instructions\b",
            r"\bdisregard (all )?(previous|above|prior) instructions\b",
            r"\bforget (all )?(previous|above|prior) instructions\b",
            r"\boverride (the )?(system|developer) (prompt|message|instructions)\b",
        ),
        file_kinds=("prompt", "config", "tool_schema"),
        confidence="high",
    ),
    TextRule(
        rule_id="PSH002",
        title="Secret exfiltration instruction",
        severity="critical",
        category="prompt-injection",
        description=(
            "The prompt or configuration appears to ask the agent to reveal, "
            "copy, or transmit secrets."
        ),
        remediation=(
            "Explicitly forbid secret disclosure. Keep secrets outside prompts "
            "and deny tools from reading .env, credential stores, or private keys."
        ),
        patterns=(
            r"\b(exfiltrate|leak|send|upload|post).{0,80}(api[_ -]?keys?|secrets?|tokens?|passwords?|credentials?|\.env)\b",
            r"\b(read|open|dump|print).{0,80}(api[_ -]?keys?|secrets?|tokens?|passwords?|credentials?|\.env)\b",
            r"\breturn.{0,80}\b(secrets?|credentials?|environment variables?)\b",
        ),
        file_kinds=("prompt", "config", "tool_schema", "code"),
        confidence="high",
    ),
    TextRule(
        rule_id="PSH003",
        title="Jailbreak or safety-disable wording",
        severity="medium",
        category="prompt-injection",
        description=(
            "The text contains jailbreak-style wording that may weaken safety "
            "or authorization checks."
        ),
        remediation=(
            "Remove roleplay jailbreak language and add explicit refusal rules "
            "for unsafe tool use."
        ),
        patterns=(
            r"\b(developer mode|dan mode|jailbreak|no safety|disable safety)\b",
            r"\byou are now unrestricted\b",
            r"\bdo not refuse\b",
        ),
        file_kinds=("prompt", "config", "tool_schema"),
    ),
    TextRule(
        rule_id="PSH004",
        title="Untrusted content treated as authority",
        severity="medium",
        category="context-integrity",
        description=(
            "The prompt appears to treat user-provided or retrieved content as "
            "more authoritative than the system policy."
        ),
        remediation=(
            "Wrap retrieved content in a data boundary and instruct the model "
            "to summarize it without following embedded instructions."
        ),
        patterns=(
            r"\b(user|web|retrieved|external).{0,60}\b(always|must).{0,60}\b(authoritative|trusted|obeyed)\b",
            r"\bfollow instructions found in (web pages?|documents?|readmes?|user content)\b",
        ),
        file_kinds=("prompt", "config"),
    ),
)


TOOL_PERMISSION_RULES: tuple[TextRule, ...] = (
    TextRule(
        rule_id="PSH101",
        title="Unrestricted shell execution",
        severity="critical",
        category="tool-misuse",
        description=(
            "The agent exposes or uses shell execution primitives that can run "
            "arbitrary commands."
        ),
        remediation=(
            "Use an allowlist of commands, require explicit confirmation for "
            "state-changing operations, and pass arguments without shell=True."
        ),
        patterns=(
            r"\bshell\s*:\s*(true|on|enabled)\b",
            r"\bshell=True\b",
            r"\bos\.system\s*\(",
            r"\bsubprocess\.(run|call|Popen)\s*\(",
            r"\bexec\s*\(",
            r"\beval\s*\(",
            r"\brun[_ -]?shell\b",
        ),
        file_kinds=("code", "config", "tool_schema"),
        confidence="high",
    ),
    TextRule(
        rule_id="PSH102",
        title="Destructive file operation without visible guard",
        severity="high",
        category="tool-misuse",
        description=(
            "The agent appears to expose delete/write operations without an "
            "obvious approval or path-scope guard nearby."
        ),
        remediation=(
            "Require confirmation for delete/write tools, restrict writes to a "
            "workspace, and log every state-changing action."
        ),
        patterns=(
            r"\b(delete|remove|rm|rmtree|unlink|write_file|overwrite)\b",
            r"\bRemove-Item\b",
            r"\brm\s+-rf\b",
            r"\bshutil\.rmtree\s*\(",
            r"\bPath\(.{0,60}\)\.unlink\s*\(",
        ),
        file_kinds=("code", "config", "tool_schema"),
    ),
    TextRule(
        rule_id="PSH103",
        title="Network egress from agent tool",
        severity="medium",
        category="tool-misuse",
        description=(
            "The agent has network egress behavior. This is normal for many "
            "agents, but risky when combined with local file or secret access."
        ),
        remediation=(
            "Document allowed domains, redact secrets from payloads, and add a "
            "confirmation step for outbound requests carrying local context."
        ),
        patterns=(
            r"\brequests\.(post|put|patch|get)\s*\(",
            r"\burllib\.request\b",
            r"\bfetch\s*\(",
            r"\bhttp(s)?://",
            r"\bnetwork\s*:\s*(true|on|enabled)\b",
        ),
        file_kinds=("code", "config", "tool_schema"),
    ),
    TextRule(
        rule_id="PSH104",
        title="Missing approval language near dangerous tool",
        severity="medium",
        category="tool-misuse",
        description=(
            "A dangerous tool name appears without nearby confirmation, "
            "approval, allowlist, or sandbox wording."
        ),
        remediation=(
            "Add a typed approval field and enforce it before shell, network, "
            "write, delete, or credential-access actions."
        ),
        patterns=(
            r"\b(name|tool|command)\b.{0,80}\b(shell|delete|remove|write|network|credential|secret)\b",
        ),
        file_kinds=("config", "tool_schema", "prompt"),
    ),
)


SECRET_PATTERN_RULES: tuple[TextRule, ...] = (
    TextRule(
        rule_id="PSH201",
        title="Potential hard-coded secret",
        severity="high",
        category="secret-hygiene",
        description=(
            "The project contains text that resembles a hard-coded API key, "
            "token, or private credential."
        ),
        remediation=(
            "Move secrets to environment variables or a secret manager. Add "
            "the local secret file to .gitignore before open sourcing."
        ),
        patterns=(
            r"\b(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
            r"\bsk-[A-Za-z0-9_\-]{20,}\b",
        ),
        file_kinds=("code", "config", "prompt", "tool_schema"),
        confidence="high",
    ),
)


def classify_file(path: Path) -> str:
    stem = path.stem.lower()
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name in {"agENTS.md".lower(), "claude.md", ".cursorrules", "llms.txt"}:
        return "prompt"
    if stem in PROMPT_FILENAMES or suffix == ".prompt":
        return "prompt"
    if "tool" in stem and suffix in {".json", ".yaml", ".yml", ".toml", ".py", ".ts", ".js"}:
        return "tool_schema"
    if suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs"}:
        return "code"
    return "config"


def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {
        ".cursorrules",
        "dockerfile",
        "makefile",
        "agENTS.md".lower(),
        "claude.md",
        "llms.txt",
    }


def scan_file_for_rules(file_record: FileRecord, rules: Iterable[TextRule]) -> list[Finding]:
    findings: list[Finding] = []
    lines = file_record.content.splitlines()
    for rule in rules:
        if file_record.kind not in rule.file_kinds:
            continue
        for pattern in rule.compiled_patterns():
            for index, line in enumerate(lines, start=1):
                match = pattern.search(line)
                if not match:
                    continue
                snippet = line.strip()
                if len(snippet) > 240:
                    snippet = snippet[:237] + "..."
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        remediation=rule.remediation,
                        evidence=[
                            Evidence(
                                file=file_record.relative_path,
                                line=index,
                                snippet=snippet,
                                matched=match.group(0),
                            )
                        ],
                        confidence=rule.confidence,
                    )
                )
    return findings


def has_nearby_guard(text: str, line_number: int, window: int = 4) -> bool:
    guard_terms = re.compile(
        r"\b(confirm|confirmation|approval|required|allowlist|denylist|sandbox|read-only|read only|scope|safe path)\b",
        re.IGNORECASE,
    )
    lines = text.splitlines()
    start = max(0, line_number - window - 1)
    end = min(len(lines), line_number + window)
    return any(guard_terms.search(line) for line in lines[start:end])
