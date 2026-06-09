from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class DeepSeekConfigError(RuntimeError):
    """Raised when DeepSeek API mode is requested without enough configuration."""


@dataclass(slots=True)
class DeepSeekClient:
    api_key: str
    api_base: str
    model: str
    timeout: int = 60

    @classmethod
    def from_env(cls) -> "DeepSeekClient":
        api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            raise DeepSeekConfigError(
                "DEEPSEEK_API_KEY is not set. Use offline mode or configure the environment variable."
            )

        api_base = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com").strip().rstrip("/")
        model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip()
        timeout = int(os.getenv("DEEPSEEK_TIMEOUT", "60"))
        return cls(api_key=api_key, api_base=api_base, model=model, timeout=timeout)

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        url = f"{self.api_base}/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"DeepSeek API HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"DeepSeek API request failed: {exc}") from exc
