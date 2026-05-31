from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from ..models import Finding, ScanResult, display_path
from ..redact import matched_terms

AGENT_DIRS = (".claude", ".codex")
INTERESTING_NAMES = ("settings.json", "config.toml", "agents", "hooks", "commands")
EXECUTION_TERMS = [
    "hook",
    "hooks",
    "command",
    "commands",
    "shell",
    "bash",
    "powershell",
    "cmd.exe",
    "curl",
    "invoke-webrequest",
    "iwr",
    "npm",
    "npx",
    "node -e",
]
STRUCTURED_KEYS = {
    "command",
    "commands",
    "args",
    "env",
    "environment",
    "hooks",
    "mcpservers",
    "mcp_servers",
    "permissions",
    "allow",
    "deny",
}


def scan(target: Path, result: ScanResult) -> None:
    for dirname in AGENT_DIRS:
        directory = target / dirname
        result.checked_items[dirname] = "present" if directory.exists() else "missing"
        if not directory.exists() or not directory.is_dir():
            continue

        interesting_files = [path for path in _iter_files(directory) if _is_interesting(path)]
        if not interesting_files:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title=f"{dirname} exists",
                    path=display_path(target, directory),
                    evidence="No obvious settings/hooks/commands files were found.",
                    risk="The directory exists, but the current filename rules did not detect obvious auto-run candidates.",
                    check_method=f"Checked file names under {dirname}.",
                    next_action="Add additional filename rules later if this project uses other agent config names.",
                )
            )
            continue

        for path in interesting_files:
            text = _read_small_text(path)
            terms = sorted(set(matched_terms(text.lower() + " " + path.name.lower(), EXECUTION_TERMS)))
            severity = "MEDIUM" if terms else "INFO"
            result.findings.append(
                Finding(
                    severity=severity,
                    title=f"AI agent config candidate: {display_path(target, path)}",
                    path=display_path(target, path),
                    evidence="matched execution-related terms: " + (", ".join(terms) if terms else "none"),
                    risk="AI agent hooks or commands may call external commands. Values are not printed.",
                    check_method="Checked file names and limited text matches for auto-run or external-command terms.",
                    next_action="Review the file locally and confirm only intended hooks or commands are defined.",
                )
            )
            structured = _structured_config_summary(path, text)
            if structured:
                result.findings.append(
                    Finding(
                        severity="MEDIUM",
                        title=f"AI agent structured config needs review: {display_path(target, path)}",
                        path=display_path(target, path),
                        evidence=structured,
                        risk="The config may define MCP servers, hooks, commands, env keys, or permissions. Values are not printed.",
                        check_method="Parsed TOML/JSON settings and checked only key paths related to execution, permissions, or environment variables.",
                        next_action="Review the intent, allowed commands, external integrations, and environment variable sources locally.",
                    )
                )


def _iter_files(directory: Path) -> list[Path]:
    ignored = {".git", "node_modules", ".venv", "venv", "__pycache__"}
    files: list[Path] = []
    for path in directory.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def _is_interesting(path: Path) -> bool:
    lowered = str(path).lower()
    return any(name in lowered for name in INTERESTING_NAMES)


def _read_small_text(path: Path, limit: int = 250_000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _structured_config_summary(path: Path, text: str) -> str:
    data = _parse_structured(path, text)
    if data is None:
        return ""
    matches = _structured_matches(data)
    if not matches:
        return ""
    shown = matches[:16]
    suffix = "" if len(matches) <= len(shown) else f"; +{len(matches) - len(shown)} more"
    return "matched structured keys: " + ", ".join(shown) + suffix + "; values not printed"


def _parse_structured(path: Path, text: str) -> Any | None:
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            return tomllib.loads(text)
        if suffix == ".json":
            return json.loads(_strip_jsonc_comments(text))
    except Exception:
        return None
    return None


def _structured_matches(data: Any) -> list[str]:
    matches: list[str] = []

    def walk(value: Any, trail: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                next_trail = trail + (key_text,)
                if lowered in STRUCTURED_KEYS or lowered in EXECUTION_TERMS:
                    matches.append(".".join(next_trail))
                walk(child, next_trail)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, trail + (f"[{index}]",))
        elif isinstance(value, str):
            lowered_value = value.lower()
            terms = matched_terms(lowered_value, EXECUTION_TERMS)
            if terms:
                matches.append(".".join(trail) + " contains " + "/".join(sorted(set(terms))))

    walk(data, ())
    deduped: list[str] = []
    for match in matches:
        if match not in deduped:
            deduped.append(match)
    return deduped


def _strip_jsonc_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)
