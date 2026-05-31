from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Finding, ScanResult, display_path
from ..redact import matched_terms

COMMAND_TERMS = ["shell", "powershell", "curl", "invoke-webrequest", "iwr", "npm install", "npx", "node -e"]


def scan(target: Path, result: ScanResult) -> None:
    tasks_path = target / ".vscode" / "tasks.json"
    result.checked_items[".vscode/tasks.json"] = "present" if tasks_path.exists() else "missing"
    if not tasks_path.exists():
        return

    try:
        text = tasks_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(_strip_jsonc_comments(text))
    except Exception as exc:
        result.findings.append(
            Finding(
                severity="LOW",
                title="VS Code tasks.json could not be parsed",
                path=display_path(target, tasks_path),
                evidence=f"parse failed: {type(exc).__name__}",
                risk="folderOpen auto-run or shell task checks may be incomplete.",
                check_method="Tried to read .vscode/tasks.json as JSON.",
                next_action="If the file uses comments or trailing commas, consider JSONC parser support later.",
            )
        )
        return

    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    if not isinstance(tasks, list):
        return

    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        task_name = str(task.get("label") or f"task[{index}]")
        run_on = _deep_get(task, ["runOptions", "runOn"])
        flat_text = str(task).lower()
        terms = sorted(set(matched_terms(flat_text, COMMAND_TERMS)))

        if run_on == "folderOpen":
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title=f"VS Code task runs on folder open: {task_name}",
                    path=display_path(target, tasks_path),
                    evidence="runOptions.runOn=folderOpen",
                    risk="The task may run automatically when the folder is opened.",
                    check_method="Checked runOptions.runOn in .vscode/tasks.json.",
                    next_action="Confirm auto-run is needed and the command is safe.",
                )
            )

        if terms:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title=f"VS Code task command needs review: {task_name}",
                    path=display_path(target, tasks_path),
                    evidence="matched command terms: " + ", ".join(terms),
                    risk="The task may include shell execution, network fetches, or npm/npx execution. Command values are not printed.",
                    check_method="Checked task definitions with term-based matching.",
                    next_action="Review the task command and args locally.",
                )
            )


def _deep_get(data: dict[str, Any], keys: list[str]) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _strip_jsonc_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)
