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
                risk="folderOpen 自動実行や shell task の確認が不足する可能性があります。",
                check_method=".vscode/tasks.json を JSON として読み込みました。",
                next_action="コメントや末尾カンマを含む場合は後続で JSONC parser 対応を検討してください。",
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
                    risk="フォルダを開いただけでタスクが自動実行される可能性があります。",
                    check_method=".vscode/tasks.json の runOptions.runOn を確認しました。",
                    next_action="自動実行が必要なタスクか、実行コマンドが安全か確認してください。",
                )
            )

        if terms:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title=f"VS Code task command needs review: {task_name}",
                    path=display_path(target, tasks_path),
                    evidence="matched command terms: " + ", ".join(terms),
                    risk="shell やネットワーク取得、npm/npx 実行を含む可能性があります。コマンド値そのものは出力していません。",
                    check_method=".vscode/tasks.json の task 定義を語句ベースで確認しました。",
                    next_action="該当 task の command / args を手元で確認してください。",
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
