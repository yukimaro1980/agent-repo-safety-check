from __future__ import annotations

from pathlib import Path

from .models import Finding, ScanProfile, ScanResult
from .scanners import agents, github_actions, local_secrets, node, repo_hygiene, vscode


def run_scan(target: Path, scanned_at: str, profile: ScanProfile = "agent") -> ScanResult:
    result = ScanResult(target=str(target), scanned_at=scanned_at, profile=profile)

    scanners = [
        node.scan,
        agents.scan,
        vscode.scan,
        github_actions.scan,
        local_secrets.scan,
    ]
    if profile == "oss":
        scanners.insert(4, repo_hygiene.scan)
    else:
        result.checked_items["repo hygiene"] = "skipped; use --profile oss"

    for scanner in scanners:
        scanner(target, result)

    checked_summary = "; ".join(f"{key}={value}" for key, value in result.checked_items.items())
    result.findings.insert(
        0,
        Finding(
            severity="INFO",
            title="Read-only scan completed",
            path=".",
            evidence=f"Profile={profile}; checked items: {checked_summary}",
            risk="この結果は危険確定ではなく、ローカル確認候補の一覧です。",
            check_method="対象ディレクトリ内の設定ファイル名と安全に読める設定内容のみを確認しました。",
            next_action="HIGH / MEDIUM の項目から順に、意図した設定かを手元で確認してください。",
        ),
    )
    return result
