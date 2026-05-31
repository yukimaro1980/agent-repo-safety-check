from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from ..models import Finding, ScanResult, display_path

SECRET_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
)
ARCHIVE_PATTERNS = (
    "*.zip",
    "*.7z",
)
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def scan(target: Path, result: ScanResult) -> None:
    candidates = [path for path in _iter_candidate_paths(target) if _matches_secret_pattern(path.name)]
    result.checked_items["local secret candidates"] = f"{len(candidates)} file(s)" if candidates else "none"
    archive_candidates = [path for path in _iter_candidate_paths(target) if _matches_archive_pattern(path.name)]
    result.checked_items["local archive candidates"] = f"{len(archive_candidates)} file(s)" if archive_candidates else "none"

    tracked = _git_tracked_files(target)
    for path in candidates:
        rel = display_path(target, path)
        tracked_state = "unknown"
        if tracked is not None:
            tracked_state = "yes" if rel.replace("\\", "/") in tracked else "no"
        severity = "MEDIUM" if tracked_state == "yes" else "LOW"
        result.findings.append(
            Finding(
                severity=severity,
                title=f"Local secret-like file exists: {path.name}",
                path=rel,
                evidence=f"file exists; tracked_by_git={tracked_state}; content not read",
                risk="秘密情報を含む可能性があるファイルです。内容は出力していません。",
                check_method="ファイル名パターンだけを確認し、可能な場合は git 管理対象かを確認しました。",
                next_action="不要なら削除ではなく、まず内容と gitignore / 履歴への混入有無を確認してください。",
            )
        )

    for path in archive_candidates:
        rel = display_path(target, path)
        tracked_state = "unknown"
        if tracked is not None:
            tracked_state = "yes" if rel.replace("\\", "/") in tracked else "no"
        severity = "MEDIUM" if tracked_state == "yes" else "LOW"
        result.findings.append(
            Finding(
                severity=severity,
                title=f"Local archive file exists: {path.name}",
                path=rel,
                evidence=f"archive file exists; tracked_by_git={tracked_state}; content not read",
                risk="秘密情報を退避したアーカイブの可能性があります。内容やパスワード有無は確認していません。",
                check_method="zip / 7z のファイル名パターンだけを確認し、可能な場合は git 管理対象かを確認しました。",
                next_action="パスワード付きか、元の平文ファイルが残っていないか、git 管理対象になっていないか確認してください。",
            )
        )


def _iter_candidate_paths(target: Path) -> list[Path]:
    paths: list[Path] = []
    for path in target.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            paths.append(path)
    return paths


def _matches_secret_pattern(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in SECRET_PATTERNS)


def _matches_archive_pattern(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in ARCHIVE_PATTERNS)


def _git_tracked_files(target: Path) -> set[str] | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(target), "ls-files"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    return {line.strip().replace("\\", "/") for line in completed.stdout.splitlines() if line.strip()}
