from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, ScanResult, display_path
from ..redact import matched_terms, redact_secret_like_text

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublishOnly"}
WATCH_PACKAGES = ("@antv/", "echarts-for-react", "size-sensor", "timeago.js", "durabletask")
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
UNPINNED_VERSION_VALUES = {"*", "latest", "next"}
REMOTE_VERSION_PREFIXES = ("git+", "git://", "github:", "http://", "https://", "ssh://")


def scan(target: Path, result: ScanResult) -> None:
    package_json = target / "package.json"
    result.checked_items["package.json"] = "present" if package_json.exists() else "missing"

    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except Exception as exc:
            result.findings.append(
                Finding(
                    severity="LOW",
                    title="package.json could not be parsed",
                    path=display_path(target, package_json),
                    evidence=f"JSON parse failed: {type(exc).__name__}",
                    risk="npm scripts や依存関係の確認が不足する可能性があります。",
                    check_method="package.json を JSON として読み込みました。",
                    next_action="ファイルが意図した JSON 形式か確認してください。",
                )
            )
            data = {}

        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            lifecycle = sorted(script for script in scripts if script in LIFECYCLE_SCRIPTS)
            for script in lifecycle:
                result.findings.append(
                    Finding(
                        severity="MEDIUM",
                        title=f"npm lifecycle script detected: {script}",
                        path=display_path(target, package_json),
                        evidence=f"scripts.{script} exists; command={redact_secret_like_text(scripts.get(script, ''))}",
                        risk="install や publish のタイミングでローカルコマンドが自動実行される可能性があります。",
                        check_method="package.json の scripts キーを確認しました。",
                        next_action="コマンド内容が信頼できるものか、依存導入時に実行されて問題ないか確認してください。",
                    )
                )

        dependency_names = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            section = data.get(key, {}) if isinstance(data, dict) else {}
            if isinstance(section, dict):
                dependency_names.update(section.keys())
        watched = sorted(name for name in dependency_names if _is_watch_package(name))
        for name in watched:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title=f"Watch-list package candidate detected: {name}",
                    path=display_path(target, package_json),
                    evidence=f"dependency name matched: {name}",
                    risk="MVP では侵害有無を断定せず、注意パッケージ候補として扱います。",
                    check_method="package.json の依存パッケージ名を注意リストと照合しました。",
                    next_action="lockfile 上の実バージョンと公式 advisory / OSV などを後続で確認してください。",
                )
            )

        dependency_versions = _dependency_versions(data if isinstance(data, dict) else {})
        unpinned = sorted(f"{name}@{version}" for name, version in dependency_versions.items() if _is_unpinned(version))
        if unpinned:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title="npm dependency uses floating version",
                    path=display_path(target, package_json),
                    evidence="matched floating versions: " + ", ".join(unpinned[:12]),
                    risk="latest や * は再現性が弱く、将来の install 結果が変わる可能性があります。",
                    check_method="package.json の dependency version を確認しました。",
                    next_action="公開OSSでは lockfile や明示 version range を使う意図があるか確認してください。",
                )
            )

        remote_deps = sorted(f"{name}@{version}" for name, version in dependency_versions.items() if _is_remote_version(version))
        if remote_deps:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title="npm dependency uses remote URL or git reference",
                    path=display_path(target, package_json),
                    evidence="matched remote dependency specs: " + ", ".join(remote_deps[:12]),
                    risk="registry package より供給元や更新内容の確認が難しい依存です。",
                    check_method="package.json の dependency version 文字列を確認しました。",
                    next_action="信頼できる upstream か、commit SHA 固定や integrity 確認が必要か確認してください。",
                )
            )

    present_lockfiles = [name for name in LOCKFILES if (target / name).exists()]
    result.checked_items["lockfiles"] = ", ".join(present_lockfiles) if present_lockfiles else "missing"
    for lockfile_name in present_lockfiles:
        lockfile_path = target / lockfile_name
        try:
            lock_text = lockfile_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            lock_text = ""
        matches = matched_terms(lock_text, list(WATCH_PACKAGES))
        if matches:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title=f"Watch-list package name found in {lockfile_name}",
                    path=display_path(target, lockfile_path),
                    evidence="matched package names: " + ", ".join(sorted(set(matches))),
                    risk="lockfile に注意候補名が含まれます。MVP ではバージョン判定までは行いません。",
                    check_method="lockfile のテキスト内に注意パッケージ名が含まれるか簡易確認しました。",
                    next_action="該当パッケージの実バージョンと導入経路を確認してください。",
                )
            )
        remote_lock_terms = matched_terms(lock_text.lower(), ["git+", "github:", "http://", "https://", "ssh://"])
        if remote_lock_terms:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title=f"Remote dependency reference found in {lockfile_name}",
                    path=display_path(target, lockfile_path),
                    evidence="matched remote terms: " + ", ".join(sorted(set(remote_lock_terms))),
                    risk="lockfile にリモート取得経路が含まれます。正当な resolved URL も含むため確認候補です。",
                    check_method="lockfile のテキストから remote dependency らしき語を確認しました。",
                    next_action="該当依存の導入元が意図どおりか確認してください。",
                )
            )


def _is_watch_package(name: str) -> bool:
    return any(name == candidate or name.startswith(candidate) for candidate in WATCH_PACKAGES)


def _dependency_versions(data: dict[str, object]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key, {})
        if not isinstance(section, dict):
            continue
        for name, version in section.items():
            if isinstance(name, str) and isinstance(version, str):
                versions[name] = version
    return versions


def _is_unpinned(version: str) -> bool:
    return version.strip().lower() in UNPINNED_VERSION_VALUES


def _is_remote_version(version: str) -> bool:
    lowered = version.strip().lower()
    return any(lowered.startswith(prefix) for prefix in REMOTE_VERSION_PREFIXES)
