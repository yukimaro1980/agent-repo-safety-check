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
                    risk="npm scripts and dependency checks may be incomplete.",
                    check_method="Tried to read package.json as JSON.",
                    next_action="Confirm the file is valid JSON.",
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
                        risk="Local commands may run automatically during install or publish.",
                        check_method="Checked the scripts key in package.json.",
                        next_action="Confirm the command is trusted and safe to run during dependency installation.",
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
                    risk="This is a watch-list candidate, not proof of compromise.",
                    check_method="Compared package.json dependency names with the watch list.",
                    next_action="Check the resolved version in the lockfile and review official advisories or OSV.",
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
                    risk="latest and * weaken reproducibility and can change future install results.",
                    check_method="Checked package.json dependency version strings.",
                    next_action="Confirm whether a lockfile or explicit version range should be used.",
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
                    risk="Remote or Git dependencies can be harder to verify than registry packages.",
                    check_method="Checked package.json dependency version strings.",
                    next_action="Confirm the upstream is trusted and whether commit SHA pinning or integrity checks are needed.",
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
                    risk="The lockfile includes a watch-list package name. Version-specific judgment is not performed.",
                    check_method="Searched lockfile text for watch-list package names.",
                    next_action="Confirm the actual version and dependency path for the matched package.",
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
                    risk="The lockfile includes remote retrieval paths. Some resolved URLs are legitimate, so this is a review candidate.",
                    check_method="Searched lockfile text for remote dependency terms.",
                    next_action="Confirm the matched dependency source is intentional.",
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
