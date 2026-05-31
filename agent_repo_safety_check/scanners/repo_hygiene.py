from __future__ import annotations

from pathlib import Path

from ..models import Finding, ScanResult, display_path

README_NAMES = ("README.md", "README.rst", "README.txt")
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")
CONTRIBUTING_NAMES = ("CONTRIBUTING.md", ".github/CONTRIBUTING.md")
SECURITY_NAMES = ("SECURITY.md", ".github/SECURITY.md")
CI_PATTERNS = ("*.yml", "*.yaml")
SAMPLE_DIRS = ("samples", "examples", "demo")
PYPROJECT = "pyproject.toml"


def scan(target: Path, result: ScanResult) -> None:
    readme = _first_existing(target, README_NAMES)
    license_file = _first_existing(target, LICENSE_NAMES)
    contributing = _first_existing(target, CONTRIBUTING_NAMES)
    security_policy = _first_existing(target, SECURITY_NAMES)
    ci_files = _workflow_files(target)
    samples = [target / dirname for dirname in SAMPLE_DIRS if (target / dirname).exists()]
    pyproject = target / PYPROJECT

    result.checked_items["repo hygiene"] = "checked"

    if readme is None:
        _append_missing(
            result,
            "README is missing",
            "README.md was not found.",
            "利用者や申請レビュアーが、目的・使い方・安全な前提を確認できません。",
            "README.md を追加し、read-only 方針、実行例、出力例、非保証範囲を記載してください。",
        )
    else:
        result.findings.append(
            Finding(
                severity="INFO",
                title="README exists",
                path=display_path(target, readme),
                evidence="README file found",
                risk="README は存在します。内容が OSS 利用者向けに十分かは別途確認してください。",
                check_method="一般的な README ファイル名を確認しました。",
                next_action="目的、インストール、実行例、出力例、safety notes が入っているか確認してください。",
            )
        )

    if license_file is None:
        _append_missing(
            result,
            "LICENSE is missing",
            "No LICENSE/COPYING file was found.",
            "OSS として利用・再配布できる条件が不明確です。",
            "公開前に MIT / Apache-2.0 など、意図した license を追加してください。",
        )
    else:
        result.findings.append(
            Finding(
                severity="INFO",
                title="LICENSE exists",
                path=display_path(target, license_file),
                evidence="license file found",
                risk="license file は存在します。内容が意図した license か確認してください。",
                check_method="一般的な license ファイル名を確認しました。",
                next_action="README と pyproject の license 表記も合わせてください。",
            )
        )

    if not ci_files:
        result.findings.append(
            Finding(
                severity="LOW",
                title="CI workflow is missing",
                path=".github/workflows",
                evidence="no workflow files found",
                risk="OSS 利用者がテスト状態を確認しづらく、保守品質の説明が弱くなります。",
                check_method=".github/workflows 配下の YAML ファイルを確認しました。",
                next_action="少なくとも unit tests を走らせる GitHub Actions workflow を追加してください。",
            )
        )

    if contributing is None:
        result.findings.append(
            Finding(
                severity="INFO",
                title="CONTRIBUTING guide is missing",
                path=".",
                evidence="CONTRIBUTING.md was not found",
                risk="外部 contributor が issue / PR の出し方を判断しづらい状態です。",
                check_method="一般的な CONTRIBUTING ファイル名を確認しました。",
                next_action="小さなプロジェクトでも、issue/PR 方針と read-only safety policy を短く書くと安心です。",
            )
        )

    if security_policy is None:
        result.findings.append(
            Finding(
                severity="INFO",
                title="SECURITY policy is missing",
                path=".",
                evidence="SECURITY.md was not found",
                risk="脆弱性報告の窓口や非公開連絡方法が分かりません。",
                check_method="一般的な SECURITY ファイル名を確認しました。",
                next_action="security tool として公開するなら、報告方法と対象範囲を短く書いてください。",
            )
        )

    if not samples:
        result.findings.append(
            Finding(
                severity="INFO",
                title="Sample project directory is missing",
                path=".",
                evidence="samples/examples/demo directory was not found",
                risk="利用者が安全に試すための fixture がない状態です。",
                check_method="samples / examples / demo ディレクトリの有無を確認しました。",
                next_action="意図的に危険パターンを入れた sample project と期待される report を用意してください。",
            )
        )

    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
        missing_bits = []
        if "license" not in text:
            missing_bits.append("license")
        if "classifiers" not in text:
            missing_bits.append("classifiers")
        if "urls" not in text and "project.urls" not in text:
            missing_bits.append("project.urls")
        if missing_bits:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title="pyproject metadata could be stronger",
                    path=display_path(target, pyproject),
                    evidence="missing metadata: " + ", ".join(missing_bits),
                    risk="package としての説明、license、project links が不足している可能性があります。",
                    check_method="pyproject.toml のテキストから OSS metadata 候補を確認しました。",
                    next_action="公開前に license、classifiers、project.urls を整えてください。",
                )
            )


def _first_existing(target: Path, candidates: tuple[str, ...]) -> Path | None:
    for candidate in candidates:
        path = target / candidate
        if path.exists():
            return path
    return None


def _workflow_files(target: Path) -> list[Path]:
    workflow_dir = target / ".github" / "workflows"
    if not workflow_dir.exists():
        return []
    files: list[Path] = []
    for pattern in CI_PATTERNS:
        files.extend(sorted(workflow_dir.glob(pattern)))
    return files


def _append_missing(
    result: ScanResult,
    title: str,
    evidence: str,
    risk: str,
    next_action: str,
) -> None:
    result.findings.append(
        Finding(
            severity="LOW",
            title=title,
            path=".",
            evidence=evidence,
            risk=risk,
            check_method="公開前 repo hygiene として一般的な必須ファイルを確認しました。",
            next_action=next_action,
        )
    )
