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
            "Users and maintainers cannot confirm the purpose, usage, or safety assumptions.",
            "Add README.md with the read-only policy, examples, output shape, and non-goals.",
        )
    else:
        result.findings.append(
            Finding(
                severity="INFO",
                title="README exists",
                path=display_path(target, readme),
                evidence="README file found",
                risk="README exists. Review whether it is sufficient for OSS users.",
                check_method="Checked common README file names.",
                next_action="Confirm it explains purpose, install, examples, output, and safety notes.",
            )
        )

    if license_file is None:
        _append_missing(
            result,
            "LICENSE is missing",
            "No LICENSE/COPYING file was found.",
            "The terms for use and redistribution are unclear.",
            "Add the intended license, such as MIT or Apache-2.0.",
        )
    else:
        result.findings.append(
            Finding(
                severity="INFO",
                title="LICENSE exists",
                path=display_path(target, license_file),
                evidence="license file found",
                risk="A license file exists. Confirm it is the intended license.",
                check_method="Checked common license file names.",
                next_action="Keep README and pyproject license metadata aligned.",
            )
        )

    if not ci_files:
        result.findings.append(
            Finding(
                severity="LOW",
                title="CI workflow is missing",
                path=".github/workflows",
                evidence="no workflow files found",
                risk="Users cannot easily see test status, which weakens maintenance signals.",
                check_method="Checked for YAML files under .github/workflows.",
                next_action="Add a GitHub Actions workflow that runs at least the unit tests.",
            )
        )

    if contributing is None:
        result.findings.append(
            Finding(
                severity="INFO",
                title="CONTRIBUTING guide is missing",
                path=".",
                evidence="CONTRIBUTING.md was not found",
                risk="External contributors may not know how to file issues or pull requests.",
                check_method="Checked common CONTRIBUTING file names.",
                next_action="Add a short issue/PR policy and read-only safety policy.",
            )
        )

    if security_policy is None:
        result.findings.append(
            Finding(
                severity="INFO",
                title="SECURITY policy is missing",
                path=".",
                evidence="SECURITY.md was not found",
                risk="Vulnerability reporting scope and private reporting expectations are unclear.",
                check_method="Checked common SECURITY file names.",
                next_action="Document reporting scope and how sensitive reports should be handled.",
            )
        )

    if not samples:
        result.findings.append(
            Finding(
                severity="INFO",
                title="Sample project directory is missing",
                path=".",
                evidence="samples/examples/demo directory was not found",
                risk="Users do not have a safe fixture for trying the scanner.",
                check_method="Checked for samples, examples, or demo directories.",
                next_action="Add a sample project with intentional risky patterns and an expected report summary.",
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
                    risk="Package description, license, or project links may be incomplete.",
                    check_method="Checked pyproject.toml text for common OSS metadata fields.",
                    next_action="Add license, classifiers, and project.urls metadata as needed.",
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
            check_method="Checked common repository hygiene files.",
            next_action=next_action,
        )
    )
