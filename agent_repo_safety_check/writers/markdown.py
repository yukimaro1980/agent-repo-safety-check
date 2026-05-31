from __future__ import annotations

from pathlib import Path

from ..models import Finding, ScanResult


def write_markdown(result: ScanResult, path: Path) -> None:
    counts = result.total_counts()
    lines = [
        f"# Agent Repo Safety Check — {result.scanned_at}",
        "",
        "## Summary",
        "",
        f"- Target: {result.target}",
        f"- Profile: {result.profile}",
        f"- Overall: HIGH {counts['HIGH']} / MEDIUM {counts['MEDIUM']} / LOW {counts['LOW']} / INFO {counts['INFO']}",
        f"- HIGH: {counts['HIGH']}",
        f"- MEDIUM: {counts['MEDIUM']}",
        f"- LOW: {counts['LOW']}",
        f"- INFO: {counts['INFO']}",
        "",
        "## Findings",
        "",
    ]

    for finding in result.findings:
        lines.extend(_finding_lines(finding))

    lines.extend(
        [
            "## Checked Items",
            "",
        ]
    )
    for key, value in result.checked_items.items():
        lines.append(f"- {key}: {value}")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- This tool is read-only.",
            "- Secret values are not printed.",
            "- Findings are confirmation candidates, not proof of compromise.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _finding_lines(finding: Finding) -> list[str]:
    return [
        f"### [{finding.severity}] {finding.title}",
        f"- **Location**: {finding.path}",
        f"- **Evidence**: {finding.evidence}",
        f"- **Risk**: {finding.risk}",
        f"- **Check**: {finding.check_method}",
        f"- **Next step**: {finding.next_action}",
        "",
    ]
