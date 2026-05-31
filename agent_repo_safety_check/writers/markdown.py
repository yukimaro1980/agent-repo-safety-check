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
        f"- 対象: {result.target}",
        f"- Profile: {result.profile}",
        f"- 総合結果: HIGH {counts['HIGH']} / MEDIUM {counts['MEDIUM']} / LOW {counts['LOW']} / INFO {counts['INFO']}",
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
            "- このツールは read-only です。",
            "- secrets の値は出力していません。",
            "- 結果は危険確定ではなく確認候補です。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _finding_lines(finding: Finding) -> list[str]:
    return [
        f"### [{finding.severity}] {finding.title}",
        f"- **場所**: {finding.path}",
        f"- **事実**: {finding.evidence}",
        f"- **リスク**: {finding.risk}",
        f"- **確認方法**: {finding.check_method}",
        f"- **次の一手**: {finding.next_action}",
        "",
    ]
