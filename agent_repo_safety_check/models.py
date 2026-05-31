from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

Severity = Literal["HIGH", "MEDIUM", "LOW", "INFO"]
ScanProfile = Literal["agent", "oss"]


@dataclass(slots=True)
class Finding:
    severity: Severity
    title: str
    path: str
    evidence: str
    risk: str
    check_method: str
    next_action: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target: str
    scanned_at: str
    profile: ScanProfile = "agent"
    findings: list[Finding] = field(default_factory=list)
    checked_items: dict[str, str] = field(default_factory=dict)
    output_markdown: str | None = None
    output_json: str | None = None

    def count_by_severity(self, severity: Severity) -> int:
        return sum(1 for finding in self.findings if finding.severity == severity)

    def total_counts(self) -> dict[str, int]:
        return {
            "HIGH": self.count_by_severity("HIGH"),
            "MEDIUM": self.count_by_severity("MEDIUM"),
            "LOW": self.count_by_severity("LOW"),
            "INFO": self.count_by_severity("INFO"),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "profile": self.profile,
            "summary": self.total_counts(),
            "checked_items": self.checked_items,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def display_path(target: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve()))
    except ValueError:
        return str(path.resolve())
