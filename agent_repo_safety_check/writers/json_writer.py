from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanResult


def write_json(result: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
