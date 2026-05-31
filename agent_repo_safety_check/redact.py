from __future__ import annotations

import re

SECRET_HINT_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|secret|password|passwd|bearer|credential|private[_-]?key)"
)


def redact_secret_like_text(value: object) -> str:
    text = str(value)
    if SECRET_HINT_RE.search(text):
        return "***redacted***"
    text = re.sub(r"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^,\s]+", r"\1=***redacted***", text)
    return text


def matched_terms(text: str, candidates: list[str]) -> list[str]:
    lowered = text.lower()
    return [candidate for candidate in candidates if candidate.lower() in lowered]
