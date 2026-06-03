# JSON Report Format

`agent-repo-safety-check` writes a JSON report next to the Markdown report.
The JSON output is intended for local maintainer automation, dashboards, and
future CI integrations.

The project is still pre-1.0, so the format may evolve. The current intent is
to keep field names stable when practical and document breaking changes in
release notes.

## Top-Level Fields

```json
{
  "target": "C:/path/to/repository",
  "scanned_at": "2026-06-03",
  "profile": "agent",
  "findings": [],
  "checked_items": {},
  "output_markdown": "C:/path/to/report.md",
  "output_json": "C:/path/to/report.json"
}
```

- `target`: absolute path scanned on the local machine.
- `scanned_at`: scan date in `YYYY-MM-DD` format.
- `profile`: scan profile, currently `agent` or `oss`.
- `findings`: list of finding objects.
- `checked_items`: map of check names to short status strings.
- `output_markdown`: absolute path to the generated Markdown report.
- `output_json`: absolute path to the generated JSON report.

Do not publish raw JSON reports without reviewing local paths and context.

## Finding Fields

```json
{
  "severity": "MEDIUM",
  "title": "GitHub Actions broad write permission candidate",
  "path": ".github/workflows/release.yml",
  "evidence": "matched write permissions: contents: write",
  "risk": "Over-broad write permissions can increase impact if a workflow is compromised.",
  "check_method": "Checked workflow YAML text for write permission candidates.",
  "next_action": "Confirm permissions can be minimized per job."
}
```

- `severity`: one of `HIGH`, `MEDIUM`, `LOW`, or `INFO`.
- `title`: short finding title for humans.
- `path`: repository-relative path when possible.
- `evidence`: bounded evidence used to explain the match.
- `risk`: why the finding may matter.
- `check_method`: what the scanner checked.
- `next_action`: suggested manual follow-up.

## Safety Expectations

- Secret-like file contents are not read or printed.
- Agent config values that look like env values or tokens are not printed.
- Findings are confirmation candidates, not proof of compromise.
- Reports may include local paths, so generated reports stay ignored by default.

## Compatibility Notes

Until `v1.0.0`, consumers should handle unknown fields gracefully and avoid
assuming every finding category is present in every scan. Maintainers should
prefer additive changes and document any incompatible changes in release notes.
