# agent-repo-safety-check

Read-only security and repository hygiene checklist for local projects, especially projects touched by AI coding agents.

The tool does not try to prove compromise. It reports confirmation candidates: risky install hooks, broad automation permissions, agent hooks, local secret-like files, and OSS readiness gaps that a maintainer should review before publishing or letting an agent work in a repository.

## Why

AI agents can edit code quickly, but they can also miss local repo risks that are obvious only after looking at configuration files:

- npm lifecycle scripts that run during install or publish
- `.codex` / `.claude` hooks and command settings
- VS Code tasks that run on folder open
- GitHub Actions with broad permissions, `pull_request_target`, remote script execution, or deploy commands
- secret-like files, private key names, and local secret archives
- missing OSS basics such as LICENSE, CI, SECURITY policy, sample projects, and stronger package metadata

`agent-repo-safety-check` is a small local preflight scan for those situations.

## Install

From a checkout:

```powershell
uv run agent-repo-safety-check scan --target F:\path\to\project
```

Without `uv`, prefer a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\agent-repo-safety-check scan --target F:\path\to\project
```

For quick local development when the environment is already isolated:

```powershell
python -m agent_repo_safety_check scan --target F:\path\to\project
```

The default profile is `agent`, which focuses on AI-agent safety preflight checks.

For OSS publication readiness checks, use:

```powershell
uv run agent-repo-safety-check scan --target F:\path\to\project --profile oss
```

## Output

By default, reports are written to:

```text
outputs/YYYY-MM-DD-security-check.md
outputs/YYYY-MM-DD-security-check.json
```

The Markdown report is meant for human review. The JSON report is meant for future automation.

## Safety Model

- Read-only: the target project is not modified.
- Secret-safe by default: secret-like file contents are not read or printed.
- Findings are confirmation candidates, not final judgments.
- The scanner prefers transparent heuristics over hidden scoring.
- False positives are expected; each finding includes a suggested manual next step.

## Checks

Current checks include:

- Node/npm: lifecycle scripts, watch-list packages, floating versions, remote/Git dependency specs, lockfile remote references
- AI agent settings: `.codex` and `.claude` files that mention hooks, commands, shells, network tools, MCP server definitions, env keys, or permissions
- VS Code: `tasks.json` auto-run and shell/network command candidates
- GitHub Actions: OIDC permissions, broad write permissions, `pull_request_target`, mutable action refs, context dumps, env dumps, remote script execution, publish/deploy terms
- Local files: `.env*`, key files, credentials files, zip/7z archive candidates, with Git tracked-state when available
- OSS profile only: README, LICENSE, CI workflows, CONTRIBUTING, SECURITY, samples/examples, and `pyproject.toml` metadata

## Profiles

`agent` is the default profile. Use it before letting an AI coding agent work in a repository. It keeps the report focused on executable configuration, automation, dependencies, and secret-like local files.

`oss` includes all `agent` checks plus publication-readiness hygiene. Use it before making a repository public, preparing a release, or building evidence for maintainer support programs.

## Example

The repository includes a deliberately risky sample project:

```powershell
uv run agent-repo-safety-check scan --target samples\risky-node-project --profile oss
```

Expected findings include npm lifecycle scripts, GitHub Actions remote script execution, `pull_request_target`, VS Code folder-open tasks, and local secret-like/archive candidates when added during tests.

A public-safe sample summary is available at `docs/sample-reports/risky-node-project-agent.md`.

## Development

Run tests:

```powershell
python -m unittest discover -s tests -p "test*.py"
```

The project is intentionally small and rule-based. New checks should explain:

- what was checked
- why it might matter
- what manual verification should happen next
- whether the check reads or redacts sensitive content

Agent config checks report matched key paths and command-like terms only. They do not print env values or secret-like values from TOML/JSON settings.

## Non-Goals

- It is not a vulnerability scanner.
- It does not upload source code or reports.
- It does not auto-fix, quarantine, delete, or rewrite target files.
- It does not replace human review before publishing a repository.

## License

MIT
