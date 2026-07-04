# Public Repository Scan Examples

These examples summarize scans of public repositories using the `oss` profile.
They are hand-written summaries, not generated reports, so they avoid local
paths and generated output files.

Command shape:

```powershell
python -m agent_repo_safety_check scan --target <public-repo-checkout> --profile oss
```

Scan date: 2026-07-04

## `yukimaro1980/agent-repo-safety-check`

Public commit: `e19fdba799cdaf828881e156455316c1541a425a`

Why this scan mattered:

- Self-scan of this tool's public repository before publishing more examples.
- Confirms the `oss` profile stays quiet on a small Python CLI repository with
  standard project files and no local secret-like files.

Sanitized summary:

```text
HIGH=0 / MEDIUM=0 / LOW=0 / INFO=3
```

Representative findings:

- INFO: read-only scan completed.
- INFO: README exists.
- INFO: LICENSE exists.

False-positive follow-up:

- None observed in this scan.

## `pypa/sampleproject`

Public commit: `621e4974ca25ce531773def586ba3ed8e736b3fc`

Why this scan mattered:

- Small Python packaging repository with GitHub Actions release automation.
- Useful for checking whether release-oriented workflows are reported without
  printing secrets or local paths.

Sanitized summary:

```text
HIGH=0 / MEDIUM=1 / LOW=0 / INFO=7
```

Representative findings:

- MEDIUM: GitHub Actions publish/deploy candidate in `.github/workflows/release.yml`.
- INFO: GitHub Actions `id-token` write permission detected in `.github/workflows/release.yml`.
- INFO: README and LICENSE are present.
- INFO: CONTRIBUTING, SECURITY, and sample-directory hygiene checks were reported as missing.

False-positive follow-up:

- The PyPI publish/deploy and OIDC findings are expected for a release workflow.
  A future rule could label trusted-publishing style release workflows more
  clearly while still keeping them visible for maintainer review.
- The sample-directory hygiene check is noisy for a repository that is itself a
  sample project. A future rule could recognize explicit sample repositories or
  let maintainers suppress this hygiene candidate.
- Tracked in GitHub issue #7.

## `expressjs/express`

Public commit: `18e5985b8a9d5e8423db0a9121f22bdaecd5b120`

Why this scan mattered:

- Mature Node.js library with multiple GitHub Actions workflows.
- Useful for checking workflow permission heuristics against a real project
  that has CI, CodeQL, scorecard, and legacy test automation.

Sanitized summary:

```text
HIGH=0 / MEDIUM=4 / LOW=0 / INFO=6
```

Representative findings:

- MEDIUM: broad write permission candidates in workflow files that use
  `checks: write` or `security-events: write`.
- INFO: GitHub Actions `id-token` write permission detected in a scorecard workflow.
- INFO: README and LICENSE are present.
- INFO: CONTRIBUTING and SECURITY hygiene checks were reported as missing.

False-positive follow-up:

- `checks: write` and `security-events: write` can be legitimate for CI,
  CodeQL, and scorecard workflows. A future rule could distinguish common
  security-reporting permissions from broader repository-write permissions.
- The repository uses community governance files outside this scanner's current
  direct-file checks. A future rule could inspect common alternatives before
  reporting missing CONTRIBUTING or SECURITY guidance.
- Tracked in GitHub issue #7.

## Publication Notes

- These summaries intentionally do not include generated Markdown or JSON
  reports.
- The scanner reads configuration and file names only for these checks; secret
  values are not printed.
- Findings are confirmation candidates. They should be reviewed by maintainers
  before being treated as problems.
