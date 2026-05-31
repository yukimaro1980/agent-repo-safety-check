# Roadmap

## Near Term

- Keep the scanner read-only and secret-safe.
- Split findings clearly between security candidates and OSS hygiene candidates.
- Add more fixtures for GitHub Actions and AI-agent config edge cases.
- Review false positives from real local repositories.
- Add more structure-aware parsing for workflow files and package metadata.

## Candidate Checks

- MCP server command and environment variable review without printing values.
- GitHub Actions checkout patterns under `pull_request_target`.
- GitHub Actions job-level permissions vs workflow-level permissions.
- Python packaging metadata and release workflow checks.
- Large files and generated artifact candidates before publication.
- Improve profile behavior:
  - `agent`: AI-agent safety preflight.
  - `oss`: publication and maintainer-readiness hygiene.

## Before Public Release

- Confirm the public repository uses `agent-repo-safety-check` consistently.
- Run scans against representative repositories and summarize false positives.
- Publish sample reports that do not contain secrets.
- Confirm GitHub repository visibility and release process.
- Prepare a short maintainer statement for OSS support programs.
