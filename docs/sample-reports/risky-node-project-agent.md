# Sample Report: risky-node-project with `agent` profile

This is a public-safe sample summary for the deliberately risky fixture under `samples/risky-node-project`.

Command shape:

```powershell
python -m agent_repo_safety_check scan --target samples\risky-node-project --profile agent
```

Expected summary:

```text
HIGH=3 / MEDIUM=9 / LOW=0 / INFO=5
```

Representative findings:

- HIGH: VS Code task runs on folder open.
- HIGH: GitHub Actions `pull_request_target` trigger detected.
- HIGH: GitHub Actions remote script execution candidate.
- MEDIUM: npm lifecycle script detected.
- MEDIUM: AI agent config candidate in `.claude/settings.json`.
- MEDIUM: AI agent structured config needs review in `.claude/settings.json`.
- MEDIUM: AI agent config candidate in `.codex/config.toml`.
- MEDIUM: AI agent structured config needs review in `.codex/config.toml`.
- MEDIUM: GitHub Actions broad write permission candidate.
- MEDIUM: GitHub Actions environment dump candidate.
- MEDIUM: GitHub Actions publish/deploy candidate.
- INFO: GitHub Actions OIDC permission detected.
- INFO: GitHub Actions mutable action reference.

Safety notes:

- The fixture includes a dummy token-like value.
- The scanner reports matched key paths such as `mcp_servers.example.env`.
- The scanner does not print the dummy token-like value.
- The report is a confirmation checklist, not a claim that the sample is compromised.
