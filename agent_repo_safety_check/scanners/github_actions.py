from __future__ import annotations

from pathlib import Path

from ..models import Finding, ScanResult, display_path

WORKFLOW_PATTERNS = ("*.yml", "*.yaml")


def scan(target: Path, result: ScanResult) -> None:
    workflow_dir = target / ".github" / "workflows"
    workflows: list[Path] = []
    if workflow_dir.exists():
        for pattern in WORKFLOW_PATTERNS:
            workflows.extend(sorted(workflow_dir.glob(pattern)))
    result.checked_items[".github/workflows"] = f"{len(workflows)} workflow file(s)" if workflows else "missing"

    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        path = display_path(target, workflow)

        if "id-token:" in lowered and "write" in lowered:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title="GitHub Actions id-token write permission detected",
                    path=path,
                    evidence="permissions includes id-token with write-like text",
                    risk="This can be valid for OIDC deploys, but it is a candidate for unintended cloud-auth paths.",
                    check_method="Checked workflow YAML text for id-token and write permission text.",
                    next_action="Confirm the OIDC jobs and trust boundaries are intentional.",
                )
            )

        if "pull_request_target" in lowered:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions pull_request_target trigger detected",
                    path=path,
                    evidence="matched pull_request_target",
                    risk="Mixing fork-originated changes with repository privileges can create dangerous execution paths.",
                    check_method="Checked workflow YAML text for the pull_request_target trigger.",
                    next_action="Review checkout targets, secrets use, write permissions, and external contributor execution conditions.",
                )
            )

        broad_permissions = _matched_broad_write_permissions(lowered)
        if broad_permissions:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title="GitHub Actions broad write permission candidate",
                    path=path,
                    evidence="matched write permissions: " + ", ".join(broad_permissions),
                    risk="Over-broad write permissions can increase impact if a workflow is compromised.",
                    check_method="Checked workflow YAML text for write permission candidates.",
                    next_action="Confirm permissions can be minimized per job.",
                )
            )

        mutable_actions = _matched_mutable_actions(text)
        if mutable_actions:
            result.findings.append(
                Finding(
                    severity="INFO",
                    title="GitHub Actions uses mutable action reference",
                    path=path,
                    evidence="matched uses refs: " + ", ".join(mutable_actions[:6]),
                    risk="main/master/latest references can change behavior when upstream changes.",
                    check_method="Checked uses: owner/repo@ref entries for mutable refs.",
                    next_action="Pin to a tag or commit SHA when possible.",
                )
            )

        if "tojson(secrets)" in lowered or "tojson(github.event)" in lowered:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions may print sensitive context",
                    path=path,
                    evidence="matched toJSON(secrets) or broad context dump",
                    risk="Secrets or event payloads may be written to logs.",
                    check_method="Checked workflow YAML text for broad context dump candidates.",
                    next_action="Limit logged context and confirm secrets are not printed.",
                )
            )

        if _contains_env_dump(lowered):
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title="GitHub Actions environment dump candidate",
                    path=path,
                    evidence="matched printenv/env style command",
                    risk="Dumping environment variables can expose sensitive surrounding context.",
                    check_method="Checked workflow YAML text for printenv/env-style output candidates.",
                    next_action="If this is for debugging, confirm it is temporary and masked as needed.",
                )
            )

        if _contains_remote_script(lowered):
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions remote script execution candidate",
                    path=path,
                    evidence="matched curl/iwr piped to shell execution",
                    risk="Executing fetched remote scripts introduces supply-chain risk.",
                    check_method="Checked workflow YAML text for curl | sh / iwr | iex patterns.",
                    next_action="Prefer pinned versions, checksums, or official actions where possible.",
                )
            )

        deploy_terms = _matched_deploy_terms(lowered)
        if deploy_terms:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title="GitHub Actions publish/deploy candidate",
                    path=path,
                    evidence="matched deploy terms: " + ", ".join(deploy_terms),
                    risk="Publish and deploy steps require careful review of credentials, permissions, and trigger conditions.",
                    check_method="Checked workflow YAML text for publish/deploy command candidates.",
                    next_action="Review branches, manual approval, permissions, and secrets use.",
                )
            )


def _contains_env_dump(lowered: str) -> bool:
    return "\n" in lowered and any(token in lowered for token in ("\n        env\n", "\n        printenv", " run: env", " run: printenv"))


def _contains_remote_script(lowered: str) -> bool:
    remote_terms = ("curl", "invoke-webrequest", "iwr", "wget")
    shell_terms = ("| sh", "| bash", "| iex", "invoke-expression")
    return any(term in lowered for term in remote_terms) and any(term in lowered for term in shell_terms)


def _matched_deploy_terms(lowered: str) -> list[str]:
    candidates = ["npm publish", "pypi", "twine upload", "docker login", "gh release", "deploy", "az login", "gcloud", "aws "]
    return [candidate for candidate in candidates if candidate in lowered]


def _matched_broad_write_permissions(lowered: str) -> list[str]:
    permissions = [
        "contents: write",
        "actions: write",
        "checks: write",
        "deployments: write",
        "packages: write",
        "pull-requests: write",
        "security-events: write",
        "statuses: write",
    ]
    return [permission for permission in permissions if permission in lowered]


def _matched_mutable_actions(text: str) -> list[str]:
    matches: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lowered_line = stripped.lower()
        if lowered_line.startswith("- uses:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
        elif lowered_line.startswith("uses:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
        else:
            continue
        lowered = value.lower()
        if lowered.endswith("@main") or lowered.endswith("@master") or lowered.endswith("@latest"):
            matches.append(value)
    return matches
