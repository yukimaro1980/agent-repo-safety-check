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
                    risk="OIDC を使う deploy では正当な設定ですが、意図しないクラウド認証経路がないか確認候補です。",
                    check_method="workflow YAML のテキストから id-token と write の組み合わせを確認しました。",
                    next_action="OIDC を使う job と信頼境界が意図どおりか確認してください。",
                )
            )

        if "pull_request_target" in lowered:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions pull_request_target trigger detected",
                    path=path,
                    evidence="matched pull_request_target",
                    risk="fork 由来の変更と repository 権限が混ざると危険な実行経路になる可能性があります。",
                    check_method="workflow YAML のテキストから pull_request_target trigger を確認しました。",
                    next_action="checkout 対象、secrets 利用、write permissions、外部 contributor の実行条件を確認してください。",
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
                    risk="必要以上の write 権限があると、侵害時の影響範囲が広がります。",
                    check_method="workflow YAML の permissions らしき行から write 権限候補を確認しました。",
                    next_action="job ごとに最小 permissions へ絞れるか確認してください。",
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
                    risk="main/master/latest 参照は、将来の upstream 変更で実行内容が変わる可能性があります。",
                    check_method="uses: owner/repo@ref 形式から mutable ref 候補を確認しました。",
                    next_action="可能なら tag や commit SHA へ固定してください。",
                )
            )

        if "tojson(secrets)" in lowered or "tojson(github.event)" in lowered:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions may print sensitive context",
                    path=path,
                    evidence="matched toJSON(secrets) or broad context dump",
                    risk="secrets やイベント payload をログに出力する可能性があります。",
                    check_method="workflow YAML のテキストから危険な context dump 候補を確認しました。",
                    next_action="ログ出力対象を必要最小限にし、secrets を含む context を出していないか確認してください。",
                )
            )

        if _contains_env_dump(lowered):
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    title="GitHub Actions environment dump candidate",
                    path=path,
                    evidence="matched printenv/env style command",
                    risk="環境変数の一覧をログに出すと、秘匿値周辺の情報が露出する可能性があります。",
                    check_method="workflow YAML のテキストから printenv / env 系の出力候補を確認しました。",
                    next_action="デバッグ用途なら一時的なものか、マスク済みか確認してください。",
                )
            )

        if _contains_remote_script(lowered):
            result.findings.append(
                Finding(
                    severity="HIGH",
                    title="GitHub Actions remote script execution candidate",
                    path=path,
                    evidence="matched curl/iwr piped to shell execution",
                    risk="取得したリモートスクリプトをその場で実行する supply-chain リスクがあります。",
                    check_method="workflow YAML のテキストから curl | sh / iwr | iex 形式を確認しました。",
                    next_action="固定バージョン、checksum、公式 action への置換ができないか確認してください。",
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
                    risk="publish や deploy は認証情報・権限・実行条件の確認が必要です。",
                    check_method="workflow YAML のテキストから publish/deploy 系コマンド候補を確認しました。",
                    next_action="実行 branch、手動承認、permissions、secrets の使い方を確認してください。",
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
