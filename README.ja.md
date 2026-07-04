# agent-repo-safety-check

言語: [English](README.md) | 日本語

AIコーディングエージェントに作業を頼む前に、ローカルリポジトリの危なそうな設定を読み取り専用で確認する小さなチェックツールです。

このツールは「侵害された」と断定するものではありません。npmの自動実行スクリプト、広すぎるGitHub Actions権限、AIエージェント用のフック設定、secretっぽいローカルファイル、OSS公開前に足りない基本ファイルなどを、メンテナーが確認するための候補として出します。

## 何のためのツール？

AIエージェントはコードを速く直してくれますが、作業前にリポジトリ内の設定をちゃんと見ておかないと、次のようなリスクに気づきにくいことがあります。

- `npm install` や publish 時に自動実行されるnpm lifecycle script
- `.codex` や `.claude` にあるフック、コマンド、シェル実行、MCP設定
- VS Codeのフォルダオープン時に動くtask
- GitHub Actionsの広すぎる権限、`pull_request_target`、remote script実行、deployコマンド
- `.env`、秘密鍵、credential、secretのバックアップarchiveっぽいファイル
- OSS公開前に欲しいREADME、LICENSE、CI、SECURITY、sampleなどの不足

`agent-repo-safety-check` は、そういう項目をローカルで軽く確認するためのpreflight scanです。

## インストールと実行

checkoutしたこのリポジトリから実行する場合:

```powershell
uv run agent-repo-safety-check scan --target F:\path\to\project
```

`uv` を使わない場合は、仮想環境を作ってから実行します。

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\agent-repo-safety-check scan --target F:\path\to\project
```

開発中に手早く動かすだけなら、Python moduleとしても実行できます。

```powershell
python -m agent_repo_safety_check scan --target F:\path\to\project
```

標準のprofileは `agent` です。AIエージェントに作業を頼む前の安全確認に寄せたチェックをします。

OSS公開前の準備状況も見たい場合は `oss` profileを使います。

```powershell
uv run agent-repo-safety-check scan --target F:\path\to\project --profile oss
```

## 出力

標準では、次の2つのレポートを書き出します。

```text
outputs/YYYY-MM-DD-security-check.md
outputs/YYYY-MM-DD-security-check.json
```

Markdownは人間が読む用、JSONは将来の自動化やdashboard用です。JSON形式の詳細は [docs/JSON_REPORT.md](docs/JSON_REPORT.md) にあります。

注意: 生成されたレポートにはローカルパスなどが含まれる可能性があります。公開する前に必ず内容を確認してください。

## 安全設計

- 読み取り専用: scan対象のprojectは変更しません。
- secret-safe: secretっぽいファイルの中身は読んだり表示したりしません。
- findingは断定ではなく「確認候補」です。
- hidden scoringではなく、理由が追えるheuristicを優先します。
- false positiveは想定内です。各findingには次に人間が確認することを書きます。

## 現在のチェック内容

- Node/npm: lifecycle script、watch-list package、floating version、remote/Git dependency、lockfile内のremote参照
- AI agent settings: `.codex` と `.claude` 内のhook、command、shell、network tool、MCP server、env key、permission候補
- VS Code: `tasks.json` の自動実行やshell/network command候補
- GitHub Actions: OIDC permission、広いwrite permission、`pull_request_target`、mutable action ref、context/env dump、remote script実行、publish/deploy語
- Local files: `.env*`、key file、credential file、zip/7z archive候補、Git tracked状態
- `oss` profileのみ: README、LICENSE、CI workflow、CONTRIBUTING、SECURITY、samples/examples、`pyproject.toml` metadata

## profileの使い分け

`agent` は標準profileです。AIコーディングエージェントに作業を頼む前に、実行されうる設定、automation、dependency、secretっぽいローカルファイルを中心に見ます。

`oss` は `agent` のチェックに加えて、公開リポジトリとしての基本的な準備も見ます。公開前、release準備、外部contributorに見せる前などに使います。

## Codexと一緒に使う流れ

Codexや別のAIエージェントに作業を頼む前に、次の順番で使う想定です。

1. `agent-repo-safety-check scan --target <repo>` をローカルで実行する。
2. HIGH と MEDIUM のfindingを先に確認する。
3. 公開やrelease前なら `--profile oss` も使う。
4. レポートを外に出す前に、private pathやsensitive contextがないか確認する。

このツールはAIエージェントを無条件に信頼するためのものではありません。作業前に、人間のメンテナーが危なそうな設定に気づきやすくするための補助です。

## サンプル

意図的に危ない設定を入れたfixtureがあります。

```powershell
uv run agent-repo-safety-check scan --target samples\risky-node-project --profile oss
```

期待されるfindingには、npm lifecycle script、GitHub Actionsのremote script実行、`pull_request_target`、VS Codeのfolder-open task、テスト用に追加されたsecret-like/archive候補などがあります。

公開して安全な要約はこちらです。

- [docs/sample-reports/risky-node-project-agent.md](docs/sample-reports/risky-node-project-agent.md)
- [docs/sample-reports/public-repository-scan-examples.md](docs/sample-reports/public-repository-scan-examples.md)

## 開発

テスト実行:

```powershell
python -m unittest discover -s tests -p "test*.py"
```

このprojectは、小さくて説明しやすいrule-based scannerとして作っています。新しいcheckを追加するときは、次の点が分かるようにしてください。

- 何を見たか
- なぜ気にする必要があるか
- 次に人間が何を確認すべきか
- secretやsensitive valueを読んだり表示したりしないか

Agent configのチェックは、matched key pathやcommand-like termだけを表示します。TOML/JSON設定内のenv値やsecretっぽい値は表示しません。

## やらないこと

- 脆弱性scannerではありません。
- source codeやreportを外部にuploadしません。
- auto-fix、隔離、削除、書き換えはしません。
- 公開前の人間レビューを置き換えるものではありません。

## ライセンス

MIT
