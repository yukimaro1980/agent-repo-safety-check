from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path
from typing import Optional

try:
    import typer
except Exception:  # pragma: no cover - fallback for minimal Python environments
    typer = None

from .models import ScanProfile, ScanResult
from .scanner import run_scan
from .writers.json_writer import write_json
from .writers.markdown import write_markdown


def scan_command(target: Path, output_dir: Path = Path("outputs"), profile: ScanProfile = "agent") -> ScanResult:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"target is not a directory: {target}")

    today = date.today().isoformat()
    output_dir.mkdir(parents=True, exist_ok=True)
    result = run_scan(target=target, scanned_at=today, profile=profile)

    md_path = output_dir / f"{today}-security-check.md"
    json_path = output_dir / f"{today}-security-check.json"
    write_markdown(result, md_path)
    write_json(result, json_path)
    result.output_markdown = str(md_path.resolve())
    result.output_json = str(json_path.resolve())
    return result


def _typer_main() -> None:
    app = typer.Typer(help="Read-only local project security checklist.")

    @app.callback()
    def root() -> None:
        """Read-only local project security checklist."""

    @app.command()
    def scan(
        target: Path = typer.Option(..., "--target", "-t", exists=True, file_okay=False),
        output_dir: Path = typer.Option(Path("outputs"), "--output-dir", "-o"),
        profile: str = typer.Option("agent", "--profile", "-p", help="Scan profile: agent or oss"),
    ) -> None:
        result = scan_command(target=target, output_dir=output_dir, profile=_parse_profile(profile))
        typer.echo(f"Scan completed: {result.target}")
        typer.echo(f"Profile: {result.profile}")
        typer.echo(f"Markdown: {result.output_markdown}")
        typer.echo(f"JSON: {result.output_json}")
        typer.echo(
            "Findings: "
            f"HIGH={result.count_by_severity('HIGH')} "
            f"MEDIUM={result.count_by_severity('MEDIUM')} "
            f"LOW={result.count_by_severity('LOW')} "
            f"INFO={result.count_by_severity('INFO')}"
        )

    app()


def _argparse_main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Read-only local project security checklist.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--target", "-t", required=True, type=Path)
    scan_parser.add_argument("--output-dir", "-o", default=Path("outputs"), type=Path)
    scan_parser.add_argument("--profile", "-p", default="agent", choices=["agent", "oss"])
    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan_command(target=args.target, output_dir=args.output_dir, profile=_parse_profile(args.profile))
        print(f"Scan completed: {result.target}")
        print(f"Profile: {result.profile}")
        print(f"Markdown: {result.output_markdown}")
        print(f"JSON: {result.output_json}")
        print(
            "Findings: "
            f"HIGH={result.count_by_severity('HIGH')} "
            f"MEDIUM={result.count_by_severity('MEDIUM')} "
            f"LOW={result.count_by_severity('LOW')} "
            f"INFO={result.count_by_severity('INFO')}"
        )


def main(argv: Optional[list[str]] = None) -> None:
    if typer is not None and argv is None:
        _typer_main()
        return
    _argparse_main(argv)


def _parse_profile(value: str) -> ScanProfile:
    if value not in {"agent", "oss"}:
        raise ValueError(f"unsupported profile: {value}")
    return value  # type: ignore[return-value]
