"""DroidScope command line interface.

Commands that work entirely locally (``doctor``, ``analyze``, ``report``,
``compare``, ``rules``) operate directly on the database and artifact store, so
they need no running server. ``server`` and ``worker`` start the long-running
processes.
"""

from __future__ import annotations

import asyncio
import json as json_module
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from app import __version__
from app.core.config import get_settings
from app.core.enums import ReportFormat, ScanProfile
from app.core.logging import configure_logging

app = typer.Typer(
    name="droidscope",
    help="Android application security analysis framework.",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect and validate detection rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()
error_console = Console(stderr=True)

# Exit codes, so the CLI composes in a pipeline.
EXIT_OK = 0
EXIT_FINDINGS = 1  # analysis succeeded and found issues at or above the threshold
EXIT_ERROR = 2  # the command failed
EXIT_UNAVAILABLE = 3  # a required tool or capability is missing

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
SEVERITY_GLYPH = {
    "critical": "◆",
    "high": "▲",
    "medium": "■",
    "low": "●",
    "info": "·",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _emit_json(payload: Any) -> None:
    console.print_json(json_module.dumps(payload, default=str))


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    settings = get_settings()
    if verbose:
        from app.core.config import LogLevel

        settings.log_level = LogLevel.debug
    configure_logging(settings)


@app.command()
def version() -> None:
    """Print the DroidScope version."""
    console.print(f"DroidScope {__version__}")


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Check external tool availability and report what is missing.

    Exits 0 when every required tool is present, 3 when a required tool is
    missing. Optional tools reduce coverage but do not fail the check.
    """
    from app.core.capabilities import analyzer_availability, collect_capabilities

    capabilities = asyncio.run(collect_capabilities())
    caps = {cap.name: cap for cap in capabilities}
    analyzers = analyzer_availability(caps)
    required_missing = [cap for cap in capabilities if not cap.available and not cap.optional]

    if json_output:
        _emit_json(
            {
                "version": __version__,
                "capabilities": [cap.to_dict() for cap in capabilities],
                "analyzers": analyzers,
                "healthy": not required_missing,
            }
        )
        raise typer.Exit(EXIT_UNAVAILABLE if required_missing else EXIT_OK)

    table = Table(title=f"DroidScope {__version__} - environment check", title_justify="left")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Enables / how to install")

    for cap in capabilities:
        if cap.available:
            status = "[green]available[/green]"
            detail = ", ".join(cap.required_for) or (cap.detail or "")
        else:
            status = (
                "[red]missing[/red]" if not cap.optional else "[yellow]not installed[/yellow]"
            )
            detail = cap.install_hint or cap.detail or ""
        table.add_row(cap.name, status, cap.version or "-", detail[:70])
    console.print(table)

    analyzer_table = Table(title="Analyzer availability", title_justify="left")
    analyzer_table.add_column("Analyzer", style="bold")
    analyzer_table.add_column("Available")
    for name, available in sorted(analyzers.items()):
        analyzer_table.add_row(
            name, "[green]yes[/green]" if available else "[yellow]no[/yellow]"
        )
    console.print(analyzer_table)

    if required_missing:
        error_console.print(
            "[red]Required tooling is missing:[/red] "
            + ", ".join(cap.name for cap in required_missing)
        )
        raise typer.Exit(EXIT_UNAVAILABLE)
    console.print("[green]All required tooling is present.[/green]")


@app.command()
def analyze(
    apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    profile: ScanProfile = typer.Option(ScanProfile.standard, "--profile", "-p"),
    json_output: bool = typer.Option(False, "--json"),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit 1 when a finding of this severity or higher is present "
        "(critical|high|medium|low|none).",
    ),
    report: ReportFormat | None = typer.Option(
        None, "--report", help="Also generate a report in this format."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Where to write the report."),
) -> None:
    """Analyse an APK locally and print the findings.

    This runs the full pipeline in-process; no server or worker is required.
    """
    exit_code = asyncio.run(_analyze(apk, profile, json_output, fail_on, report, output))
    raise typer.Exit(exit_code)


async def _analyze(
    apk: Path,
    profile: ScanProfile,
    json_output: bool,
    fail_on: str,
    report_format: ReportFormat | None,
    output: Path | None,
) -> int:
    from app.database.session import create_all, session_scope
    from app.services.apk_service import ApkService
    from app.services.pipeline import ScanPipeline
    from app.services.scan_service import ScanService

    settings = get_settings()
    settings.ensure_directories()
    await create_all()

    async with session_scope() as session:
        ingest = await ApkService(session, settings=settings).ingest_file(apk, actor="cli")
        apk_row = ingest.apk
        creation = await ScanService(session, settings=settings).create(
            apk_row.id, profile=profile, reuse=False, actor="cli"
        )
        scan_id = creation.scan.id
        package = apk_row.package_name
        sha256 = apk_row.sha256

    if not json_output:
        console.print(
            f"Analysing [bold]{package or apk.name}[/bold] "
            f"(sha256 {sha256[:16]}…) with the {profile.value} profile"
        )

    async with session_scope() as session:
        outcome = await ScanPipeline(session, settings=settings).run(scan_id)

    async with session_scope() as session:
        from sqlalchemy import select

        from app.models import Finding

        findings = (
            (
                await session.execute(
                    select(Finding).where(Finding.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        findings = sorted(
            findings,
            key=lambda f: (
                -SEVERITY_ORDER[::-1].index(str(getattr(f.severity, "value", f.severity))),
                f.rule_id,
            ),
        )
        payload = {
            "scan_id": scan_id,
            "apk": {"package": package, "sha256": sha256, "file": apk.name},
            "status": outcome.status.value,
            "duration_seconds": outcome.duration_seconds,
            "findings_total": outcome.findings,
            "severity_counts": outcome.severity_counts,
            "risk": outcome.risk,
            "analyzers": outcome.executions,
            "limitations": outcome.limitations,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": str(getattr(f.severity, "value", f.severity)),
                    "confidence": str(getattr(f.confidence, "value", f.confidence)),
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "component": f.affected_component,
                }
                for f in findings
            ],
        }

        report_path: Path | None = None
        if report_format is not None:
            from app.reports.service import ReportService

            generated = await ReportService(session, settings=settings).generate(
                scan_id, report_format
            )
            store = ReportService(session, settings=settings).store
            data = store.read_bytes(generated.storage_key)
            report_path = output or Path.cwd() / (generated.filename or "report")
            report_path.write_bytes(data)
            payload["report"] = {"format": report_format.value, "path": str(report_path)}

    if json_output:
        _emit_json(payload)
    else:
        _print_analysis(payload, report_path)

    if outcome.status.value not in {"completed", "cancelled"}:
        return EXIT_ERROR
    return _threshold_exit(outcome.severity_counts, fail_on)


def _threshold_exit(counts: dict[str, int], fail_on: str) -> int:
    fail_on = (fail_on or "none").lower()
    if fail_on in {"none", ""}:
        return EXIT_OK
    if fail_on not in SEVERITY_ORDER:
        error_console.print(f"[red]unknown --fail-on value {fail_on!r}[/red]")
        return EXIT_ERROR
    threshold = SEVERITY_ORDER.index(fail_on)
    for index, severity in enumerate(SEVERITY_ORDER):
        if index <= threshold and counts.get(severity, 0):
            return EXIT_FINDINGS
    return EXIT_OK


def _print_analysis(payload: dict, report_path: Path | None) -> None:
    counts = payload["severity_counts"]
    risk = payload.get("risk") or {}

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Scan", payload["scan_id"])
    summary.add_row("Status", payload["status"])
    summary.add_row("Duration", f"{payload['duration_seconds']:.2f}s")
    summary.add_row("Findings", str(payload["findings_total"]))
    summary.add_row(
        "Risk",
        f"{risk.get('score', 'n/a')} / 100 ({risk.get('band', 'unknown')})",
    )
    console.print(summary)
    console.print()

    severity_line = "  ".join(
        f"[{SEVERITY_STYLE[s]}]{SEVERITY_GLYPH[s]} {s}: {counts.get(s, 0)}[/{SEVERITY_STYLE[s]}]"
        for s in SEVERITY_ORDER
    )
    console.print(severity_line)
    console.print()

    if payload["findings"]:
        table = Table(show_lines=False)
        table.add_column("Sev", width=9)
        table.add_column("Rule", style="bold", width=18)
        table.add_column("Finding")
        table.add_column("Location", style="dim")
        for finding in payload["findings"][:60]:
            severity = finding["severity"]
            location = finding.get("file_path") or finding.get("component") or ""
            if finding.get("line_number"):
                location = f"{location}:{finding['line_number']}"
            table.add_row(
                f"[{SEVERITY_STYLE[severity]}]{SEVERITY_GLYPH[severity]} {severity}[/{SEVERITY_STYLE[severity]}]",
                finding["rule_id"],
                finding["title"][:62],
                str(location)[-44:],
            )
        console.print(table)
        if len(payload["findings"]) > 60:
            console.print(f"[dim]… and {len(payload['findings']) - 60} more findings[/dim]")

    incomplete = [a for a in payload["analyzers"] if a["status"] != "completed"]
    if incomplete:
        console.print()
        console.print("[yellow]Analyzers that did not complete:[/yellow]")
        for item in incomplete:
            console.print(f"  {item['analyzer']}: {item['status']} - {item.get('error') or ''}")

    if payload.get("limitations"):
        console.print()
        console.print("[dim]Limitations:[/dim]")
        for limitation in payload["limitations"][:6]:
            console.print(f"  [dim]• {limitation}[/dim]")

    if report_path:
        console.print()
        console.print(f"[green]Report written to[/green] {report_path}")


@app.command()
def report(
    scan_id: str = typer.Argument(...),
    report_format: ReportFormat = typer.Option(ReportFormat.pdf, "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate a report for a stored scan."""

    async def run() -> int:
        from app.database.session import create_all, session_scope
        from app.reports.service import ReportService

        settings = get_settings()
        settings.ensure_directories()
        await create_all()
        async with session_scope() as session:
            service = ReportService(session, settings=settings)
            generated = await service.generate(scan_id, report_format)
            data = await service.read_payload(generated)
        destination = output or Path.cwd() / (generated.filename or "report")
        destination.write_bytes(data)
        console.print(
            f"[green]Wrote[/green] {destination} "
            f"({len(data)} bytes, sha256 {generated.sha256[:16]}…)"
        )
        return EXIT_OK

    raise typer.Exit(asyncio.run(run()))


@app.command()
def compare(
    baseline: Path = typer.Argument(..., exists=True, dir_okay=False),
    updated: Path = typer.Argument(..., exists=True, dir_okay=False),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Compare two APK files, analysing each if needed."""

    async def run() -> int:
        from app.database.session import create_all, session_scope
        from app.services.apk_service import ApkService
        from app.services.compare import CompareService
        from app.services.pipeline import ScanPipeline
        from app.services.scan_service import ScanService

        settings = get_settings()
        settings.ensure_directories()
        await create_all()

        ids: list[str] = []
        for path in (baseline, updated):
            async with session_scope() as session:
                ingest = await ApkService(session, settings=settings).ingest_file(path, actor="cli")
                apk_id = ingest.apk.id
                creation = await ScanService(session, settings=settings).create(
                    apk_id, profile=ScanProfile.quick, actor="cli"
                )
                scan_id = creation.scan.id
                reused = creation.reused
            if not reused:
                async with session_scope() as session:
                    await ScanPipeline(session, settings=settings).run(scan_id)
            ids.append(apk_id)

        async with session_scope() as session:
            comparison = await CompareService(session).compare(ids[0], ids[1])
            summary = dict(comparison.summary)
            result = dict(comparison.result)

        if json_output:
            _emit_json({"summary": summary, "result": result})
            return EXIT_OK

        table = Table(title="APK comparison", title_justify="left")
        table.add_column("Change", style="bold")
        table.add_column("Value")
        for key, value in summary.items():
            table.add_row(key.replace("_", " "), str(value))
        console.print(table)

        for label, key in (
            ("Permissions added", "permissions"),
            ("Components added", "components"),
        ):
            added = result.get(key, {}).get("added", [])
            if added:
                console.print(f"\n[bold]{label}[/bold]")
                for item in added[:15]:
                    console.print(f"  + {item}")
        return EXIT_OK

    raise typer.Exit(asyncio.run(run()))


@rules_app.command("list")
def rules_list(
    json_output: bool = typer.Option(False, "--json"),
    engine: str | None = typer.Option(None, "--engine"),
) -> None:
    """List loaded detection rules."""
    from app.detection.registry import load_builtin_rules, registry

    load_builtin_rules()
    metadata = sorted(registry.metadata(), key=lambda m: m.id)
    if engine:
        metadata = [m for m in metadata if m.engine == engine]

    if json_output:
        _emit_json([m.to_dict() for m in metadata])
        raise typer.Exit(EXIT_OK)

    table = Table(title=f"{len(metadata)} detection rules", title_justify="left")
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Engine", style="dim")
    table.add_column("Name")
    for meta in metadata:
        severity = meta.severity.value
        table.add_row(
            meta.id,
            f"[{SEVERITY_STYLE[severity]}]{severity}[/{SEVERITY_STYLE[severity]}]",
            meta.engine,
            meta.name[:58],
        )
    console.print(table)


@rules_app.command("validate")
def rules_validate(
    path: Path | None = typer.Option(None, "--path", help="Rule directory to validate."),
) -> None:
    """Validate every rule file and report errors.

    Exits 2 when any rule file is invalid, so this is usable in CI.
    """
    from app.analyzers.yara.analyzer import YaraRuleSet
    from app.detection.pattern_rules import validate_rules_dir

    specs, errors = validate_rules_dir(path)
    console.print(f"Pattern rules: [bold]{len(specs)}[/bold] valid, {len(errors)} invalid")
    for error in errors:
        error_console.print(f"  [red]{error}[/red]")

    yara_set = YaraRuleSet(path / "yara" if path else None)
    if YaraRuleSet.available():
        report = yara_set.load()
        console.print(
            f"YARA rules:    [bold]{report.rule_count}[/bold] compiled from "
            f"{len(report.files)} file(s), {len(report.errors)} error(s)"
        )
        for error in report.errors:
            error_console.print(f"  [red]{error}[/red]")
        if report.errors:
            errors.extend(report.errors)
    else:
        console.print("[yellow]YARA rules not validated: yara-python is not installed[/yellow]")

    if errors:
        raise typer.Exit(EXIT_ERROR)
    console.print("[green]All rule files are valid.[/green]")


@app.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the API server."""
    import uvicorn

    console.print(f"Starting DroidScope API on http://{host}:{port} (docs at /docs)")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload, log_level="info")


@app.command()
def worker(
    once: bool = typer.Option(False, "--once", help="Process the queue once, then exit."),
    max_jobs: int | None = typer.Option(None, "--max-jobs"),
) -> None:
    """Start the background analysis worker."""
    from app.jobs.worker import run_worker

    processed = asyncio.run(run_worker(once=once, max_jobs=max_jobs))
    console.print(f"Worker exited after processing {processed} job(s)")


@app.command("init-db")
def init_db() -> None:
    """Create database tables (development convenience)."""

    async def run() -> None:
        from app.database.session import create_all

        settings = get_settings()
        settings.ensure_directories()
        await create_all()

    asyncio.run(run())
    console.print(f"[green]Database ready at[/green] {get_settings().resolved_database_url}")


def run() -> None:  # pragma: no cover - console script entry point
    try:
        app()
    except KeyboardInterrupt:
        error_console.print("interrupted")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    run()
