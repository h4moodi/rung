"""Command line interface: ``rung audit | rules | stages | baseline | serve``.

Exit codes: 0 clean, 1 findings at or above the threshold, 2 tool or configuration error.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import click
import typer
from rich.console import Console

from rung import __version__
from rung.config import BaselineEntry, Config, ConfigError, dump_baseline, load_config
from rung.engine import has_blocking_findings, run_audit
from rung.models import Severity
from rung.registry import Registry, load_builtin_rules
from rung.report import render_rules, render_stages, render_terminal, to_json, to_sarif

app = typer.Typer(
    name="rung",
    help="Stage-aware repository auditing against the Klotins et al. progression model.",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


class OutputFormat(StrEnum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"


class ListFormat(StrEnum):
    terminal = "terminal"
    json = "json"


def _load_registry() -> Registry:
    """Indirection so tests can inject a private registry."""
    return load_builtin_rules()


def _fail(message: str) -> typer.Exit:
    typer.echo(f"rung: error: {message}", err=True)
    return typer.Exit(2)


@contextmanager
def _errors_exit_2() -> Iterator[None]:
    """Turn every failure into a one-line stderr message and exit code 2."""
    try:
        yield
    except (click.exceptions.Exit, click.exceptions.Abort, click.ClickException):
        raise
    except ConfigError as exc:
        raise _fail(f"configuration: {exc}") from None
    except Exception as exc:
        if os.environ.get("RUNG_DEBUG") == "1":
            traceback.print_exc(file=sys.stderr)
        detail = " ".join(str(exc).split())[:300]
        raise _fail(f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__) from None


def _check_repo(path: Path) -> None:
    if not path.is_dir():
        raise _fail(f"not a directory: {path}")


def _check_output(output: Path | None, repo: Path, allow: bool) -> None:
    """Protect the read-only guarantee: refuse to write a report into the audited repo."""
    if output is None or allow:
        return
    if output.resolve().is_relative_to(repo.resolve()):
        raise _fail(
            f"refusing to write {output} inside the audited repository; "
            "choose a path outside it or pass --allow-write-in-repo"
        )


def _write(output: Path, text: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    typer.echo(f"wrote {output}", err=True)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"rung {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = False,
) -> None:
    """rung: find out which rung of the ladder a repository has reached."""


PathArg = Annotated[Path, typer.Argument(help="Repository to audit.")]
ConfigOpt = Annotated[
    Path | None, typer.Option("--config", "-c", help="Config file (default: PATH/rung.toml).")
]
AllowOpt = Annotated[
    bool, typer.Option("--allow-write-in-repo", help="Permit --output inside the audited repo.")
]


@app.command()
def audit(
    path: PathArg = Path("."),
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.terminal,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here, not stdout.")
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="Exit 1 at or above this severity.")
    ] = None,
    config: ConfigOpt = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colours.")] = False,
    show_all: Annotated[bool, typer.Option("--all", help="Do not truncate long lists.")] = False,
    allow_write_in_repo: AllowOpt = False,
) -> None:
    """Audit a repository and report its stage, scores, checklist and findings."""
    with _errors_exit_2():
        _check_repo(path)
        _check_output(output, path, allow_write_in_repo)
        cfg = load_config(path, config)
        if fail_on is not None:
            cfg = cfg.model_copy(update={"fail_on": fail_on})
        registry = _load_registry()
        report = run_audit(path, config=cfg, registry=registry)
        limit = None if show_all else 15
        if fmt is OutputFormat.terminal:
            if output is None:
                render_terminal(report, Console(no_color=no_color, highlight=False), limit=limit)
            else:
                console = Console(record=True, no_color=True, width=100, file=io.StringIO())
                render_terminal(report, console, limit=limit)
                _write(output, console.export_text())
        else:
            text = (
                to_json(report)
                if fmt is OutputFormat.json
                else json.dumps(to_sarif(report, registry=registry), indent=2) + "\n"
            )
            if output is None:
                typer.echo(text, nl=False)
            else:
                _write(output, text)
        blocking = has_blocking_findings(report, cfg.fail_on)
    raise typer.Exit(1 if blocking else 0)


@app.command()
def rules(
    fmt: Annotated[ListFormat, typer.Option("--format", "-f")] = ListFormat.terminal,
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
) -> None:
    """List every rule with its stage, severity and dimension."""
    with _errors_exit_2():
        registry = _load_registry()
        if fmt is ListFormat.json:
            payload = [
                {
                    "id": r.id,
                    "title": r.title,
                    "dimension": r.dimension.value,
                    "stage": r.stage.value,
                    "severity": r.severity.value,
                    "confidence": r.confidence.value,
                    "weight": r.weight,
                    "description": r.description,
                    "remediation": r.remediation,
                    "tags": list(r.tags),
                }
                for r in registry
            ]
            typer.echo(json.dumps(payload, indent=2))
        else:
            render_rules(registry, Console(no_color=no_color, highlight=False))


@app.command()
def stages(no_color: Annotated[bool, typer.Option("--no-color")] = False) -> None:
    """Explain the four stages of the progression model."""
    render_stages(Console(no_color=no_color, highlight=False))


@app.command()
def baseline(
    path: PathArg = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Baseline file to write.")] = ...,  # type: ignore[assignment]
    justification: Annotated[
        str, typer.Option("--justification", help="Why these findings are accepted.")
    ] = ...,  # type: ignore[assignment]
    config: ConfigOpt = None,
    allow_write_in_repo: AllowOpt = False,
) -> None:
    """Accept all current findings: write them to a baseline file with a justification.

    Entries already suppressed by the configured baseline are carried over with their
    original justification, so regenerating a baseline never loses one.
    """
    with _errors_exit_2():
        if not justification.strip():
            raise _fail("--justification must not be blank")
        _check_repo(path)
        _check_output(output, path, allow_write_in_repo)
        cfg: Config = load_config(path, config)
        report = run_audit(path, config=cfg, registry=_load_registry())
        entries = [
            BaselineEntry(
                fingerprint=s.fingerprint,
                rule_id=s.rule_id,
                justification=s.justification,
                path=s.path,
            )
            for s in report.suppressed
        ] + [
            BaselineEntry(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                justification=justification,
                path=f.location.path,
            )
            for f in report.findings
        ]
        _write(output, dump_baseline(entries))
        typer.echo(f"{len(entries)} finding(s) recorded in the baseline")


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8000,
) -> None:
    """Run the HTTP API (needs the `api` extra)."""
    if any(importlib.util.find_spec(name) is None for name in ("uvicorn", "fastapi")):
        raise _fail("the API needs the 'api' extra: pip install 'rung[api]'")
    import uvicorn

    uvicorn.run("rung.api.app:create_app", factory=True, host=host, port=port)
