#!/usr/bin/env python3
"""Diagnostic-accuracy harness for the rung evaluation study.

Reads a CSV of ``source,expected_stage[,notes]`` rows, audits every repository with rung
and compares the classified stage with the expected (ground-truth) label.

    python scripts/benchmark.py evaluation/benchmark.csv --out evaluation/results.csv

``source`` is a local path or an ``https://`` git URL. Remote repositories are cloned once
into ``--cache`` (default ``.rung-cache/``, git-ignored) and reused on later runs; nothing
is ever written inside an audited repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rung.models import STAGE_ORDER, Stage

_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class Row:
    source: str
    expected: Stage
    predicted: Stage
    overall_score: float

    @property
    def distance(self) -> int:
        """Rungs between the expected and the predicted stage (0 = exact)."""
        return abs(self.expected.order - self.predicted.order)


@dataclass(frozen=True)
class Evaluation:
    total: int
    exact: int
    within_one: int
    confusion: dict[tuple[Stage, Stage], int]  # (expected, predicted) -> count

    @property
    def accuracy(self) -> float:
        return self.exact / self.total if self.total else 0.0

    @property
    def adjacent_accuracy(self) -> float:
        return self.within_one / self.total if self.total else 0.0


def evaluate(rows: list[Row]) -> Evaluation:
    """Exact accuracy, within-one-rung accuracy and the confusion matrix."""
    return Evaluation(
        total=len(rows),
        exact=sum(r.distance == 0 for r in rows),
        within_one=sum(r.distance <= 1 for r in rows),
        confusion=dict(Counter((r.expected, r.predicted) for r in rows)),
    )


def format_confusion(ev: Evaluation) -> str:
    width = max(len(s.value) for s in STAGE_ORDER) + 2
    header = "expected \\ predicted".ljust(22) + "".join(s.value.rjust(width) for s in STAGE_ORDER)
    lines = [header]
    for exp in STAGE_ORDER:
        cells = "".join(str(ev.confusion.get((exp, pred), 0)).rjust(width) for pred in STAGE_ORDER)
        lines.append(exp.value.ljust(22) + cells)
    return "\n".join(lines)


def resolve_source(source: str, cache: Path) -> Path:
    """Return a local directory for ``source``, cloning https URLs into ``cache``."""
    if not source.startswith("https://"):
        path = Path(source).expanduser()
        if not path.is_dir():
            raise ValueError(f"not a directory: {source}")
        return path
    if not _URL_RE.match(source):
        raise ValueError(f"unsupported repository URL: {source}")
    name = source.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    dest = cache / f"{name}-{hashlib.sha256(source.encode()).hexdigest()[:10]}"
    if not dest.exists():
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--", source, str(dest)],
            check=True,
            timeout=900,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_TERMINAL_PROMPT": "0"},
        )
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("benchmark", type=Path, help="CSV with source,expected_stage columns")
    parser.add_argument("--out", type=Path, help="write per-repository results to this CSV")
    parser.add_argument("--cache", type=Path, default=Path(".rung-cache"))
    args = parser.parse_args(argv)

    from rung.engine import run_audit  # imported late so --help works without the engine

    rows: list[Row] = []
    with args.benchmark.open(newline="", encoding="utf-8") as fh:
        for record in csv.DictReader(fh):
            source = record["source"].strip()
            try:
                expected = Stage(record["expected_stage"].strip().lower())
                report = run_audit(resolve_source(source, args.cache), source=source)
            except (ValueError, subprocess.SubprocessError) as exc:
                print(f"skip {source}: {exc}", file=sys.stderr)
                continue
            row = Row(source, expected, report.classification.stage, report.overall_score)
            rows.append(row)
            mark = "ok " if row.distance == 0 else f"off by {row.distance}"
            print(f"{mark:9} {source}: expected {expected.value}, got {row.predicted.value}")

    if not rows:
        print("no repositories were audited", file=sys.stderr)
        return 2

    ev = evaluate(rows)
    print()
    print(format_confusion(ev))
    print()
    print(f"exact accuracy:      {ev.exact}/{ev.total} = {ev.accuracy:.1%}")
    print(f"within one rung:     {ev.within_one}/{ev.total} = {ev.adjacent_accuracy:.1%}")

    if args.out:
        with args.out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["source", "expected_stage", "predicted_stage", "distance", "score"])
            for r in rows:
                writer.writerow(
                    [r.source, r.expected.value, r.predicted.value, r.distance, r.overall_score]
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
