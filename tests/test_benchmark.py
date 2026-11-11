from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from rung.models import Stage

_SPEC = importlib.util.spec_from_file_location(
    "rung_benchmark", Path(__file__).parent.parent / "scripts" / "benchmark.py"
)
assert _SPEC and _SPEC.loader
benchmark = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = benchmark  # dataclasses resolve types via sys.modules
_SPEC.loader.exec_module(benchmark)


def _row(expected: Stage, predicted: Stage):
    return benchmark.Row("repo", expected, predicted, 50.0)


def test_evaluate_counts_exact_and_adjacent():
    rows = [
        _row(Stage.inception, Stage.inception),
        _row(Stage.growth, Stage.stabilization),
        _row(Stage.maturity, Stage.inception),
        _row(Stage.maturity, Stage.maturity),
    ]
    ev = benchmark.evaluate(rows)
    assert (ev.total, ev.exact, ev.within_one) == (4, 2, 3)
    assert ev.accuracy == 0.5 and ev.adjacent_accuracy == 0.75
    assert ev.confusion[(Stage.maturity, Stage.inception)] == 1
    table = benchmark.format_confusion(ev)
    assert table.splitlines()[0].startswith("expected") and len(table.splitlines()) == 5


def test_evaluate_empty():
    ev = benchmark.evaluate([])
    assert ev.accuracy == 0.0 and ev.adjacent_accuracy == 0.0


def test_resolve_source_local_and_rejections(tmp_path):
    assert benchmark.resolve_source(str(tmp_path), tmp_path / "cache") == tmp_path
    with pytest.raises(ValueError):
        benchmark.resolve_source(str(tmp_path / "missing"), tmp_path / "cache")
    with pytest.raises(ValueError):
        benchmark.resolve_source("https://example.com/a b;rm -rf", tmp_path / "cache")
    assert not (tmp_path / "cache").exists()
