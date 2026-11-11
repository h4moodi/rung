from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rung.config import (
    BaselineEntry,
    Config,
    ConfigError,
    dump_baseline,
    load_baseline,
    load_config,
)
from rung.models import Severity

FULL = """
[rung]
fail_on = "medium"
stage_threshold = 0.8
max_commits = 250
some_future_key = true

[rules]
disable = ["COM004", "DOC009"]
[rules.severity]
DOC003 = "low"

[paths]
ignore = ["vendor/**", "**/*.min.js"]

[baseline]
file = "rung-baseline.json"

[unknown_table]
x = 1
"""


def _write(root: Path, toml: str, baseline: object | None = None) -> Path:
    (root / "rung.toml").write_text(toml, encoding="utf-8")
    if baseline is not None:
        (root / "rung-baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
    return root


def test_defaults_when_no_config_file(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == Config()
    assert cfg.fail_on is Severity.high and cfg.stage_threshold == 0.7
    assert cfg.max_commits == 5000 and cfg.disable == frozenset()
    assert cfg.severity_overrides == {} and cfg.ignore_paths == () and cfg.baseline == ()


def test_full_config_is_loaded_and_unknown_keys_are_ignored(tmp_path):
    entry = {"fingerprint": "abc123", "rule_id": "DOC001", "justification": " pilot only "}
    cfg = load_config(_write(tmp_path, FULL, [entry]))
    assert cfg.fail_on is Severity.medium
    assert cfg.stage_threshold == 0.8 and cfg.max_commits == 250
    assert cfg.disable == frozenset({"COM004", "DOC009"})
    assert cfg.severity_overrides == {"DOC003": Severity.low}
    assert cfg.ignore_paths == ("vendor/**", "**/*.min.js")
    assert cfg.baseline == (
        BaselineEntry(fingerprint="abc123", rule_id="DOC001", justification="pilot only"),
    )


def test_unknown_rule_ids_are_not_a_load_error(tmp_path):
    cfg = load_config(_write(tmp_path, '[rules]\ndisable = ["NOPE999"]\n'))
    assert cfg.disable == frozenset({"NOPE999"})


def test_explicit_path_wins_and_baseline_is_relative_to_it(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, '[rung]\nfail_on = "low"\n')
    elsewhere = tmp_path / "ci"
    elsewhere.mkdir()
    (elsewhere / "strict.toml").write_text(
        '[rung]\nfail_on = "critical"\n[baseline]\nfile = "accepted.json"\n', encoding="utf-8"
    )
    (elsewhere / "accepted.json").write_text(
        json.dumps([{"fingerprint": "f", "rule_id": "SEC001", "justification": "test key"}]),
        encoding="utf-8",
    )
    cfg = load_config(repo, elsewhere / "strict.toml")
    assert cfg.fail_on is Severity.critical and cfg.baseline[0].rule_id == "SEC001"


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(tmp_path, tmp_path / "absent.toml")


@pytest.mark.parametrize(
    "toml",
    [
        '[rung]\nfail_on = "catastrophic"\n',
        "[rung]\nfail_on = 3\n",
        "[rung]\nstage_threshold = 0\n",
        "[rung]\nstage_threshold = 1.5\n",
        '[rung]\nstage_threshold = "0.7"\n',
        "[rung]\nstage_threshold = true\n",
        "[rung]\nmax_commits = 0\n",
        "[rung]\nmax_commits = 2.5\n",
        '[rung]\nmax_commits = "many"\n',
        '[rules]\ndisable = "COM004"\n',
        "[rules]\ndisable = [1, 2]\n",
        '[rules]\nseverity = ["DOC003"]\n',
        '[rules.severity]\nDOC003 = "meh"\n',
        '[paths]\nignore = "vendor/**"\n',
        '[paths]\nignore = [""]\n',
        'rung = "not a table"\n',
        "[baseline]\nfile = 7\n",
        "[rung\nbroken",
    ],
)
def test_bad_values_raise_config_error(tmp_path, toml):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, toml))


def test_threshold_of_exactly_one_and_integer_form_are_accepted(tmp_path):
    assert load_config(_write(tmp_path, "[rung]\nstage_threshold = 1\n")).stage_threshold == 1.0


@pytest.mark.parametrize(
    "baseline",
    [
        [{"fingerprint": "f", "rule_id": "DOC001"}],
        [{"fingerprint": "f", "rule_id": "DOC001", "justification": "   "}],
        [{"fingerprint": "f", "rule_id": "DOC001", "justification": 5}],
        [{"fingerprint": "", "rule_id": "DOC001", "justification": "ok"}],
        [{"rule_id": "DOC001", "justification": "ok"}],
        ["just a string"],
        {"fingerprint": "f", "rule_id": "DOC001", "justification": "ok"},
    ],
)
def test_invalid_baseline_entries_raise_config_error(tmp_path, baseline):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, '[baseline]\nfile = "rung-baseline.json"\n', baseline))


def test_missing_or_malformed_baseline_file(tmp_path):
    _write(tmp_path, '[baseline]\nfile = "rung-baseline.json"\n')
    with pytest.raises(ConfigError, match="baseline file not found"):
        load_config(tmp_path)
    (tmp_path / "rung-baseline.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid UTF-8 JSON"):
        load_config(tmp_path)


def test_error_messages_name_the_file_and_key_but_not_the_value(tmp_path):
    with pytest.raises(ConfigError) as info:
        load_config(_write(tmp_path, '[rung]\nfail_on = "catastrophic"\n'))
    text = str(info.value)
    assert "rung.toml" in text and "fail_on" in text and "catastrophic" not in text


def test_config_is_frozen_and_validated_when_built_directly():
    cfg = Config(disable=["DOC001"], severity_overrides={"DOC002": "low"})
    assert cfg.disable == frozenset({"DOC001"})
    assert cfg.severity_overrides["DOC002"] is Severity.low
    with pytest.raises(ValidationError):
        cfg.fail_on = Severity.low  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Config(stage_threshold=0)
    with pytest.raises(ValidationError):
        Config(not_a_field=1)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        BaselineEntry(fingerprint="f", rule_id="DOC001", justification="")
    assert cfg.model_copy(update={"fail_on": Severity.low}).fail_on is Severity.low


def test_baseline_dump_round_trips_sorted(tmp_path):
    entries = [
        BaselineEntry(fingerprint="b", rule_id="SEC001", justification="j2", path="z.py"),
        BaselineEntry(fingerprint="a", rule_id="DOC001", justification="j1"),
    ]
    text = dump_baseline(entries)
    assert text.endswith("\n") and text == dump_baseline(reversed(entries))
    target = tmp_path / "b.json"
    target.write_text(text, encoding="utf-8")
    loaded = load_baseline(target)
    assert [e.rule_id for e in loaded] == ["DOC001", "SEC001"]
    assert loaded[1].path == "z.py" and "path" not in json.loads(text)[0]


def test_repo_config_cannot_point_baseline_outside_the_repo(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("[]")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "rung.toml").write_text('[baseline]\nfile = "../outside.json"\n')
    with pytest.raises(ConfigError, match="inside the audited repository"):
        load_config(repo)
    # An explicit --config is the operator's own file and may reference any path.
    assert load_config(repo, repo / "rung.toml").baseline == ()
