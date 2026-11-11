"""Configuration: the ``Config`` model, ``rung.toml`` loading and baseline files.

Loading is read-only and strict about *values* (a bad type, an out-of-range threshold or a
baseline entry without a justification is a :class:`ConfigError`) but lenient about
*names*: unknown TOML keys are ignored, and rule ids are only checked later by the engine,
which knows the registry.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from rung.models import Severity

CONFIG_FILENAME = "rung.toml"

#: Upper bound for a baseline file; anything larger is not a hand-reviewed suppression list.
MAX_BASELINE_BYTES = 5_000_000


class ConfigError(Exception):
    """The configuration (or a baseline file it points at) is invalid. CLI exit code 2."""


class BaselineEntry(BaseModel):
    """One accepted finding. ``path`` is informational only; matching uses the fingerprint."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    fingerprint: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    justification: str
    path: str | None = None

    @field_validator("fingerprint", "rule_id", "justification", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("justification")
    @classmethod
    def _justified(cls, value: str) -> str:
        if not value:
            raise ValueError("a non-empty justification is required")
        return value


class Config(BaseModel):
    """Effective audit configuration. Immutable; derive variants with ``model_copy``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fail_on: Severity = Severity.high
    stage_threshold: float = Field(default=0.7, gt=0, le=1)
    max_commits: int = Field(default=5000, ge=1)
    disable: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    ignore_paths: tuple[str, ...] = ()
    baseline: tuple[BaselineEntry, ...] = ()

    @field_validator("stage_threshold", "max_commits", mode="before")
    @classmethod
    def _real_numbers_only(cls, value: object) -> object:
        # pydantic's lax mode would turn True into 1 and "5000" into 5000.
        if isinstance(value, bool | str):
            raise ValueError("must be a number")
        return value

    @field_validator("disable", "ignore_paths", mode="before")
    @classmethod
    def _list_of_strings(cls, value: object) -> object:
        if isinstance(value, str | bytes | Mapping):
            raise ValueError("must be a list of strings")
        return value

    @field_validator("ignore_paths")
    @classmethod
    def _no_blank_globs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not glob.strip() for glob in value):
            raise ValueError("ignore globs must not be blank")
        return value


def _format_validation_error(exc: ValidationError) -> str:
    """One line per problem, without echoing the offending input value."""
    problems = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        where = ".".join(str(part) for part in err["loc"])
        message = str(err["msg"]).removeprefix("Value error, ")
        problems.append(f"{where}: {message}" if where else message)
    return "; ".join(problems)


def _table(doc: Mapping[str, Any], name: str, origin: Path) -> Mapping[str, Any]:
    value = doc.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError(f"{origin}: [{name}] must be a table")
    return value


def parse_baseline(data: object, origin: Path | str = "baseline") -> tuple[BaselineEntry, ...]:
    """Validate decoded baseline JSON: a list of ``{fingerprint, rule_id, justification}``."""
    if not isinstance(data, list):
        raise ConfigError(f"{origin}: a baseline must be a JSON list of entries")
    entries: list[BaselineEntry] = []
    for index, item in enumerate(data):
        if not isinstance(item, Mapping):
            raise ConfigError(f"{origin}: entry {index} must be an object")
        try:
            entries.append(BaselineEntry.model_validate(dict(item)))
        except ValidationError as exc:
            raise ConfigError(f"{origin}: entry {index}: {_format_validation_error(exc)}") from None
    return tuple(entries)


def load_baseline(path: Path | str) -> tuple[BaselineEntry, ...]:
    """Read and validate a baseline file."""
    file = Path(path)
    try:
        if file.stat().st_size > MAX_BASELINE_BYTES:
            raise ConfigError(f"{file}: baseline file is larger than {MAX_BASELINE_BYTES} bytes")
        data = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{file}: baseline file not found") from None
    except OSError as exc:
        raise ConfigError(f"{file}: cannot read baseline file ({exc.strerror})") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ConfigError(f"{file}: baseline file is not valid UTF-8 JSON") from None
    return parse_baseline(data, file)


def dump_baseline(entries: Iterable[BaselineEntry]) -> str:
    """Serialise baseline entries deterministically (sorted, trailing newline)."""
    ordered = sorted(entries, key=lambda e: (e.rule_id, e.path or "", e.fingerprint))
    payload = [e.model_dump(mode="json", exclude_none=True) for e in ordered]
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _from_toml(doc: Mapping[str, Any], origin: Path, confine: Path | None = None) -> Config:
    core = _table(doc, "rung", origin)
    rules = _table(doc, "rules", origin)
    paths = _table(doc, "paths", origin)
    baseline = _table(doc, "baseline", origin)

    values: dict[str, Any] = {
        key: core[key] for key in ("fail_on", "stage_threshold", "max_commits") if key in core
    }
    if "disable" in rules:
        values["disable"] = rules["disable"]
    if "severity" in rules:
        values["severity_overrides"] = rules["severity"]
    if "ignore" in paths:
        values["ignore_paths"] = paths["ignore"]
    if "file" in baseline:
        ref = baseline["file"]
        if not isinstance(ref, str) or not ref.strip():
            raise ConfigError(f"{origin}: baseline.file must be a non-empty string")
        # Relative to the config file, so the config means the same from any cwd.
        target = origin.parent / ref
        if confine is not None and not target.resolve().is_relative_to(confine.resolve()):
            raise ConfigError(f"{origin}: baseline.file must stay inside the audited repository")
        values["baseline"] = load_baseline(target)
    try:
        return Config.model_validate(values)
    except ValidationError as exc:
        raise ConfigError(f"{origin}: {_format_validation_error(exc)}") from None


def load_config(repo_root: Path | str, explicit: Path | str | None = None) -> Config:
    """Resolve the configuration for an audit of ``repo_root``.

    ``explicit`` (``--config``) wins and must exist; otherwise ``<repo_root>/rung.toml`` is
    used when present; otherwise the defaults apply.
    """
    confine: Path | None = None
    if explicit is not None:
        origin = Path(explicit)
        if not origin.is_file():
            raise ConfigError(f"{origin}: config file not found")
    else:
        # A config found inside the audited repo is untrusted input: neither it nor the
        # baseline it names may resolve (e.g. through a symlink) outside the repo.
        confine = Path(repo_root)
        origin = confine / CONFIG_FILENAME
        if not origin.is_file():
            return Config()
        if not origin.resolve().is_relative_to(confine.resolve()):
            raise ConfigError(f"{origin}: config file must stay inside the audited repository")
    try:
        with origin.open("rb") as fh:
            doc = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"{origin}: cannot read config file ({exc.strerror})") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{origin}: invalid TOML: {exc}") from None
    return _from_toml(doc, origin, confine)
