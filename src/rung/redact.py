"""Secret redaction. A detected credential must never reach output, logs or tests."""

from __future__ import annotations

import hashlib


def redact(value: str, keep: int = 4) -> str:
    """Return a display-safe form of a secret: a short prefix plus a length marker.

    ``keep`` is capped so that at most a quarter of the value is ever revealed.

    >>> redact("AKIAABCDEFGHIJKLMNOP")
    'AKIA****************(20 chars)'
    """
    keep = max(0, min(keep, len(value) // 4))
    return f"{value[:keep]}{'*' * min(len(value) - keep, 16)}({len(value)} chars)"


def secret_anchor(value: str) -> str:
    """A stable, non-reversible identifier for a secret value, for fingerprints."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
