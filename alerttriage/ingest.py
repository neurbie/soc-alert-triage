"""Stage 1 - Ingest: load raw JSON alerts and normalize them into ``Alert`` objects.

Real alert feeds are messy. This stage is deliberately forgiving about *format*
(severity vocabularies, timestamp styles, alert-type spelling) and strict about
*content* (an alert with no source IP or no timestamp cannot be triaged).

Bad records never crash the run. Each one is returned as a ``RejectedAlert``
with a reason, and the report lists them so nothing is silently dropped. In a
SOC, an alert that vanishes in the pipeline is worse than a noisy one.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import Alert, Severity

REQUIRED_FIELDS = ("timestamp", "source_ip", "alert_type", "severity", "description")

# Every severity spelling we have seen in the wild, mapped to the normalized scale.
_SEVERITY_ALIASES: dict[str, Severity] = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
}

# Numeric severities are treated as a 1-5 scale (1 = info ... 5 = critical),
# which is the most common convention (e.g. Suricata uses 1-3 inverted, but most
# SIEMs normalize to an ascending scale before export).
_NUMERIC_SEVERITY: dict[int, Severity] = {
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}


@dataclass(frozen=True)
class RejectedAlert:
    """A record that failed validation, with enough context to find it again."""

    source_file: str
    index: int
    reason: str
    raw: Any


class IngestError(Exception):
    """Raised when a whole file is unusable (missing, not JSON, wrong shape)."""


# --------------------------------------------------------------------------- #
# Field normalizers. Each raises ValueError with a human-readable message.
# --------------------------------------------------------------------------- #


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 strings or Unix epoch numbers into an aware UTC datetime.

    Naive timestamps (no offset) are assumed to be UTC, which is the only safe
    assumption for security telemetry.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise ValueError(f"invalid timestamp {value!r}")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid timestamp {value!r}")

    text = value.strip()
    if text.endswith(("Z", "z")):  # fromisoformat handles 'Z' only on 3.11+
        text = text[:-1] + "+00:00"
    try:
        ts = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"unparseable timestamp {value!r} (expected ISO-8601)") from None

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def parse_severity(value: Any) -> Severity:
    """Map strings like ``"High"``/``"crit"`` or integers 1-5 onto ``Severity``."""
    if isinstance(value, bool):
        raise ValueError(f"invalid severity {value!r}")
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        number = int(value)
        if number in _NUMERIC_SEVERITY:
            return _NUMERIC_SEVERITY[number]
        raise ValueError(f"numeric severity {number} out of range (expected 1-5)")
    if isinstance(value, str):
        key = value.strip().lower()
        if key in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[key]
    raise ValueError(f"unknown severity {value!r}")


def normalize_alert_type(value: Any) -> str:
    """``"Brute Force - SSH"`` -> ``"brute_force_ssh"``.

    Normalizing here is what lets dedup treat differently-spelled copies of the
    same detection as one indicator.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid alert_type {value!r}")
    slug = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    if not slug:
        raise ValueError(f"invalid alert_type {value!r}")
    return slug


def normalize_ip(value: Any) -> str:
    """Validate an IPv4/IPv6 address and return its canonical string form."""
    if not isinstance(value, str):
        raise ValueError(f"invalid source_ip {value!r}")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError(f"invalid source_ip {value!r}") from None


def _optional_str(record: dict, key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# --------------------------------------------------------------------------- #
# Record- and file-level loading
# --------------------------------------------------------------------------- #


def parse_alert(record: Any, fallback_id: str) -> Alert:
    """Validate and normalize a single raw alert dict.

    Raises ``ValueError`` describing the *first* problem found.
    """
    if not isinstance(record, dict):
        raise ValueError(f"alert must be a JSON object, got {type(record).__name__}")

    missing = [f for f in REQUIRED_FIELDS if record.get(f) in (None, "")]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")

    description = str(record["description"]).strip()
    if not description:
        raise ValueError("missing required field(s): description")

    return Alert(
        alert_id=_optional_str(record, "alert_id") or _optional_str(record, "id") or fallback_id,
        timestamp=parse_timestamp(record["timestamp"]),
        source_ip=normalize_ip(record["source_ip"]),
        alert_type=normalize_alert_type(record["alert_type"]),
        severity=parse_severity(record["severity"]),
        description=description,
        dest_ip=_optional_str(record, "dest_ip"),
        hostname=_optional_str(record, "hostname"),
        user=_optional_str(record, "user"),
        sensor=_optional_str(record, "sensor") or _optional_str(record, "source"),
    )


def _extract_records(data: Any, path: Path) -> list[Any]:
    """Accept either a bare JSON array or an object with an ``"alerts"`` array."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("alerts"), list):
        return data["alerts"]
    raise IngestError(
        f"{path}: expected a JSON array of alerts or an object with an 'alerts' array"
    )


def load_alerts(paths: Iterable[str | Path]) -> tuple[list[Alert], list[RejectedAlert]]:
    """Load one or more alert batch files.

    Returns ``(alerts, rejected)``. Alerts from all files are merged into one
    list, so several sensor exports can be triaged as a single queue.
    """
    alerts: list[Alert] = []
    rejected: list[RejectedAlert] = []

    for path in map(Path, paths):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise IngestError(f"{path}: file not found") from None
        except json.JSONDecodeError as exc:
            raise IngestError(f"{path}: invalid JSON ({exc})") from None

        for index, record in enumerate(_extract_records(data, path)):
            fallback_id = f"{path.stem}#{index}"
            try:
                alerts.append(parse_alert(record, fallback_id))
            except ValueError as exc:
                rejected.append(RejectedAlert(path.name, index, str(exc), record))

    return alerts, rejected
