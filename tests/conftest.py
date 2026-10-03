"""Shared test helpers."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from alerttriage.models import Alert, Severity

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

BASE_TIME = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def make_alert(
    minutes: float = 0,
    source_ip: str = "203.0.113.5",
    alert_type: str = "brute_force_ssh",
    severity: Severity = Severity.HIGH,
    **kwargs,
) -> Alert:
    """Build an Alert ``minutes`` after BASE_TIME with sensible defaults."""
    return Alert(
        alert_id=kwargs.pop("alert_id", f"T-{next(_ids)}"),
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        source_ip=source_ip,
        alert_type=alert_type,
        severity=severity,
        description=kwargs.pop("description", "test alert"),
        **kwargs,
    )


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES
