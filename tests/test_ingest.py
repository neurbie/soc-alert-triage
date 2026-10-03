import json
from datetime import datetime, timezone

import pytest

from alerttriage.ingest import (
    IngestError,
    load_alerts,
    normalize_alert_type,
    parse_alert,
    parse_severity,
    parse_timestamp,
)
from alerttriage.models import Severity

VALID = {
    "timestamp": "2026-09-28T02:10:00Z",
    "source_ip": "203.0.113.45",
    "alert_type": "Brute Force - SSH",
    "severity": "High",
    "description": "failed logins",
}


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("info", Severity.INFO),
        ("Informational", Severity.INFO),
        ("LOW", Severity.LOW),
        ("med", Severity.MEDIUM),
        (" High ", Severity.HIGH),
        ("crit", Severity.CRITICAL),
        (1, Severity.INFO),
        (5, Severity.CRITICAL),
        ("4", Severity.HIGH),
    ],
)
def test_parse_severity_accepts_common_vocabularies(raw, expected):
    assert parse_severity(raw) is expected


@pytest.mark.parametrize("raw", ["urgent", 0, 6, True, None, 3.5])
def test_parse_severity_rejects_unknown(raw):
    with pytest.raises(ValueError):
        parse_severity(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "2026-09-28T02:10:00Z",
        "2026-09-28T02:10:00+00:00",
        "2026-09-28T04:10:00+02:00",
        "2026-09-28T02:10:00",  # naive -> assumed UTC
        1790561400,  # epoch seconds
    ],
)
def test_parse_timestamp_normalizes_to_utc(raw):
    assert parse_timestamp(raw) == datetime(2026, 9, 28, 2, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize("raw", ["yesterday", "", None, True, "28/09/2026 02:10"])
def test_parse_timestamp_rejects_garbage(raw):
    with pytest.raises(ValueError):
        parse_timestamp(raw)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Brute Force - SSH", "brute_force_ssh"),
        ("brute_force_ssh", "brute_force_ssh"),
        ("  C2 Beacon ", "c2_beacon"),
        ("SQL-Injection", "sql_injection"),
    ],
)
def test_alert_type_normalization_makes_spellings_collide(raw, expected):
    assert normalize_alert_type(raw) == expected


def test_parse_alert_happy_path_and_optional_fields():
    alert = parse_alert({**VALID, "id": "X-1", "hostname": "bastion-01", "user": " root ", "source": "wazuh"}, "fb")
    assert alert.alert_id == "X-1"
    assert alert.alert_type == "brute_force_ssh"
    assert alert.severity is Severity.HIGH
    assert alert.hostname == "bastion-01"
    assert alert.user == "root"
    assert alert.sensor == "wazuh"  # "source" accepted as an alias for "sensor"


def test_parse_alert_uses_fallback_id():
    assert parse_alert(VALID, "batch#3").alert_id == "batch#3"


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"source_ip": None}, "missing required field(s): source_ip"),
        ({"description": ""}, "missing required field(s): description"),
        ({"source_ip": "999.1.1.1"}, "invalid source_ip"),
        ({"severity": "urgent"}, "unknown severity"),
        ({"timestamp": "nope"}, "unparseable timestamp"),
    ],
)
def test_parse_alert_reports_first_problem(patch, message):
    with pytest.raises(ValueError, match=message.replace("(", r"\(").replace(")", r"\)")):
        parse_alert({**VALID, **patch}, "fb")


def test_load_alerts_accepts_array_and_object_and_collects_rejections(tmp_path):
    arr = tmp_path / "a.json"
    arr.write_text(json.dumps([VALID, {**VALID, "source_ip": "bad"}, "not an object"]))
    obj = tmp_path / "b.json"
    obj.write_text(json.dumps({"batch_id": "x", "alerts": [VALID]}))

    alerts, rejected = load_alerts([arr, obj])

    assert len(alerts) == 2
    assert [(r.source_file, r.index) for r in rejected] == [("a.json", 1), ("a.json", 2)]


def test_load_alerts_raises_on_unusable_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(IngestError, match="invalid JSON"):
        load_alerts([bad])

    wrong_shape = tmp_path / "shape.json"
    wrong_shape.write_text(json.dumps({"events": []}))
    with pytest.raises(IngestError, match="expected a JSON array"):
        load_alerts([wrong_shape])

    with pytest.raises(IngestError, match="file not found"):
        load_alerts([tmp_path / "missing.json"])
