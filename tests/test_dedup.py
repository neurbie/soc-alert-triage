from datetime import timedelta

import pytest

from alerttriage.dedup import deduplicate

from .conftest import make_alert

WINDOW = timedelta(minutes=15)


def test_same_indicator_within_window_merges():
    incidents = deduplicate([make_alert(0), make_alert(5), make_alert(10)], WINDOW)
    assert len(incidents) == 1
    assert incidents[0].count == 3


def test_gap_larger_than_window_splits_into_new_incident():
    incidents = deduplicate([make_alert(0), make_alert(5), make_alert(60), make_alert(62)], WINDOW)
    assert [i.count for i in incidents] == [2, 2]


def test_window_is_rolling_not_fixed():
    # Each gap is 10m, total span 60m: a fixed 15m bucket would split this,
    # rolling sessions keep it as one sustained incident.
    incidents = deduplicate([make_alert(m) for m in range(0, 61, 10)], WINDOW)
    assert len(incidents) == 1
    assert incidents[0].duration == timedelta(minutes=60)


def test_window_boundary_is_inclusive():
    assert len(deduplicate([make_alert(0), make_alert(15)], WINDOW)) == 1
    assert len(deduplicate([make_alert(0), make_alert(15.01)], WINDOW)) == 2


def test_different_ip_or_type_never_merge():
    alerts = [
        make_alert(0, source_ip="203.0.113.5", alert_type="brute_force_ssh"),
        make_alert(1, source_ip="203.0.113.6", alert_type="brute_force_ssh"),
        make_alert(2, source_ip="203.0.113.5", alert_type="port_scan"),
    ]
    assert len(deduplicate(alerts, WINDOW)) == 3


def test_input_order_does_not_matter():
    alerts = [make_alert(10), make_alert(0), make_alert(5)]
    (incident,) = deduplicate(alerts, WINDOW)
    assert [a.timestamp for a in incident.alerts] == sorted(a.timestamp for a in alerts)


def test_exact_duplicate_alert_ids_are_dropped():
    a = make_alert(0, alert_id="DUP-1")
    (incident,) = deduplicate([a, a, make_alert(1)], WINDOW)
    assert incident.count == 2


def test_zero_window_only_merges_simultaneous_alerts():
    incidents = deduplicate([make_alert(0), make_alert(0), make_alert(1)], timedelta(0))
    assert [i.count for i in incidents] == [2, 1]


def test_negative_window_rejected():
    with pytest.raises(ValueError):
        deduplicate([make_alert(0)], timedelta(minutes=-1))


def test_empty_input():
    assert deduplicate([], WINDOW) == []
