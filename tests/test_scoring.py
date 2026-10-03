from collections import defaultdict

import pytest

from alerttriage.models import Incident, Priority, Severity
from alerttriage.scoring import (
    ScoringConfig,
    assign_priority,
    blast_radius_component,
    build_queue,
    correlation_component,
    frequency_component,
)

from .conftest import make_alert


def incident(*alerts) -> Incident:
    first = alerts[0]
    return Incident(first.source_ip, first.alert_type, sorted(alerts, key=lambda a: a.timestamp))


@pytest.mark.parametrize("count, points", [(1, 0), (2, 5), (4, 10), (8, 15), (500, 15)])
def test_frequency_is_logarithmic_and_capped(count, points):
    inc = incident(*[make_alert(i) for i in range(count)])
    assert frequency_component(inc).points == points


def test_blast_radius_counts_one_asset_per_alert_not_host_plus_ip():
    same_box = incident(
        make_alert(0, hostname="bastion-01", dest_ip="10.0.1.10", user="root"),
        make_alert(1, hostname="bastion-01", dest_ip="10.0.1.10", user="root"),
    )
    assert same_box.blast_radius == 1
    assert blast_radius_component(same_box).points == 0


def test_blast_radius_uses_users_or_assets_whichever_is_wider():
    spray = incident(*[make_alert(i, hostname="mail-01", user=f"u{i}") for i in range(9)])
    assert spray.blast_radius == 9
    assert blast_radius_component(spray).points == 10  # capped


def test_correlation_rewards_other_activity_from_same_source():
    types_by_ip = defaultdict(set, {"203.0.113.5": {"port_scan", "brute_force_ssh", "successful_login_after_failures"}})
    inc = incident(make_alert(0, alert_type="brute_force_ssh"))
    comp = correlation_component(inc, types_by_ip)
    assert comp.points == 15
    assert "port_scan" in comp.reason


def test_priority_thresholds():
    low = incident(make_alert(0, severity=Severity.LOW))
    config = ScoringConfig()
    assert assign_priority(85, low, config) is Priority.P1
    assert assign_priority(60, low, config) is Priority.P2
    assert assign_priority(59.9, low, config) is Priority.P3
    assert assign_priority(10, low, config) is Priority.P4


def test_critical_floor_keeps_critical_at_p2_or_better():
    crit = incident(make_alert(0, severity=Severity.CRITICAL))
    assert assign_priority(5, crit, ScoringConfig()) is Priority.P2


def test_single_critical_outranks_noisy_low_severity():
    noisy = [make_alert(i, source_ip="10.0.3.50", severity=Severity.LOW, user=f"u{i}") for i in range(50)]
    critical = make_alert(0, source_ip="198.51.100.1", alert_type="data_exfiltration", severity=Severity.CRITICAL)
    tickets = build_queue([incident(*noisy), incident(critical)])
    assert tickets[0].incident.alert_type == "data_exfiltration"


def test_within_band_critical_ranks_above_high_even_with_lower_score():
    # Mirrors sample batch 1: brute force (high, many) vs the successful login (critical, one).
    brute = incident(*[make_alert(i, user=f"u{i}") for i in range(26)])
    login = incident(make_alert(27, alert_type="successful_login_after_failures", severity=Severity.CRITICAL))
    tickets = build_queue([brute, login])
    assert [t.priority for t in tickets] == [Priority.P1, Priority.P1]
    assert tickets[0].incident is login
    assert tickets[0].score < tickets[1].score


def test_ticket_ids_follow_rank_and_related_tickets_link_same_source():
    a = incident(make_alert(0, alert_type="port_scan", severity=Severity.MEDIUM))
    b = incident(make_alert(5, alert_type="brute_force_ssh"))
    c = incident(make_alert(0, source_ip="198.51.100.9", alert_type="port_scan", severity=Severity.LOW))
    tickets = build_queue([a, b, c], ScoringConfig(ticket_prefix="SOC"))

    assert [t.ticket_id for t in tickets] == ["SOC-0001", "SOC-0002", "SOC-0003"]
    assert [t.rank for t in tickets] == [1, 2, 3]
    by_type_ip = {(t.incident.source_ip, t.incident.alert_type): t for t in tickets}
    assert by_type_ip[("203.0.113.5", "port_scan")].related == [by_type_ip[("203.0.113.5", "brute_force_ssh")].ticket_id]
    assert by_type_ip[("198.51.100.9", "port_scan")].related == []


def test_score_breakdown_sums_to_score_and_is_clamped():
    big = incident(
        *[make_alert(i, alert_type="data_exfiltration", severity=Severity.CRITICAL, user=f"u{i}") for i in range(20)]
    )
    (ticket,) = build_queue([big])
    assert ticket.score == 100  # 70 + 15 + 10 + 10 = 105, clamped
    assert sum(c.points for c in ticket.breakdown) == 105


def test_internal_detection_ignores_documentation_ranges():
    assert incident(make_alert(0, source_ip="10.1.2.3")).source_is_internal
    assert incident(make_alert(0, source_ip="fd00::1")).source_is_internal
    # Python's is_private is True for TEST-NET-3; we must not call it internal.
    assert not incident(make_alert(0, source_ip="203.0.113.45")).source_is_internal
