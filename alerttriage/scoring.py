"""Stage 3 - Score and rank incidents into a prioritized ticket queue.

The score is a 0-100 number built from five additive components. Each one
answers a question an experienced analyst would ask when eyeballing a queue:

=====================  ==========  =============================================
Component              Range       Question it answers
=====================  ==========  =============================================
Severity               10 - 70     How bad did the sensor say this was?
Frequency              0 - 15      Is this a one-off or sustained activity?
Blast radius           0 - 10      How many distinct hosts/users/IPs were hit?
Threat category        -10 - +10   Is this alert type inherently urgent or noisy?
Correlation            0 - 15      Is this source doing *other* bad things too?
=====================  ==========  =============================================

Severity dominates on purpose: a single critical alert should outrank a
thousand informational ones. The other components move incidents *within* and
*slightly across* severity bands, which is where human triage judgment
normally comes in.

Every component is recorded as a ``ScoreComponent`` so the report can show
exactly why a ticket landed where it did. A triage tool whose ranking can't be
explained won't be trusted by analysts, and shouldn't be.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from .models import Incident, Priority, ScoreComponent, Severity, Ticket

# Base points by the highest severity seen in the incident.
SEVERITY_POINTS: dict[Severity, float] = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 40,
    Severity.HIGH: 55,
    Severity.CRITICAL: 70,
}

# Alert types that warrant an adjustment regardless of reported severity.
# Positive: late kill-chain stages, where minutes matter.
# Negative: high-volume, low-fidelity detections that are mostly noise.
CATEGORY_MODIFIERS: dict[str, float] = {
    "ransomware_activity": 10,
    "data_exfiltration": 10,
    "credential_dumping": 10,
    "web_shell_upload": 10,
    "c2_beacon": 8,
    "successful_login_after_failures": 8,
    "privilege_escalation": 8,
    "lateral_movement": 8,
    "malware_detected": 5,
    "dns_tunneling": 5,
    "impossible_travel": 5,
    "port_scan": -5,
    "policy_violation": -5,
    "tor_exit_node_connection": -3,
    "geo_anomaly": -3,
}

# Score thresholds for each priority band (score >= threshold).
PRIORITY_THRESHOLDS: list[tuple[float, Priority]] = [
    (80, Priority.P1),
    (60, Priority.P2),
    (40, Priority.P3),
    (0, Priority.P4),
]

FREQUENCY_MAX = 15.0
BLAST_RADIUS_MAX = 10.0
CORRELATION_MAX = 15.0


@dataclass
class ScoringConfig:
    """Tunable knobs, grouped so a SOC can adjust them without editing logic."""

    severity_points: dict[Severity, float] = field(default_factory=lambda: dict(SEVERITY_POINTS))
    category_modifiers: dict[str, float] = field(default_factory=lambda: dict(CATEGORY_MODIFIERS))
    priority_thresholds: list[tuple[float, Priority]] = field(
        default_factory=lambda: list(PRIORITY_THRESHOLDS)
    )
    ticket_prefix: str = "TRI"


# --------------------------------------------------------------------------- #
# Individual score components
# --------------------------------------------------------------------------- #


def severity_component(incident: Incident, config: ScoringConfig) -> ScoreComponent:
    sev = incident.max_severity
    return ScoreComponent("Severity", config.severity_points[sev], f"highest alert severity is {sev.label}")


def frequency_component(incident: Incident) -> ScoreComponent:
    """Logarithmic: 1 alert = 0, 2 = 5, 4 = 10, 8+ = 15.

    Log scaling reflects diminishing returns: going from 1 to 10 occurrences
    tells you a lot (it's sustained), going from 1,000 to 1,010 tells you
    nothing new. Linear scaling would let a chatty low-severity rule bury
    everything else.
    """
    points = min(FREQUENCY_MAX, 5 * math.log2(incident.count))
    span = _format_span(incident)
    return ScoreComponent("Frequency", round(points, 1), f"{incident.count} alert(s) {span}")


def blast_radius_component(incident: Incident) -> ScoreComponent:
    """+2.5 per distinct target beyond the first, capped at 10 (5+ targets).

    One source touching many users/hosts suggests spraying, scanning or
    worm-like spread rather than a single misbehaving connection. See
    ``Incident.blast_radius`` for how targets are counted.
    """
    n = incident.blast_radius
    points = min(BLAST_RADIUS_MAX, 2.5 * max(0, n - 1))
    if n:
        reason = f"{len(incident.assets)} asset(s), {len(incident.users)} user(s)"
    else:
        reason = "no host/IP/user fields present"
    return ScoreComponent("Blast radius", points, reason)


def category_component(incident: Incident, config: ScoringConfig) -> ScoreComponent:
    points = config.category_modifiers.get(incident.alert_type, 0.0)
    if points > 0:
        reason = f"'{incident.alert_type}' is a high-impact category"
    elif points < 0:
        reason = f"'{incident.alert_type}' is a high-volume, low-fidelity category"
    else:
        reason = "no category adjustment"
    return ScoreComponent("Threat category", points, reason)


def correlation_component(incident: Incident, types_by_ip: dict[str, set[str]]) -> ScoreComponent:
    """+7.5 per *other* alert type raised by the same source IP, capped at 15.

    A single IP that port-scans, then brute-forces SSH, then logs in
    successfully is walking the kill chain. Each of those alerts alone might
    be routine; together they are an intrusion. This component lets the
    pieces raise each other's priority.
    """
    others = sorted(types_by_ip[incident.source_ip] - {incident.alert_type})
    points = min(CORRELATION_MAX, 7.5 * len(others))
    reason = f"same source also raised: {', '.join(others)}" if others else "no other activity from this source"
    return ScoreComponent("Correlation", points, reason)


def _format_span(incident: Incident) -> str:
    seconds = int(incident.duration.total_seconds())
    if incident.count == 1:
        return "(single event)"
    if seconds < 60:
        return f"over {seconds}s"
    if seconds < 3600:
        return f"over {seconds // 60}m"
    return f"over {seconds // 3600}h {(seconds % 3600) // 60}m"


# --------------------------------------------------------------------------- #
# Priority + ranking
# --------------------------------------------------------------------------- #


def assign_priority(score: float, incident: Incident, config: ScoringConfig) -> Priority:
    """Map score to a priority band, with one safety floor.

    Floor rule: an incident containing a CRITICAL alert is never below P2.
    The additive model can in theory pull a critical alert down (e.g. a
    critical "policy_violation" with a negative category modifier); a human
    should still look at anything a sensor called critical within the hour.
    """
    priority = next(p for threshold, p in config.priority_thresholds if score >= threshold)
    if incident.max_severity == Severity.CRITICAL:
        priority = min(priority, Priority.P2)
    return priority


def score_incident(
    incident: Incident, types_by_ip: dict[str, set[str]], config: ScoringConfig
) -> tuple[float, list[ScoreComponent]]:
    breakdown = [
        severity_component(incident, config),
        frequency_component(incident),
        blast_radius_component(incident),
        category_component(incident, config),
        correlation_component(incident, types_by_ip),
    ]
    total = sum(c.points for c in breakdown)
    return round(max(0.0, min(100.0, total)), 1), breakdown


def _rank_key(ticket: Ticket) -> tuple:
    """Sort order for the queue. Each later key only breaks ties in the earlier ones.

    1. Priority band (P1 before P2). The band comes from the score, plus the
       critical floor rule.
    2. Max severity, *within* a band. A single critical "successful login after
       failures" should sit above the 26 high-severity brute-force alerts that
       led to it, even though volume gives the brute force a slightly higher
       score: the login is the compromise, and the brute force is context.
    3. Score.
    4. Most recent activity. Something still happening beats something that
       stopped hours ago.
    5. Alert count.
    6. Source IP / type, only so the output is deterministic.
    """
    inc = ticket.incident
    return (
        ticket.priority,
        -inc.max_severity,
        -ticket.score,
        -inc.last_seen.timestamp(),
        -inc.count,
        inc.source_ip,
        inc.alert_type,
    )


def build_queue(incidents: list[Incident], config: ScoringConfig | None = None) -> list[Ticket]:
    """Score every incident and return tickets in work order (rank 1 first)."""
    config = config or ScoringConfig()

    # Correlation needs a global view: which alert types has each IP raised?
    types_by_ip: dict[str, set[str]] = defaultdict(set)
    for inc in incidents:
        types_by_ip[inc.source_ip].add(inc.alert_type)

    tickets: list[Ticket] = []
    for inc in incidents:
        score, breakdown = score_incident(inc, types_by_ip, config)
        priority = assign_priority(score, inc, config)
        tickets.append(Ticket("", inc, score, priority, breakdown))

    tickets.sort(key=_rank_key)

    # Ticket IDs follow queue order so "TRI-0001" is always the top of the queue.
    for rank, ticket in enumerate(tickets, start=1):
        ticket.rank = rank
        ticket.ticket_id = f"{config.ticket_prefix}-{rank:04d}"

    # Cross-link tickets that share a source IP, so analysts work them together.
    by_ip: dict[str, list[str]] = defaultdict(list)
    for ticket in tickets:
        by_ip[ticket.incident.source_ip].append(ticket.ticket_id)
    for ticket in tickets:
        ticket.related = [t for t in by_ip[ticket.incident.source_ip] if t != ticket.ticket_id]

    return tickets
