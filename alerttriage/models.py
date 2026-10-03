"""Core data models for AlertTriage.

Three objects flow through the pipeline:

    raw JSON dict  --ingest-->  Alert  --dedup-->  Incident  --score-->  Ticket

* ``Alert``    - one normalized, validated security alert as emitted by a sensor.
* ``Incident`` - a cluster of alerts sharing the same indicator
                 (source IP + alert type) inside a rolling time window.
* ``Ticket``   - a scored, prioritized Incident ready for an analyst queue.

Everything here is a plain dataclass so the pipeline stages stay easy to test
in isolation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum

# Address space treated as "inside the organization". Defined explicitly rather
# than using ``ipaddress.is_private``, which also returns True for documentation
# and benchmarking ranges (e.g. 203.0.113.0/24) that are *not* internal.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",      # RFC 1918
        "172.16.0.0/12",   # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",   # RFC 6598 carrier-grade NAT (often used internally)
        "127.0.0.0/8",     # loopback
        "169.254.0.0/16",  # link-local
        "fc00::/7",        # IPv6 unique local
        "fe80::/10",       # IPv6 link-local
        "::1/128",         # IPv6 loopback
    )
]


class Severity(IntEnum):
    """Normalized alert severity.

    Sensors disagree wildly on severity vocabularies (``"crit"``, ``"High"``,
    ``3``, ``"sev2"``...). Everything is mapped onto this five-level scale at
    ingest time. Being an ``IntEnum`` means severities compare and sort
    naturally (``Severity.HIGH > Severity.LOW``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Priority(IntEnum):
    """Ticket priority. Lower number = work it first (P1 is the most urgent)."""

    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4

    @property
    def label(self) -> str:
        return {
            Priority.P1: "Critical",
            Priority.P2: "High",
            Priority.P3: "Medium",
            Priority.P4: "Low",
        }[self]

    @property
    def sla(self) -> timedelta:
        """Target time-to-acknowledge for this priority."""
        return {
            Priority.P1: timedelta(minutes=15),
            Priority.P2: timedelta(hours=1),
            Priority.P3: timedelta(hours=4),
            Priority.P4: timedelta(hours=24),
        }[self]


@dataclass(frozen=True)
class Alert:
    """A single validated security alert.

    Required fields mirror the minimum a SOC needs to act on an alert. The
    optional fields are used for context (blast radius, related assets) when
    present, but never required.
    """

    alert_id: str
    timestamp: datetime
    source_ip: str
    alert_type: str  # normalized: lowercase snake_case
    severity: Severity
    description: str
    dest_ip: str | None = None
    hostname: str | None = None
    user: str | None = None
    sensor: str | None = None

    @property
    def dedup_key(self) -> tuple[str, str]:
        """The indicator that identifies "the same underlying activity"."""
        return (self.source_ip, self.alert_type)


@dataclass
class Incident:
    """A group of alerts the dedup stage decided are one piece of activity.

    ``alerts`` is always kept sorted by timestamp, so ``first_seen`` and
    ``last_seen`` are cheap to read.
    """

    source_ip: str
    alert_type: str
    alerts: list[Alert] = field(default_factory=list)

    # -- basic shape ---------------------------------------------------------

    @property
    def count(self) -> int:
        return len(self.alerts)

    @property
    def first_seen(self) -> datetime:
        return self.alerts[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.alerts[-1].timestamp

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen

    @property
    def max_severity(self) -> Severity:
        return max(a.severity for a in self.alerts)

    # -- context used by scoring and the report ------------------------------

    @property
    def assets(self) -> list[str]:
        """Distinct machines this activity touched.

        Each alert contributes one asset: its hostname if present, otherwise
        its destination IP. Preferring one identifier per alert avoids counting
        ``bastion-01`` and ``10.0.1.10`` as two targets when they are the same box.
        """
        seen: dict[str, None] = {}  # dict as an ordered set
        for a in self.alerts:
            asset = a.hostname or a.dest_ip
            if asset:
                seen[asset] = None
        return list(seen)

    @property
    def blast_radius(self) -> int:
        """How widely this activity spread: max(distinct assets, distinct users).

        One source hitting 12 users (phishing, password spraying) or 12 hosts
        (scanning, worm-like spread) is worse than one source hitting the same
        target 12 times. Taking the max rather than the sum keeps a single user
        on a single host at 1.
        """
        return max(len(self.assets), len(self.users))

    @property
    def users(self) -> list[str]:
        return sorted({a.user for a in self.alerts if a.user})

    @property
    def hosts(self) -> list[str]:
        return sorted({a.hostname for a in self.alerts if a.hostname})

    @property
    def dest_ips(self) -> list[str]:
        return sorted({a.dest_ip for a in self.alerts if a.dest_ip})

    @property
    def sensors(self) -> list[str]:
        return sorted({a.sensor for a in self.alerts if a.sensor})

    @property
    def source_is_internal(self) -> bool:
        """True for RFC 1918 / loopback / link-local sources.

        An *internal* source raising malware or C2 alerts usually means a
        compromised endpoint, which changes the response playbook.
        """
        try:
            addr = ipaddress.ip_address(self.source_ip)
        except ValueError:
            return False
        return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


@dataclass(frozen=True)
class ScoreComponent:
    """One line of a score breakdown, kept so every score is explainable."""

    name: str
    points: float
    reason: str


@dataclass
class Ticket:
    """A scored incident, positioned in the triage queue."""

    ticket_id: str
    incident: Incident
    score: float
    priority: Priority
    breakdown: list[ScoreComponent]
    rank: int = 0
    related: list[str] = field(default_factory=list)  # other ticket IDs, same source IP
