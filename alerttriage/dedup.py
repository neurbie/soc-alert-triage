"""Stage 2 - Deduplicate: collapse repeated alerts into incidents.

Two alerts describe the *same underlying activity* when they share an
indicator - the same source IP raising the same alert type - and occur close
together in time.

Windowing strategy: rolling (gap-based) sessions
------------------------------------------------
Alerts for one indicator are sorted by time. An alert joins the current
incident if it arrived within ``window`` of the incident's **most recent**
alert; otherwise it starts a new incident.

    window = 15m

    10:00  10:05  10:12  10:20        11:30  11:31
      |------|------|------|            |------|
      `------ incident A ---'           `- B --'
              (each gap <= 15m)    (70m gap -> new incident)

Why rolling rather than fixed buckets (10:00-10:15, 10:15-10:30, ...)?

* Fixed buckets split one continuous attack at arbitrary boundaries, so a
  brute-force run from 10:14 to 10:16 would become two tickets.
* A slow, persistent attack (one attempt every 10 minutes for 6 hours) is
  exactly the kind of thing an analyst wants as *one* ticket with a high
  count, not 24 separate ones.
* A real gap in activity (attacker went quiet, came back later) still
  produces a separate incident, which is usually what you want: it may be a
  new campaign and deserves a fresh look.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .models import Alert, Incident

DEFAULT_WINDOW = timedelta(minutes=15)


def deduplicate(alerts: Iterable[Alert], window: timedelta = DEFAULT_WINDOW) -> list[Incident]:
    """Group alerts into incidents by (source_ip, alert_type) and time proximity.

    Exact duplicates (same ``alert_id``, often produced when a sensor re-sends
    or two exports overlap) are dropped before clustering so they don't inflate
    the frequency score.

    Returns incidents sorted by first-seen time. Ranking happens later.
    """
    if window < timedelta(0):
        raise ValueError("window must be non-negative")

    by_indicator: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    seen_ids: set[str] = set()
    for alert in alerts:
        if alert.alert_id in seen_ids:
            continue
        seen_ids.add(alert.alert_id)
        by_indicator[alert.dedup_key].append(alert)

    incidents: list[Incident] = []
    for (source_ip, alert_type), group in by_indicator.items():
        group.sort(key=lambda a: a.timestamp)

        current = Incident(source_ip, alert_type, [group[0]])
        for alert in group[1:]:
            if alert.timestamp - current.last_seen <= window:
                current.alerts.append(alert)
            else:
                incidents.append(current)
                current = Incident(source_ip, alert_type, [alert])
        incidents.append(current)

    incidents.sort(key=lambda i: (i.first_seen, i.source_ip, i.alert_type))
    return incidents
