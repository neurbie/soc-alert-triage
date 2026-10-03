"""Stage 4 - Render the ticket queue as a Markdown triage report.

The layout follows how an analyst actually works a queue at shift start:

1. **Header / shift summary** - how much came in, how much was noise, how
   much is urgent. Answers "how bad is today?" in five seconds.
2. **Queue table** - one row per ticket in work order. This is the worklist.
3. **Ticket cards** - per-ticket detail: why it scored what it did, the
   evidence, first-response steps, and a checklist to record the disposition.
4. **Appendix** - alerts rejected at ingest, so nothing disappears silently.

Output is plain GitHub-flavored Markdown, so it renders in GitHub, GitLab,
Confluence, Obsidian, or a ticketing system's Markdown field.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .ingest import RejectedAlert
from .models import Alert, Priority, Ticket
from .playbooks import playbook_for

PRIORITY_BADGE = {
    Priority.P1: "🔴 P1",
    Priority.P2: "🟠 P2",
    Priority.P3: "🟡 P3",
    Priority.P4: "🔵 P4",
}

# Tokens that should stay uppercase when turning alert_type slugs into titles.
_ACRONYMS = {"ssh", "rdp", "dns", "c2", "sql", "ip", "tor", "smb", "vpn", "edr", "mfa"}

MAX_EVIDENCE_ROWS = 5


@dataclass
class ReportContext:
    """Run metadata shown in the report header."""

    input_files: list[str]
    window: timedelta
    total_alerts: int
    rejected: list[RejectedAlert]
    all_alerts: list[Alert]
    generated_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #


def humanize_type(alert_type: str) -> str:
    """``brute_force_ssh`` -> ``Brute Force SSH``."""
    return " ".join(w.upper() if w in _ACRONYMS else w.capitalize() for w in alert_type.split("_"))


def fmt_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_short_time(ts: datetime) -> str:
    return ts.strftime("%m-%d %H:%M")


def fmt_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def fmt_sla(priority: Priority) -> str:
    minutes = int(priority.sla.total_seconds() // 60)
    return f"{minutes} min" if minutes < 60 else f"{minutes // 60} h"


def md_escape(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def table(headers: list[str], rows: Iterable[list[str]], align: list[str] | None = None) -> str:
    """Build a GFM table. ``align`` entries are 'l', 'r' or 'c'."""
    align = align or ["l"] * len(headers)
    sep = {"l": ":---", "r": "---:", "c": ":---:"}
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep[a] for a in align) + " |",
    ]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _pct(part: int, whole: int) -> str:
    return f"{(100 * part / whole):.0f}%" if whole else "0%"


# --------------------------------------------------------------------------- #
# Report sections
# --------------------------------------------------------------------------- #


def render_header(ctx: ReportContext) -> str:
    generated = ctx.generated_at or datetime.now(timezone.utc)
    lines = ["# SOC Triage Queue", ""]
    lines.append(f"**Generated:** {fmt_time(generated)}  ")
    lines.append(f"**Input:** {', '.join(f'`{f}`' for f in ctx.input_files)}  ")
    if ctx.all_alerts:
        first = min(a.timestamp for a in ctx.all_alerts)
        last = max(a.timestamp for a in ctx.all_alerts)
        lines.append(f"**Alert window:** {fmt_time(first)} → {fmt_time(last)}  ")
    lines.append(f"**Dedup window:** {fmt_duration(ctx.window)} rolling, keyed on source IP + alert type")
    return "\n".join(lines)


def render_summary(tickets: list[Ticket], ctx: ReportContext) -> str:
    accepted = len(ctx.all_alerts)
    reduction = _pct(accepted - len(tickets), accepted)
    exact_dupes = accepted - sum(t.incident.count for t in tickets)

    out = ["## Shift Summary", ""]
    out.append(
        table(
            ["Alerts received", "Rejected (malformed)", "Exact duplicates", "Tickets after dedup", "Noise reduction"],
            [[str(ctx.total_alerts), str(len(ctx.rejected)), str(exact_dupes), str(len(tickets)), reduction]],
            ["r"] * 5,
        )
    )
    out.append("")

    tickets_by_pri = Counter(t.priority for t in tickets)
    alerts_by_pri = Counter()
    for t in tickets:
        alerts_by_pri[t.priority] += t.incident.count
    out.append(
        table(
            ["Priority", "Tickets", "Underlying alerts", "Ack SLA"],
            [
                [f"{PRIORITY_BADGE[p]} {p.label}", str(tickets_by_pri[p]), str(alerts_by_pri[p]), fmt_sla(p)]
                for p in Priority
            ],
            ["l", "r", "r", "r"],
        )
    )

    p1 = tickets_by_pri[Priority.P1]
    if p1:
        out += ["", f"> **⚠ {p1} P1 ticket(s) need acknowledgement within {fmt_sla(Priority.P1)}.** Start at the top of the queue."]
    elif tickets:
        out += ["", "> No P1 tickets this batch. Work the queue top-down."]
    return "\n".join(out)


def render_queue(tickets: list[Ticket]) -> str:
    out = ["## Queue", "", "Work top-down. Ticket numbers follow queue order.", ""]
    if not tickets:
        out.append("_Queue is empty._")
        return "\n".join(out)

    rows = []
    for t in tickets:
        inc = t.incident
        source = f"`{inc.source_ip}`" + (" (int)" if inc.source_is_internal else "")
        rows.append(
            [
                str(t.rank),
                f"[{t.ticket_id}](#{t.ticket_id.lower()})",
                PRIORITY_BADGE[t.priority],
                f"{t.score:.1f}",
                humanize_type(inc.alert_type),
                source,
                inc.max_severity.label,
                str(inc.count),
                str(inc.blast_radius),
                fmt_short_time(inc.last_seen),
            ]
        )
    out.append(
        table(
            ["#", "Ticket", "Pri", "Score", "Alert type", "Source", "Max sev", "Alerts", "Targets", "Last seen"],
            rows,
            ["r", "l", "l", "r", "l", "l", "l", "r", "r", "l"],
        )
    )
    return "\n".join(out)


def _list_or_dash(values: list[str], limit: int = 8) -> str:
    if not values:
        return "—"
    shown = ", ".join(f"`{md_escape(v)}`" for v in values[:limit])
    extra = len(values) - limit
    return shown + (f" +{extra} more" if extra > 0 else "")


def render_ticket(t: Ticket) -> str:
    inc = t.incident
    title = f"{humanize_type(inc.alert_type)} from {inc.source_ip}"
    # Explicit anchor so queue-table links work regardless of renderer slug rules.
    out = [f'<a id="{t.ticket_id.lower()}"></a>', f"### {PRIORITY_BADGE[t.priority]} · {t.ticket_id} · {title}", ""]

    if inc.count == 1:
        occurrence = f"1 alert at {fmt_time(inc.first_seen)}"
    else:
        occurrence = (
            f"{inc.count} alerts over {fmt_duration(inc.duration)} "
            f"({fmt_time(inc.first_seen)} → {fmt_time(inc.last_seen)})"
        )

    fields = [
        ["Priority", f"**{t.priority.name} – {t.priority.label}** (acknowledge within {fmt_sla(t.priority)})"],
        ["Score", f"**{t.score:.1f}** / 100"],
        ["Max severity", inc.max_severity.label],
        ["Source IP", f"`{inc.source_ip}` ({'internal' if inc.source_is_internal else 'external'})"],
        ["Occurrences", occurrence],
        ["Hosts", _list_or_dash(inc.hosts)],
        ["Users", _list_or_dash(inc.users)],
        ["Destination IPs", _list_or_dash(inc.dest_ips)],
        ["Sensors", _list_or_dash(inc.sensors)],
        ["Related tickets", ", ".join(f"[{r}](#{r.lower()})" for r in t.related) or "—"],
    ]
    out.append(table(["Field", "Value"], fields))
    out.append("")

    out.append("**Why this score**")
    out.append("")
    out.append(
        table(
            ["Component", "Points", "Reason"],
            [[c.name, f"{c.points:+.1f}", md_escape(c.reason)] for c in t.breakdown],
            ["l", "r", "l"],
        )
    )
    out.append("")

    out.append("**Evidence**")
    out.append("")
    evidence = _select_evidence(inc.alerts)
    out.append(
        table(
            ["Time (UTC)", "Alert ID", "Sev", "Description"],
            [
                [
                    a.timestamp.strftime("%H:%M:%S"),
                    f"`{md_escape(a.alert_id)}`",
                    a.severity.label,
                    md_escape(truncate(a.description, 110)),
                ]
                for a in evidence
            ],
        )
    )
    if inc.count > len(evidence):
        out.append("")
        out.append(f"_…and {inc.count - len(evidence)} more alert(s) in this incident._")
    out.append("")

    out.append("**Recommended first response**")
    out.append("")
    out += [f"{i}. {step}" for i, step in enumerate(playbook_for(inc.alert_type), start=1)]
    out.append("")

    out += [
        "**Analyst checklist**",
        "",
        "- [ ] Acknowledged — analyst: ________  time: ________",
        "- [ ] Investigated / scoped",
        "- [ ] Contained or escalated",
        "- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive",
        "",
        "**Notes:**",
        "",
        "---",
    ]
    return "\n".join(out)


def _select_evidence(alerts: list[Alert]) -> list[Alert]:
    """Pick the rows most useful to an analyst, shown in time order.

    Always include the first and last alert (bracket the activity), then fill
    remaining slots with the highest-severity alerts. For a brute force that
    ends in a critical event, that critical event is guaranteed to be shown.
    """
    if len(alerts) <= MAX_EVIDENCE_ROWS:
        return alerts
    chosen = {id(alerts[0]): alerts[0], id(alerts[-1]): alerts[-1]}
    for a in sorted(alerts, key=lambda a: a.severity, reverse=True):
        if len(chosen) >= MAX_EVIDENCE_ROWS:
            break
        chosen.setdefault(id(a), a)
    return sorted(chosen.values(), key=lambda a: a.timestamp)


def _raw_preview(raw: object) -> str:
    """Show rejected records as compact JSON (as they appeared in the file)."""
    if isinstance(raw, str):
        return raw
    return json.dumps(raw, separators=(",", ":"), default=str)


def render_rejected(rejected: list[RejectedAlert]) -> str:
    out = ["## Appendix: Rejected Alerts", ""]
    out.append(
        "These records failed validation and were **not** triaged. "
        "Fix the upstream sensor/export or review them manually."
    )
    out.append("")
    out.append(
        table(
            ["File", "Index", "Reason", "Raw (truncated)"],
            [
                [
                    f"`{r.source_file}`",
                    str(r.index),
                    md_escape(r.reason),
                    f"`{md_escape(truncate(_raw_preview(r.raw), 80))}`",
                ]
                for r in rejected
            ],
            ["l", "r", "l", "l"],
        )
    )
    return "\n".join(out)


def render_report(
    tickets: list[Ticket],
    ctx: ReportContext,
    detail_limit: int | None = None,
    min_priority: Priority | None = None,
) -> str:
    """Assemble the full report.

    ``tickets`` is the complete ranked queue; the shift summary always reflects
    all of it. ``min_priority`` (e.g. ``Priority.P2``) hides lower-priority
    tickets from the queue table and cards. ``detail_limit`` caps how many
    ticket cards are rendered; the queue table still lists every shown ticket
    so the analyst sees the full workload.
    """
    shown = [t for t in tickets if min_priority is None or t.priority <= min_priority]
    sections = [render_header(ctx), render_summary(tickets, ctx), render_queue(shown)]

    hidden = len(tickets) - len(shown)
    if hidden:
        sections.append(f"_{hidden} ticket(s) below {min_priority.name} hidden by `--min-priority`._")

    if shown:
        detailed = shown if detail_limit is None else shown[:detail_limit]
        sections.append("## Tickets")
        sections += [render_ticket(t) for t in detailed]
        if len(detailed) < len(shown):
            sections.append(
                f"_{len(shown) - len(detailed)} lower-ranked ticket(s) listed in the queue "
                f"table only (re-run with a higher `--details` to expand)._"
            )

    if ctx.rejected:
        sections.append(render_rejected(ctx.rejected))

    sections.append("<sub>Generated by AlertTriage. Scores are decision support, not a verdict — verify before acting.</sub>")
    return "\n\n".join(sections) + "\n"
