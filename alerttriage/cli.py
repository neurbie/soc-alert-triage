"""Command-line entry point: ``python -m alerttriage <batch.json> [...]``.

Wires the four pipeline stages together:

    load_alerts -> deduplicate -> build_queue -> render_report
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .dedup import deduplicate
from .ingest import IngestError, load_alerts, parse_timestamp
from .models import Priority
from .report import ReportContext, render_report
from .scoring import ScoringConfig, build_queue


def _positive_minutes(value: str) -> int:
    minutes = int(value)
    if minutes < 0:
        raise argparse.ArgumentTypeError("window must be >= 0 minutes")
    return minutes


def _priority(value: str) -> Priority:
    try:
        return Priority[value.upper()]
    except KeyError:
        raise argparse.ArgumentTypeError("priority must be one of P1, P2, P3, P4") from None


def _timestamp(value: str) -> datetime:
    try:
        return parse_timestamp(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alerttriage",
        description="Deduplicate, score and rank security alerts into a Markdown triage queue.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="one or more JSON alert batch files")
    parser.add_argument(
        "-o", "--output", type=Path, help="write the Markdown report here (default: stdout)"
    )
    parser.add_argument(
        "-w", "--window", type=_positive_minutes, default=15, metavar="MIN",
        help="dedup window in minutes: max gap between alerts in one incident (default: 15)",
    )
    parser.add_argument(
        "--min-priority", type=_priority, metavar="PN",
        help="only show tickets at this priority or higher, e.g. P2 shows P1+P2",
    )
    parser.add_argument(
        "--details", type=int, metavar="N",
        help="render full ticket cards for only the top N tickets (default: all)",
    )
    parser.add_argument(
        "--prefix", default="TRI", help="ticket ID prefix (default: TRI -> TRI-0001)"
    )
    parser.add_argument(
        "--generated-at", type=_timestamp, metavar="ISO8601",
        help="override the report timestamp (useful for reproducible output)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    window = timedelta(minutes=args.window)

    try:
        alerts, rejected = load_alerts(args.inputs)
    except IngestError as exc:
        print(f"alerttriage: error: {exc}", file=sys.stderr)
        return 2

    incidents = deduplicate(alerts, window)
    tickets = build_queue(incidents, ScoringConfig(ticket_prefix=args.prefix))

    ctx = ReportContext(
        input_files=[p.name for p in args.inputs],
        window=window,
        total_alerts=len(alerts) + len(rejected),
        rejected=rejected,
        all_alerts=alerts,
        generated_at=args.generated_at or datetime.now(timezone.utc),
    )
    markdown = render_report(tickets, ctx, detail_limit=args.details, min_priority=args.min_priority)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
    else:
        sys.stdout.write(markdown)

    # One-line console summary on stderr, so it doesn't pollute piped Markdown.
    counts = {p: sum(1 for t in tickets if t.priority == p) for p in Priority}
    summary = " ".join(f"{p.name}={n}" for p, n in counts.items())
    where = f" -> {args.output}" if args.output else ""
    print(
        f"alerttriage: {len(alerts)} alerts ({len(rejected)} rejected) -> "
        f"{len(tickets)} tickets [{summary}]{where}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
