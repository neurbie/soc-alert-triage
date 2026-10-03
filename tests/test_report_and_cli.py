from datetime import datetime, timedelta, timezone

import pytest

from alerttriage.cli import main
from alerttriage.dedup import deduplicate
from alerttriage.models import Priority, Severity
from alerttriage.report import ReportContext, _select_evidence, humanize_type, md_escape, render_report
from alerttriage.scoring import build_queue

from .conftest import make_alert

FIXED_NOW = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)


def _report(alerts, **kwargs):
    tickets = build_queue(deduplicate(alerts))
    ctx = ReportContext(["test.json"], timedelta(minutes=15), len(alerts), [], alerts, FIXED_NOW)
    return render_report(tickets, ctx, **kwargs)


def test_humanize_type_keeps_acronyms():
    assert humanize_type("brute_force_ssh") == "Brute Force SSH"
    assert humanize_type("c2_beacon") == "C2 Beacon"


def test_md_escape_protects_table_cells():
    assert md_escape("a|b\nc") == "a\\|b c"


def test_report_has_all_sections_and_escapes_descriptions():
    md = _report([make_alert(0, description="payload ' OR 1=1 | cat /etc/passwd")])
    for heading in ("# SOC Triage Queue", "## Shift Summary", "## Queue", "## Tickets", "TRI-0001"):
        assert heading in md
    assert "1=1 \\| cat" in md


def test_min_priority_hides_lower_tickets_but_summary_counts_all():
    alerts = [
        make_alert(0, alert_type="data_exfiltration", severity=Severity.CRITICAL),
        make_alert(0, source_ip="10.0.9.9", alert_type="policy_violation", severity=Severity.INFO),
    ]
    md = _report(alerts, min_priority=Priority.P2)
    assert "Policy Violation from" not in md
    assert "1 ticket(s) below P2 hidden" in md
    assert "| 2 | 0 | 0 | 2 |" in md  # summary still reflects both tickets


def test_details_limit_renders_fewer_cards():
    alerts = [make_alert(0, source_ip=f"198.51.100.{i}") for i in range(4)]
    md = _report(alerts, detail_limit=1)
    assert md.count('<a id="tri-') == 1
    assert "3 lower-ranked ticket(s)" in md


def test_evidence_always_includes_the_worst_alert():
    alerts = [make_alert(i, severity=Severity.LOW) for i in range(20)]
    alerts[10] = make_alert(10, severity=Severity.CRITICAL, alert_id="THE-ONE")
    chosen = _select_evidence(alerts)
    assert len(chosen) == 5
    assert "THE-ONE" in [a.alert_id for a in chosen]
    assert chosen[0] is alerts[0] and chosen[-1] is alerts[-1]


@pytest.mark.parametrize(
    "sample, top_type",
    [
        ("batch_01_overnight_perimeter.json", "Successful Login After Failures"),
        ("batch_02_phishing_to_c2.json", "Data Exfiltration"),
        ("batch_03_mixed_day_shift.json", "Web Shell Upload"),
    ],
)
def test_cli_end_to_end_on_samples(samples_dir, tmp_path, sample, top_type):
    out = tmp_path / "report.md"
    rc = main([str(samples_dir / sample), "-o", str(out), "--generated-at", "2026-10-03T08:00:00Z"])
    assert rc == 0
    md = out.read_text()
    assert f"🔴 P1 · TRI-0001 · {top_type}" in md


def test_cli_merges_multiple_files(samples_dir, capsys):
    files = sorted(str(p) for p in samples_dir.glob("*.json"))
    assert main(files + ["--generated-at", "2026-10-03T08:00:00Z"]) == 0
    captured = capsys.readouterr()
    assert "Appendix: Rejected Alerts" in captured.out
    assert "rejected" in captured.err


def test_cli_missing_file_exits_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.json")]) == 2
    assert "file not found" in capsys.readouterr().err
