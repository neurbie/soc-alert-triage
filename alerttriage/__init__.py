"""AlertTriage - turn a noisy batch of security alerts into a prioritized SOC ticket queue.

Pipeline:

    ingest.load_alerts  ->  dedup.deduplicate  ->  scoring.build_queue  ->  report.render_report

Each stage is a pure function over the dataclasses in ``models``, so they can
be used independently (e.g. feed ``build_queue`` from a SIEM API instead of
JSON files).
"""

__version__ = "1.0.0"
