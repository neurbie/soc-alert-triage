# AlertTriage

**Turn a noisy batch of security alerts into a prioritized SOC ticket queue.**

AlertTriage ingests raw alerts from a JSON export (SIEM, IDS, EDR, or any
mix of them). It collapses repeated alerts into incidents, scores each incident
with a scoring model you can inspect line by line, and writes a Markdown triage
queue an analyst can work top-down at shift start.

```
88 raw alerts  ──►  5 rejected (malformed)  ──►  17 tickets  ──►  1 × P1, 4 × P2, 3 × P3, 9 × P4
                                                 (80% noise reduction)
```

- **Zero runtime dependencies.** Pure Python standard library, 3.10+.
- **Explainable.** Every ticket shows exactly which factors produced its score.
- **Forgiving on format, strict on content.** Handles mixed severity labels,
  timestamp formats and alert-type spellings, and never silently drops a bad
  record.
- **Tested.** 74 unit and end-to-end tests.

---

## Table of contents

1. [Why this exists](#why-this-exists)
2. [Quick start](#quick-start)
3. [What the report looks like](#what-the-report-looks-like)
4. [How triage works](#how-triage-works)
   - [Stage 1 · Ingest & normalize](#stage-1--ingest--normalize)
   - [Stage 2 · Deduplicate](#stage-2--deduplicate)
   - [Stage 3 · Score](#stage-3--score)
   - [Stage 4 · Prioritize & rank](#stage-4--prioritize--rank)
   - [Worked example](#worked-example)
5. [Sample batches](#sample-batches)
6. [Input format](#input-format)
7. [CLI reference](#cli-reference)
8. [Using it as a library](#using-it-as-a-library)
9. [Project layout](#project-layout)
10. [Running the tests](#running-the-tests)
11. [Design decisions & limitations](#design-decisions--limitations)
12. [Roadmap](#roadmap)

---

## Why this exists

Alert fatigue is one of the most common failure modes in a Security Operations
Center. One brute-force attempt can produce dozens of near-identical alerts, a
misconfigured cron job can produce hundreds, and the one alert that matters
(*"successful login after 143 failures"*) ends up somewhere in the middle of the
pile.

Tier-1 triage is mostly the same few steps done by hand:

1. Group the duplicates ("these 26 alerts are one brute force").
2. Ask "how bad, how much, how wide, and is this source doing anything else?"
3. Put the worst thing at the top, with enough context to start working it.

AlertTriage automates those steps and shows its reasoning, so the analyst's
time goes to investigation instead of sorting.

---

## Quick start

```bash
git clone https://github.com/neurbie/soc-alert-triage.git && cd soc-alert-triage

# Run straight from the source tree (no install needed)
python -m alerttriage samples/batch_01_overnight_perimeter.json -o report.md

# ...or install the `alerttriage` command
pip install .
alerttriage samples/*.json -o full_queue.md
```

A one-line summary is printed to stderr:

```
alerttriage: 46 alerts (0 rejected) -> 7 tickets [P1=2 P2=1 P3=1 P4=3] -> report.md
```

Pre-generated reports for every sample are in [`examples/`](examples/):

| Sample | Report |
| :--- | :--- |
| Overnight perimeter attack | [`examples/batch_01_overnight_perimeter_report.md`](examples/batch_01_overnight_perimeter_report.md) |
| Phishing → malware → C2 → exfil | [`examples/batch_02_phishing_to_c2_report.md`](examples/batch_02_phishing_to_c2_report.md) |
| Noisy day shift with bad data | [`examples/batch_03_mixed_day_shift_report.md`](examples/batch_03_mixed_day_shift_report.md) |

---

## What the report looks like

The report follows the order an analyst reads a queue in:

| Section | Purpose |
| :--- | :--- |
| **Header** | Inputs, alert time range, dedup settings. |
| **Shift Summary** | Alerts in, alerts rejected, tickets out, noise reduction, ticket count per priority with ack SLAs. Tells you how bad the shift is in five seconds. |
| **Queue** | One row per ticket in work order. This is the worklist. |
| **Ticket cards** | Per ticket: key fields, score breakdown, evidence, first-response playbook, and a checklist for recording the disposition. |
| **Appendix** | Every rejected record and the reason it was rejected. |

Excerpt from the batch 1 queue:

| # | Ticket | Pri | Score | Alert type | Source | Max sev | Alerts | Targets | Last seen |
| ---: | :--- | :--- | ---: | :--- | :--- | :--- | ---: | ---: | :--- |
| 1 | TRI-0001 | 🔴 P1 | 93.0 | Successful Login After Failures | `203.0.113.45` | Critical | 1 | 1 | 09-28 02:51 |
| 2 | TRI-0002 | 🔴 P1 | 95.0 | Brute Force SSH | `203.0.113.45` | High | 26 | 6 | 09-28 02:50 |
| 3 | TRI-0003 | 🟠 P2 | 72.9 | Port Scan | `203.0.113.45` | Medium | 6 | 6 | 09-28 02:01 |
| 4 | TRI-0004 | 🟡 P3 | 47.9 | Brute Force RDP | `198.51.100.88` | Medium | 3 | 1 | 09-28 04:05 |
| 5 | TRI-0005 | 🔵 P4 | 33.6 | TOR Exit Node Connection | `192.0.2.200` | Low | 5 | 1 | 09-28 03:11 |

And one ticket card's score breakdown:

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +70.0 | highest alert severity is Critical |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +8.0 | 'successful_login_after_failures' is a high-impact category |
| Correlation | +15.0 | same source also raised: brute_force_ssh, port_scan |

---

## How triage works

```
 JSON batch(es)
      │
      ▼
┌────────────┐   Alert    ┌────────────┐  Incident  ┌────────────┐   Ticket   ┌────────────┐
│ 1. Ingest  │──────────► │ 2. Dedup   │──────────► │ 3. Score   │──────────► │ 4. Report  │──► Markdown
│ normalize, │            │ IP + type, │            │ 5 factors, │            │ summary,   │
│ validate   │            │ rolling    │            │ priority,  │            │ queue,     │
└────────────┘            │ window     │            │ rank       │            │ cards      │
      │                   └────────────┘            └────────────┘            └────────────┘
      └── RejectedAlert ───────────────────────────────────────────────────────► Appendix
```

Each stage is a pure function over the dataclasses in
[`alerttriage/models.py`](alerttriage/models.py), so each one can be tested
and reused on its own.

### Stage 1 · Ingest & normalize

[`alerttriage/ingest.py`](alerttriage/ingest.py)

Real feeds are inconsistent. Ingest normalizes every field to one canonical
form:

| Field | Accepted input | Normalized to |
| :--- | :--- | :--- |
| `timestamp` | ISO-8601 with `Z`, with an offset, or naive; Unix epoch seconds | timezone-aware **UTC** (naive values are assumed to be UTC) |
| `severity` | `info`/`informational`, `low`, `med`/`medium`/`moderate`, `high`, `crit`/`critical` (any case); integers `1`–`5` | `Severity` enum: INFO < LOW < MEDIUM < HIGH < CRITICAL |
| `alert_type` | `"Brute Force - SSH"`, `"brute_force_ssh"`, `"SQL-Injection"` | lowercase snake_case: `brute_force_ssh` |
| `source_ip` | IPv4 / IPv6 | canonical string, validated |

Normalizing `alert_type` matters more than it looks. Without it,
`"C2 Beacon"` from Zeek and `"c2_beacon"` from the SIEM would never
deduplicate together.

**Rejection, not crashing.** Records that can't be triaged (missing source
IP, unparseable timestamp, unknown severity, not a JSON object) are collected
as `RejectedAlert`s with a reason and listed in the report appendix. An alert
that disappears inside the pipeline is worse than a noisy one, so nothing is
dropped without being reported.

### Stage 2 · Deduplicate

[`alerttriage/dedup.py`](alerttriage/dedup.py)

**Indicator.** Two alerts describe the same underlying activity if they
share a **source IP** and a normalized **alert type**.

**Time window: rolling sessions.** Alerts for one indicator are sorted by
time. An alert joins the current incident if it arrives within `--window`
minutes (default 15) of that incident's **most recent** alert. A larger gap
starts a new incident.

```
window = 15m

10:00  10:05  10:12  10:20             11:30  11:31
  │──────│──────│──────│                  │──────│
  └──────── incident A ───┘                └─ B ──┘
         (each gap ≤ 15m)           (70m gap → new incident)
```

Why rolling instead of fixed buckets (10:00–10:15, 10:15–10:30, …)?

- **Fixed buckets split attacks at arbitrary edges.** A brute force running
  from 10:14 to 10:16 would become two tickets.
- **Slow, persistent activity should be one ticket.** One attempt every 12
  minutes for 6 hours is a single sustained incident with a high count, not
  30 separate tickets. Sample batch 3 includes this case: a misconfigured
  backup job.
- **Real gaps still split.** If an attacker goes quiet and comes back hours
  later, that's a separate ticket. It may be a new campaign and deserves its
  own look. Batch 3 shows this with two SQL injection bursts from the same IP,
  three hours apart.

**Exact duplicates** (the same `alert_id` seen twice, e.g. a sensor re-send
or overlapping exports) are dropped before clustering so they don't inflate
the frequency score. The summary table reports how many were dropped.

### Stage 3 · Score

[`alerttriage/scoring.py`](alerttriage/scoring.py)

Each incident gets a **0–100 score** from five additive components. Each one
is a question an experienced analyst asks when scanning a queue:

| Component | Range | Question | Formula |
| :--- | :--- | :--- | :--- |
| **Severity** | 10 – 70 | How bad did the sensor say it was? | Highest severity in the incident: Info 10, Low 25, Medium 40, High 55, Critical 70 |
| **Frequency** | 0 – 15 | One-off, or sustained? | `min(15, 5 × log₂(count))`: 1→0, 2→5, 4→10, 8+→15 |
| **Blast radius** | 0 – 10 | How widely did it spread? | `min(10, 2.5 × (targets − 1))`, where targets = max(distinct assets, distinct users) |
| **Threat category** | −10 – +10 | Is this type inherently urgent, or inherently noisy? | Lookup table (see below) |
| **Correlation** | 0 – 15 | Is this source doing *other* bad things too? | `min(15, 7.5 × other alert types from the same IP)` |

The total is clamped to 0–100.

**Design rationale**

- **Severity dominates on purpose.** One critical alert should beat a thousand
  informational ones. The other four factors only move an incident about one
  severity band up or down. That matches how human triage works: the sensor
  sets the baseline, and context adjusts it.
- **Frequency is logarithmic.** Going from 1 to 8 occurrences tells you a lot
  (the activity is sustained). Going from 1,000 to 1,008 tells you nothing new.
  With a linear scale, one noisy low-severity rule would bury everything else.
- **Blast radius counts targets carefully.** Each alert contributes one asset:
  its hostname, or its destination IP if no hostname is present. That stops
  `bastion-01` and `10.0.1.10` from being counted as two targets when they are
  the same machine. Taking `max(assets, users)` instead of the sum keeps
  "one user on one host" at 1, while a phishing wave to 9 users or a scan of 6
  hosts scores high.
- **Correlation detects kill-chain progression.** A port scan, an SSH brute
  force and a successful login from one IP are each fairly routine on their
  own. Together they are an intrusion. Correlation lets those pieces raise
  each other's priority.

**Threat category modifiers**

| Modifier | Alert types |
| ---: | :--- |
| **+10** | `ransomware_activity`, `data_exfiltration`, `credential_dumping`, `web_shell_upload` |
| **+8** | `c2_beacon`, `successful_login_after_failures`, `privilege_escalation`, `lateral_movement` |
| **+5** | `malware_detected`, `dns_tunneling`, `impossible_travel` |
| **−3** | `tor_exit_node_connection`, `geo_anomaly` |
| **−5** | `port_scan`, `policy_violation` |

Positive modifiers go to late kill-chain stages, where minutes matter.
Negative modifiers go to high-volume, low-fidelity detections. Unknown types
get 0. All weights live in `ScoringConfig`, so a SOC can tune them without
touching the logic.

### Stage 4 · Prioritize & rank

**Priority bands**

| Priority | Score | Ack SLA | Meaning |
| :--- | :--- | :--- | :--- |
| 🔴 **P1** Critical | ≥ 80 | 15 min | Probable active compromise. Drop everything. |
| 🟠 **P2** High | 60 – 79.9 | 1 h | Likely malicious, or high-impact if real. |
| 🟡 **P3** Medium | 40 – 59.9 | 4 h | Suspicious; investigate during the shift. |
| 🔵 **P4** Low | < 40 | 24 h | Noise, policy, or recon. Batch-review or tune. |

**Critical floor rule.** An incident that contains a CRITICAL alert is never
ranked below P2, whatever its score. With the default weights this can't
happen anyway (the lowest possible critical score is 70 − 10 = 60, which is
already P2). The rule is a guard against tuning: if someone lowers the
severity weights or adds a large negative modifier, a human still looks at
anything a sensor called critical within the hour.

**Ranking within the queue** (each key only breaks ties in the ones above it):

1. **Priority band.** P1 before P2.
2. **Max severity, within the band.** A single *critical* "successful login
   after failures" ranks above the 26 *high* brute-force alerts that led to
   it, even though volume gives the brute force a slightly higher score. The
   login is the compromise; the brute force is context. The score decides
   which band a ticket is in, and severity leads inside the band.
3. **Score.**
4. **Most recent activity.** Something still happening beats something that
   stopped hours ago.
5. **Alert count.**
6. **Source IP / type.** Only so the output is deterministic.

Ticket IDs (`TRI-0001`, …) follow queue order, so `TRI-0001` is always the
first ticket to work. Tickets that share a source IP are cross-linked as
**Related tickets** so they can be worked together.

### Worked example

From sample batch 1, where attacker `203.0.113.45` raised three alert types:

| Ticket | Severity | Frequency | Blast radius | Category | Correlation | **Score** | **Priority** |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| Successful Login After Failures (1 alert) | 70 | 0 | 0 | +8 | 15 | **93.0** | 🔴 P1, rank 1 |
| Brute Force SSH (26 alerts, 6 users) | 55 | 15 | 10 | 0 | 15 | **95.0** | 🔴 P1, rank 2 |
| Port Scan (6 alerts, 6 hosts) | 40 | 12.9 | 10 | −5 | 15 | **72.9** | 🟠 P2 |
| *Same port scan with no follow-up activity* | 40 | 12.9 | 10 | −5 | 0 | *57.9* | *🟡 P3* |

The last row shows what correlation does. On its own, the scan would be a P3.
Because the same IP went on to brute-force and log in, it becomes a P2 and is
linked to the two P1 tickets.

---

## Sample batches

All IPs use RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918 private ranges. Hostnames
and users are fictional.

### `batch_01_overnight_perimeter.json`: external brute force to compromise

46 alerts in a plain JSON array. Mixed severity formats (`"high"`, `"High"`,
`4`, `"crit"`) and one re-sent duplicate.

- `203.0.113.45` scans 6 hosts, brute-forces SSH on `bastion-01` across 6
  usernames (26 alerts), then **logs in successfully as `deploy`**.
- Background noise: an RDP brute force, Tor exit node connections, a Shodan
  probe, and BitTorrent policy violations.

**Result:** 7 tickets (85% reduction). The successful login is `TRI-0001`,
and the scan is promoted to P2 by correlation.

### `batch_02_phishing_to_c2.json`: phishing → malware → C2 → exfiltration

38 alerts in the `{"batch_id": …, "alerts": [...]}` envelope format.

- `192.0.2.66` sends a macro-laden invoice to 9 users.
- `fin-ws-07` (`10.0.5.23`) runs the macro, loads a Cobalt Strike beacon, sends
  19 beacons to `198.51.100.77` at 5-minute intervals, tunnels DNS, then
  **exfiltrates 1.8 GB of payroll data**.
- Distractors: an impossible-travel sign-in, an auto-quarantined adware hit,
  and a blocked file-sharing site.

**Result:** 8 tickets (79% reduction). All three P1s are the compromised host
and are cross-linked. Data exfiltration is first because it is critical and
the most recent. The 19 beacons collapse into one ticket.

### `batch_03_mixed_day_shift.json`: noisy shift with dirty data

88 records, including **5 malformed ones** (missing source IP, a free-text
timestamp, invalid IP `999.10.1.1`, vendor severity `"urgent"`, and a raw
syslog string). It also mixes timestamp formats: epoch, `+02:00` offset, and
`Z`.

- `192.0.2.10` runs SQL injection against `web-prod-02` in two bursts three
  hours apart, then **uploads a web shell**.
- Privilege escalation followed by `/etc/shadow` access on `app-prod-05`.
- Noise: an internal Nessus scanner (22 alerts, 18 hosts), a misconfigured
  backup job failing SSH auth every 12 minutes for 6 hours, single port scans
  from six internet IPs, and policy violations.

**Result:** 17 tickets (80% reduction), with the web shell as the only P1. The
two SQLi bursts are separate tickets because of the gap. The 6-hour backup-job
noise chains into one P3, and all 5 bad records appear in the appendix.

---

## Input format

A JSON file containing **either** a bare array of alerts **or** an object
with an `"alerts"` array (other top-level keys are ignored):

```json
[
  {
    "alert_id": "IDS-0412-00033",
    "timestamp": "2026-09-28T02:51:01Z",
    "source_ip": "203.0.113.45",
    "alert_type": "Successful Login After Failures",
    "severity": "critical",
    "description": "Accepted password for 'deploy' from 203.0.113.45 after 143 failed attempts",
    "hostname": "bastion-01",
    "dest_ip": "10.0.1.10",
    "user": "deploy",
    "sensor": "wazuh-mgr"
  }
]
```

| Field | Required | Notes |
| :--- | :---: | :--- |
| `timestamp` | ✅ | ISO-8601 or Unix epoch seconds. Naive values are treated as UTC. |
| `source_ip` | ✅ | IPv4 or IPv6. Half of the dedup key. |
| `alert_type` | ✅ | Free text, normalized to snake_case. The other half of the dedup key. |
| `severity` | ✅ | See the normalization table above. |
| `description` | ✅ | Shown as evidence on the ticket. |
| `alert_id` / `id` | | Used for exact-duplicate removal. Defaults to `<file>#<index>`. |
| `hostname`, `dest_ip`, `user` | | Used for blast radius and ticket context. |
| `sensor` / `source` | | The tool that raised the alert, shown on the ticket. |

Pass several files to merge them into one queue, for example IDS, EDR and
email-gateway exports from the same shift.

---

## CLI reference

```
alerttriage INPUT [INPUT ...] [options]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-o, --output FILE` | stdout | Write the Markdown report to a file. |
| `-w, --window MIN` | `15` | Dedup window: the largest gap in minutes between alerts in one incident. |
| `--min-priority PN` | all | Show only tickets at this priority or higher (`P2` shows P1 and P2). The summary still counts everything. |
| `--details N` | all | Render full cards for only the top N tickets. The queue table still lists every ticket. |
| `--prefix STR` | `TRI` | Ticket ID prefix. |
| `--generated-at ISO` | now | Fix the report timestamp, for reproducible output. |
| `--version` | | Print the version. |

Exit codes: `0` on success, `2` if an input file is missing, isn't valid JSON,
or has the wrong shape. Malformed *records* are not errors; they go to the
appendix.

```bash
# The morning handover: what needs action in the next hour?
alerttriage samples/*.json --min-priority P2 -o handover.md

# Tighter clustering (5 min) for a high-volume feed
alerttriage feed.json --window 5

# Print to the terminal and skim the queue table
alerttriage samples/batch_02_phishing_to_c2.json --details 0 | less
```

---

## Using it as a library

Each stage can be called on its own. For example, you could feed alerts from
a SIEM API instead of from files:

```python
from datetime import timedelta
from alerttriage.ingest import load_alerts
from alerttriage.dedup import deduplicate
from alerttriage.scoring import build_queue, ScoringConfig

alerts, rejected = load_alerts(["samples/batch_02_phishing_to_c2.json"])
incidents = deduplicate(alerts, window=timedelta(minutes=10))

config = ScoringConfig()
config.category_modifiers["phishing_email"] = 5   # tune for your environment
tickets = build_queue(incidents, config)

for t in tickets[:3]:
    print(t.ticket_id, t.priority.name, t.score, t.incident.alert_type, t.incident.source_ip)
    for c in t.breakdown:
        print(f"   {c.name:<16}{c.points:+6.1f}  {c.reason}")
```

---

## Project layout

```
soc-alert-triage/
├── alerttriage/
│   ├── models.py      # Alert, Incident, Ticket, Severity, Priority dataclasses
│   ├── ingest.py      # Stage 1: load + normalize + validate JSON
│   ├── dedup.py       # Stage 2: rolling-window clustering by (source_ip, alert_type)
│   ├── scoring.py     # Stage 3: 5-factor score, priority bands, ranking
│   ├── report.py      # Stage 4: Markdown rendering
│   ├── playbooks.py   # First-response steps per alert type
│   ├── cli.py         # argparse entry point wiring the stages together
│   └── __main__.py    # enables `python -m alerttriage`
├── samples/           # 3 demo alert batches
├── examples/          # reports generated from the samples
├── tests/             # pytest suite (74 tests)
└── pyproject.toml
```

---

## Running the tests

```bash
pip install pytest      # the only dev dependency
python -m pytest -q
```

The suite covers each normalizer (including the inputs that should be
rejected), the dedup window edges (inclusive boundary, rolling vs fixed, zero
window, out-of-order input), each score component, the priority thresholds and
critical floor, the ranking order, Markdown escaping, and end-to-end CLI runs
that check the top ticket for every sample.

To regenerate the example reports after changing the logic:

```bash
for f in samples/*.json; do
  python -m alerttriage "$f" --generated-at 2026-10-03T08:00:00Z \
    -o "examples/$(basename "$f" .json)_report.md"
done
```

---

## Design decisions & limitations

**Decisions**

- **Additive score instead of an ML model.** Analysts need to trust and
  question the ranking. An additive score with a visible breakdown can be
  argued with ("why is this P2?"). A model's output usually can't be. The
  weights are a starting point, meant to be tuned against a SOC's own
  closed-ticket history.
- **Internal-IP detection uses an explicit list.** Python's
  `ipaddress.is_private` returns `True` for documentation ranges such as
  `203.0.113.0/24`, which would label an external attacker "internal". The
  tool checks against RFC 1918, CGNAT, loopback, link-local and IPv6 ULA
  instead (`models.INTERNAL_NETWORKS`). A test pins this behavior.
- **Markdown output.** It renders in GitHub, GitLab, Confluence, Obsidian and
  most ticketing systems, diffs cleanly, and needs no viewer. Ticket anchors
  are explicit `<a id>` tags, so queue links work regardless of each
  renderer's slug rules.

**Known limitations**

- **The dedup key is source IP only.** Activity is not correlated by user or
  destination. In batch 2, `m.chen` gets both the phishing email and the
  impossible-travel alert, but the two tickets aren't linked.
- **No allowlist or suppression.** The authorized Nessus scanner in batch 3
  still produces a P3. In production, known scanners and service accounts
  would be suppressed or down-weighted.
- **Batch, not streaming.** Each run triages one snapshot. There is no state
  between runs, so an incident spanning two exports becomes two tickets.
- **NAT and shared IPs** (proxies, CGNAT, cloud egress) can merge unrelated
  activity under one source IP.
- **No threat-intel enrichment.** IP reputation, ASN and geolocation aren't
  looked up.

## Roadmap

- [ ] Suppression list (YAML) for known scanners, service accounts and accepted risks
- [ ] Correlate by user and destination asset as well as source IP
- [ ] Optional threat-intel enrichment (AbuseIPDB / OTX), cached locally
- [ ] JSON output for pushing tickets into TheHive, Jira or ServiceNow
- [ ] MITRE ATT&CK technique tags per alert type
- [ ] Stateful mode that carries open incidents across runs
