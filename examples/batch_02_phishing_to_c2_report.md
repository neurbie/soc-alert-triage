# SOC Triage Queue

**Generated:** 2026-10-03 08:00:00 UTC  
**Input:** `batch_02_phishing_to_c2.json`  
**Alert window:** 2026-09-29 09:02:36 UTC → 2026-09-29 11:07:41 UTC  
**Dedup window:** 15m 00s rolling, keyed on source IP + alert type

## Shift Summary

| Alerts received | Rejected (malformed) | Exact duplicates | Tickets after dedup | Noise reduction |
| ---: | ---: | ---: | ---: | ---: |
| 38 | 0 | 0 | 8 | 79% |

| Priority | Tickets | Underlying alerts | Ack SLA |
| :--- | ---: | ---: | ---: |
| 🔴 P1 Critical | 3 | 22 | 15 min |
| 🟠 P2 High | 3 | 14 | 1 h |
| 🟡 P3 Medium | 0 | 0 | 4 h |
| 🔵 P4 Low | 2 | 2 | 24 h |

> **⚠ 3 P1 ticket(s) need acknowledgement within 15 min.** Start at the top of the queue.

## Queue

Work top-down. Ticket numbers follow queue order.

| # | Ticket | Pri | Score | Alert type | Source | Max sev | Alerts | Targets | Last seen |
| ---: | :--- | :--- | ---: | :--- | :--- | :--- | ---: | ---: | :--- |
| 1 | [TRI-0001](#tri-0001) | 🔴 P1 | 95.0 | Data Exfiltration | `10.0.5.23` (int) | Critical | 1 | 1 | 09-29 11:07 |
| 2 | [TRI-0002](#tri-0002) | 🔴 P1 | 95.0 | Malware Detected | `10.0.5.23` (int) | Critical | 2 | 1 | 09-29 09:32 |
| 3 | [TRI-0003](#tri-0003) | 🔴 P1 | 93.0 | C2 Beacon | `10.0.5.23` (int) | High | 19 | 1 | 09-29 11:05 |
| 4 | [TRI-0004](#tri-0004) | 🟠 P2 | 60.0 | Impossible Travel | `203.0.113.190` | High | 1 | 1 | 09-29 10:03 |
| 5 | [TRI-0005](#tri-0005) | 🟠 P2 | 70.0 | DNS Tunneling | `10.0.5.23` (int) | Medium | 4 | 1 | 09-29 10:53 |
| 6 | [TRI-0006](#tri-0006) | 🟠 P2 | 65.0 | Phishing Email | `192.0.2.66` | Medium | 9 | 9 | 09-29 09:08 |
| 7 | [TRI-0007](#tri-0007) | 🔵 P4 | 30.0 | Malware Detected | `10.0.5.41` (int) | Low | 1 | 1 | 09-29 10:12 |
| 8 | [TRI-0008](#tri-0008) | 🔵 P4 | 5.0 | Policy Violation | `10.0.9.4` (int) | Info | 1 | 1 | 09-29 09:50 |

## Tickets

<a id="tri-0001"></a>
### 🔴 P1 · TRI-0001 · Data Exfiltration from 10.0.5.23

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **95.0** / 100 |
| Max severity | Critical |
| Source IP | `10.0.5.23` (internal) |
| Occurrences | 1 alert at 2026-09-29 11:07:41 UTC |
| Hosts | `fin-ws-07` |
| Users | `j.alvarez` |
| Destination IPs | `198.51.100.77` |
| Sensors | `zeek` |
| Related tickets | [TRI-0002](#tri-0002), [TRI-0003](#tri-0003), [TRI-0005](#tri-0005) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +70.0 | highest alert severity is Critical |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +10.0 | 'data_exfiltration' is a high-impact category |
| Correlation | +15.0 | same source also raised: c2_beacon, dns_tunneling, malware_detected |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 11:07:41 | `SIEM-7730-00035` | Critical | 1.8 GB outbound to 198.51.100.77 over 6 min; files from \\\\fs01\\finance\\payroll staged in %TEMP%\\a.7z |

**Recommended first response**

1. Engage incident response lead - potential breach notification event.
2. Block the destination and isolate the source host.
3. Quantify what left: volume, file names, data classification.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0002"></a>
### 🔴 P1 · TRI-0002 · Malware Detected from 10.0.5.23

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **95.0** / 100 |
| Max severity | Critical |
| Source IP | `10.0.5.23` (internal) |
| Occurrences | 2 alerts over 48s (2026-09-29 09:31:14 UTC → 2026-09-29 09:32:02 UTC) |
| Hosts | `fin-ws-07` |
| Users | `j.alvarez` |
| Destination IPs | — |
| Sensors | `crowdstrike` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0003](#tri-0003), [TRI-0005](#tri-0005) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +70.0 | highest alert severity is Critical |
| Frequency | +5.0 | 2 alert(s) over 48s |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +5.0 | 'malware_detected' is a high-impact category |
| Correlation | +15.0 | same source also raised: c2_beacon, data_exfiltration, dns_tunneling |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:31:14 | `SIEM-7730-00010` | High | Malicious macro: EXCEL.EXE spawned powershell.exe -enc ... (Invoice_8841.xlsm) |
| 09:32:02 | `SIEM-7730-00011` | Critical | Cobalt Strike beacon DLL loaded into rundll32.exe (C:\\Users\\Public\\upd.dll) - NOT quarantined |

**Recommended first response**

1. Isolate the host via EDR if the detection was not auto-remediated.
2. Retrieve the file hash and check prevalence across the fleet.
3. Identify the infection vector (email, download, USB) and scope other victims.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0003"></a>
### 🔴 P1 · TRI-0003 · C2 Beacon from 10.0.5.23

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **93.0** / 100 |
| Max severity | High |
| Source IP | `10.0.5.23` (internal) |
| Occurrences | 19 alerts over 1h 30m (2026-09-29 09:35:02 UTC → 2026-09-29 11:05:07 UTC) |
| Hosts | `fin-ws-07` |
| Users | — |
| Destination IPs | `198.51.100.77` |
| Sensors | `zeek` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0002](#tri-0002), [TRI-0005](#tri-0005) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +15.0 | 19 alert(s) over 1h 30m |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | +8.0 | 'c2_beacon' is a high-impact category |
| Correlation | +15.0 | same source also raised: data_exfiltration, dns_tunneling, malware_detected |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:35:02 | `SIEM-7730-00012` | High | Periodic HTTPS beaconing to 198.51.100.77 (interval ~300s, jitter 5%, JA3 matches Cobalt Strike) |
| 09:39:53 | `SIEM-7730-00013` | High | Periodic HTTPS beaconing to 198.51.100.77 (interval ~300s, jitter 5%, JA3 matches Cobalt Strike) |
| 09:44:50 | `SIEM-7730-00014` | High | Periodic HTTPS beaconing to 198.51.100.77 (interval ~300s, jitter 5%, JA3 matches Cobalt Strike) |
| 09:49:52 | `SIEM-7730-00015` | High | Periodic HTTPS beaconing to 198.51.100.77 (interval ~300s, jitter 5%, JA3 matches Cobalt Strike) |
| 11:05:07 | `SIEM-7730-00030` | High | Periodic HTTPS beaconing to 198.51.100.77 (interval ~300s, jitter 5%, JA3 matches Cobalt Strike) |

_…and 14 more alert(s) in this incident._

**Recommended first response**

1. Isolate the internal host immediately; beaconing implies an active implant.
2. Block the C2 destination at DNS and proxy; hunt for other hosts contacting it.
3. Capture memory before reimaging if forensics are required.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0004"></a>
### 🟠 P2 · TRI-0004 · Impossible Travel from 203.0.113.190

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **60.0** / 100 |
| Max severity | High |
| Source IP | `203.0.113.190` (external) |
| Occurrences | 1 alert at 2026-09-29 10:03:55 UTC |
| Hosts | — |
| Users | `m.chen` |
| Destination IPs | — |
| Sensors | `entra-id` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 0 asset(s), 1 user(s) |
| Threat category | +5.0 | 'impossible_travel' is a high-impact category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 10:03:55 | `SIEM-7730-00037` | High | Sign-in for m.chen from Lagos, NG 34 min after sign-in from Chicago, US (8,700 km) |

**Recommended first response**

1. Confirm with the user whether both logins are theirs (VPN, travel).
2. If not, revoke sessions and force a password reset with MFA re-enrollment.
3. Review mailbox rules and OAuth grants created during the suspicious session.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0005"></a>
### 🟠 P2 · TRI-0005 · DNS Tunneling from 10.0.5.23

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **70.0** / 100 |
| Max severity | Medium |
| Source IP | `10.0.5.23` (internal) |
| Occurrences | 4 alerts over 8m 00s (2026-09-29 10:45:00 UTC → 2026-09-29 10:53:00 UTC) |
| Hosts | `fin-ws-07` |
| Users | — |
| Destination IPs | — |
| Sensors | `zeek` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0002](#tri-0002), [TRI-0003](#tri-0003) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +40.0 | highest alert severity is Medium |
| Frequency | +10.0 | 4 alert(s) over 8m |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | +5.0 | 'dns_tunneling' is a high-impact category |
| Correlation | +15.0 | same source also raised: c2_beacon, data_exfiltration, malware_detected |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 10:45:00 | `SIEM-7730-00031` | Medium | High-entropy DNS TXT queries: 4ba07346513866e216c8a4c296eb608d13b90542deb93aee.cdn-sync.example (777 queries/… |
| 10:47:00 | `SIEM-7730-00032` | Medium | High-entropy DNS TXT queries: 98af0f11b88634a75dfca30f0dcf61b7174890ccce526aa1.cdn-sync.example (360 queries/… |
| 10:49:00 | `SIEM-7730-00033` | Medium | High-entropy DNS TXT queries: 623ea7395b4abcb57769fa9f0c70cf71c1f7a73d43b954a5.cdn-sync.example (898 queries/… |
| 10:53:00 | `SIEM-7730-00034` | Medium | High-entropy DNS TXT queries: 0dab66b6ab78c480c855beed17fe02694c50f92c292ed0ef.cdn-sync.example (455 queries/… |

**Recommended first response**

1. Inspect the queried domain (length/entropy of subdomains, registration age).
2. Sinkhole or block the domain; isolate the querying host.
3. Hunt for the process generating the queries on the endpoint.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0006"></a>
### 🟠 P2 · TRI-0006 · Phishing Email from 192.0.2.66

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **65.0** / 100 |
| Max severity | Medium |
| Source IP | `192.0.2.66` (external) |
| Occurrences | 9 alerts over 5m 59s (2026-09-29 09:02:36 UTC → 2026-09-29 09:08:35 UTC) |
| Hosts | — |
| Users | `a.kowalski`, `d.oyelaran`, `j.alvarez`, `k.nguyen`, `l.fischer`, `m.chen`, `r.patel`, `s.brooks` +1 more |
| Destination IPs | — |
| Sensors | `proofpoint` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +40.0 | highest alert severity is Medium |
| Frequency | +15.0 | 9 alert(s) over 5m |
| Blast radius | +10.0 | 0 asset(s), 9 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:02:36 | `SIEM-7730-00001` | Medium | Suspicious email to j.alvarez@corp.example: 'Q3 Invoice Overdue - Action Required' with macro-enabled attachm… |
| 09:03:41 | `SIEM-7730-00002` | Medium | Suspicious email to k.nguyen@corp.example: 'Q3 Invoice Overdue - Action Required' with macro-enabled attachme… |
| 09:04:14 | `SIEM-7730-00003` | Medium | Suspicious email to r.patel@corp.example: 'Q3 Invoice Overdue - Action Required' with macro-enabled attachmen… |
| 09:04:46 | `SIEM-7730-00004` | Medium | Suspicious email to s.brooks@corp.example: 'Q3 Invoice Overdue - Action Required' with macro-enabled attachme… |
| 09:08:35 | `SIEM-7730-00009` | Medium | Suspicious email to t.haddad@corp.example: 'Q3 Invoice Overdue - Action Required' with macro-enabled attachme… |

_…and 4 more alert(s) in this incident._

**Recommended first response**

1. Pull the message from all mailboxes (search by sender / subject / hash).
2. Check proxy and email logs for recipients who clicked or opened attachments.
3. Block sender domain and any embedded URLs; submit IOCs to threat intel.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0007"></a>
### 🔵 P4 · TRI-0007 · Malware Detected from 10.0.5.41

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **30.0** / 100 |
| Max severity | Low |
| Source IP | `10.0.5.41` (internal) |
| Occurrences | 1 alert at 2026-09-29 10:12:09 UTC |
| Hosts | `fin-ws-12` |
| Users | `k.nguyen` |
| Destination IPs | — |
| Sensors | `crowdstrike` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +5.0 | 'malware_detected' is a high-impact category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 10:12:09 | `SIEM-7730-00036` | Low | PUP/Adware.BrowserAssist quarantined automatically |

**Recommended first response**

1. Isolate the host via EDR if the detection was not auto-remediated.
2. Retrieve the file hash and check prevalence across the fleet.
3. Identify the infection vector (email, download, USB) and scope other victims.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0008"></a>
### 🔵 P4 · TRI-0008 · Policy Violation from 10.0.9.4

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **5.0** / 100 |
| Max severity | Info |
| Source IP | `10.0.9.4` (internal) |
| Occurrences | 1 alert at 2026-09-29 09:50:00 UTC |
| Hosts | `hr-lt-03` |
| Users | `s.brooks` |
| Destination IPs | — |
| Sensors | `zscaler` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +10.0 | highest alert severity is Info |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | -5.0 | 'policy_violation' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:50:00 | `SIEM-7730-00038` | Info | Access to uncategorized file-sharing site blocked |

**Recommended first response**

1. Verify the activity against acceptable-use policy.
2. Notify the user's manager or IT per policy if confirmed.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<sub>Generated by AlertTriage. Scores are decision support, not a verdict — verify before acting.</sub>
