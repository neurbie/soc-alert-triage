# SOC Triage Queue

**Generated:** 2026-10-03 08:00:00 UTC  
**Input:** `batch_03_mixed_day_shift.json`  
**Alert window:** 2026-09-30 07:12:00 UTC → 2026-09-30 15:41:10 UTC  
**Dedup window:** 15m 00s rolling, keyed on source IP + alert type

## Shift Summary

| Alerts received | Rejected (malformed) | Exact duplicates | Tickets after dedup | Noise reduction |
| ---: | ---: | ---: | ---: | ---: |
| 88 | 5 | 0 | 17 | 80% |

| Priority | Tickets | Underlying alerts | Ack SLA |
| :--- | ---: | ---: | ---: |
| 🔴 P1 Critical | 1 | 1 | 15 min |
| 🟠 P2 High | 4 | 19 | 1 h |
| 🟡 P3 Medium | 3 | 54 | 4 h |
| 🔵 P4 Low | 9 | 9 | 24 h |

> **⚠ 1 P1 ticket(s) need acknowledgement within 15 min.** Start at the top of the queue.

## Queue

Work top-down. Ticket numbers follow queue order.

| # | Ticket | Pri | Score | Alert type | Source | Max sev | Alerts | Targets | Last seen |
| ---: | :--- | :--- | ---: | :--- | :--- | :--- | ---: | ---: | :--- |
| 1 | [TRI-0001](#tri-0001) | 🔴 P1 | 87.5 | Web Shell Upload | `192.0.2.10` | Critical | 1 | 1 | 09-30 13:04 |
| 2 | [TRI-0002](#tri-0002) | 🟠 P2 | 77.5 | SQL Injection | `192.0.2.10` | High | 12 | 1 | 09-30 10:17 |
| 3 | [TRI-0003](#tri-0003) | 🟠 P2 | 74.1 | SQL Injection | `192.0.2.10` | High | 5 | 1 | 09-30 13:03 |
| 4 | [TRI-0004](#tri-0004) | 🟠 P2 | 72.5 | Credential Dumping | `10.0.2.33` (int) | High | 1 | 1 | 09-30 14:25 |
| 5 | [TRI-0005](#tri-0005) | 🟠 P2 | 70.5 | Privilege Escalation | `10.0.2.33` (int) | High | 1 | 1 | 09-30 14:22 |
| 6 | [TRI-0006](#tri-0006) | 🟡 P3 | 42.0 | Geo Anomaly | `203.0.113.240` | Medium | 2 | 1 | 09-30 15:41 |
| 7 | [TRI-0007](#tri-0007) | 🟡 P3 | 45.0 | Port Scan | `10.0.0.5` (int) | Low | 22 | 18 | 09-30 09:20 |
| 8 | [TRI-0008](#tri-0008) | 🟡 P3 | 40.0 | Brute Force SSH | `10.0.3.50` (int) | Low | 30 | 1 | 09-30 13:00 |
| 9 | [TRI-0009](#tri-0009) | 🔵 P4 | 20.0 | Port Scan | `203.0.113.77` | Low | 1 | 1 | 09-30 13:56 |
| 10 | [TRI-0010](#tri-0010) | 🔵 P4 | 20.0 | Port Scan | `198.51.100.199` | Low | 1 | 1 | 09-30 13:10 |
| 11 | [TRI-0011](#tri-0011) | 🔵 P4 | 20.0 | Port Scan | `203.0.113.9` | Low | 1 | 1 | 09-30 12:34 |
| 12 | [TRI-0012](#tri-0012) | 🔵 P4 | 20.0 | Port Scan | `198.51.100.4` | Low | 1 | 1 | 09-30 12:26 |
| 13 | [TRI-0013](#tri-0013) | 🔵 P4 | 20.0 | Port Scan | `192.0.2.150` | Low | 1 | 1 | 09-30 10:27 |
| 14 | [TRI-0014](#tri-0014) | 🔵 P4 | 20.0 | Port Scan | `198.51.100.61` | Low | 1 | 1 | 09-30 09:41 |
| 15 | [TRI-0015](#tri-0015) | 🔵 P4 | 5.0 | Policy Violation | `10.0.6.30` (int) | Info | 1 | 1 | 09-30 14:26 |
| 16 | [TRI-0016](#tri-0016) | 🔵 P4 | 5.0 | Policy Violation | `10.0.6.21` (int) | Info | 1 | 1 | 09-30 13:11 |
| 17 | [TRI-0017](#tri-0017) | 🔵 P4 | 5.0 | Policy Violation | `10.0.6.30` (int) | Info | 1 | 1 | 09-30 10:22 |

## Tickets

<a id="tri-0001"></a>
### 🔴 P1 · TRI-0001 · Web Shell Upload from 192.0.2.10

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **87.5** / 100 |
| Max severity | Critical |
| Source IP | `192.0.2.10` (external) |
| Occurrences | 1 alert at 2026-09-30 13:04:29 UTC |
| Hosts | `web-prod-02` |
| Users | — |
| Destination IPs | `10.0.2.20` |
| Sensors | `crowdstrike` |
| Related tickets | [TRI-0002](#tri-0002), [TRI-0003](#tri-0003) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +70.0 | highest alert severity is Critical |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | +10.0 | 'web_shell_upload' is a high-impact category |
| Correlation | +7.5 | same source also raised: sql_injection |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 13:04:29 | `SOC-1188-00018` | Critical | w3wp.exe wrote /uploads/img/thumb.aspx; file matches China Chopper web shell signature |

**Recommended first response**

1. Locate and quarantine the uploaded file on the web server.
2. Review web server access logs for requests to the uploaded path.
3. Treat the server as compromised; check for lateral movement from it.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0002"></a>
### 🟠 P2 · TRI-0002 · SQL Injection from 192.0.2.10

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **77.5** / 100 |
| Max severity | High |
| Source IP | `192.0.2.10` (external) |
| Occurrences | 12 alerts over 17m 18s (2026-09-30 10:00:35 UTC → 2026-09-30 10:17:53 UTC) |
| Hosts | `web-prod-02` |
| Users | — |
| Destination IPs | `10.0.2.20` |
| Sensors | `modsecurity` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0003](#tri-0003) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +15.0 | 12 alert(s) over 17m |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +7.5 | same source also raised: web_shell_upload |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 10:00:35 | `SOC-1188-00001` | High | ModSecurity 942100: SQLi in param 'id' on /api/v1/orders: ' OR 1=1-- |
| 10:01:12 | `SOC-1188-00002` | High | ModSecurity 942100: SQLi in param 'id' on /api/v1/orders: UNION SELECT username,password FROM users-- |
| 10:03:22 | `SOC-1188-00003` | High | ModSecurity 942100: SQLi in param 'id' on /api/v1/orders: '; WAITFOR DELAY '0:0:5'-- |
| 10:04:07 | `SOC-1188-00004` | High | ModSecurity 942100: SQLi in param 'id' on /api/v1/orders: '; WAITFOR DELAY '0:0:5'-- |
| 10:17:53 | `SOC-1188-00012` | High | ModSecurity 942100: SQLi in param 'id' on /api/v1/orders: UNION SELECT username,password FROM users-- |

_…and 7 more alert(s) in this incident._

**Recommended first response**

1. Check web server responses: did any injected request return 200 with data?
2. Review database logs for unexpected queries in the same window.
3. Block source at WAF; file a ticket with the app owner to fix the input handling.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0003"></a>
### 🟠 P2 · TRI-0003 · SQL Injection from 192.0.2.10

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **74.1** / 100 |
| Max severity | High |
| Source IP | `192.0.2.10` (external) |
| Occurrences | 5 alerts over 2m 29s (2026-09-30 13:00:53 UTC → 2026-09-30 13:03:22 UTC) |
| Hosts | `web-prod-02` |
| Users | — |
| Destination IPs | `10.0.2.20` |
| Sensors | `modsecurity` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0002](#tri-0002) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +11.6 | 5 alert(s) over 2m |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +7.5 | same source also raised: web_shell_upload |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 13:00:53 | `SOC-1188-00013` | High | ModSecurity 942100: SQLi in param 'q' on /search: ' OR 1=1-- |
| 13:01:28 | `SOC-1188-00014` | High | ModSecurity 942100: SQLi in param 'q' on /search: ' OR 1=1-- |
| 13:02:06 | `SOC-1188-00015` | High | ModSecurity 942100: SQLi in param 'q' on /search: '; WAITFOR DELAY '0:0:5'-- |
| 13:02:44 | `SOC-1188-00016` | High | ModSecurity 942100: SQLi in param 'q' on /search: '; WAITFOR DELAY '0:0:5'-- |
| 13:03:22 | `SOC-1188-00017` | High | ModSecurity 942100: SQLi in param 'q' on /search: ' OR 1=1-- |

**Recommended first response**

1. Check web server responses: did any injected request return 200 with data?
2. Review database logs for unexpected queries in the same window.
3. Block source at WAF; file a ticket with the app owner to fix the input handling.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0004"></a>
### 🟠 P2 · TRI-0004 · Credential Dumping from 10.0.2.33

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **72.5** / 100 |
| Max severity | High |
| Source IP | `10.0.2.33` (internal) |
| Occurrences | 1 alert at 2026-09-30 14:25:02 UTC |
| Hosts | `app-prod-05` |
| Users | `root` |
| Destination IPs | — |
| Sensors | `auditd` |
| Related tickets | [TRI-0005](#tri-0005) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +10.0 | 'credential_dumping' is a high-impact category |
| Correlation | +7.5 | same source also raised: privilege_escalation |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 14:25:02 | `SOC-1188-00078` | High | Read access to /etc/shadow by non-standard process /tmp/.x/lz |

**Recommended first response**

1. Validate the alert against raw logs to rule out a false positive.
2. Determine scope: other hosts, users or IPs involved.
3. Contain if malicious, then escalate per the IR plan.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0005"></a>
### 🟠 P2 · TRI-0005 · Privilege Escalation from 10.0.2.33

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **70.5** / 100 |
| Max severity | High |
| Source IP | `10.0.2.33` (internal) |
| Occurrences | 1 alert at 2026-09-30 14:22:31 UTC |
| Hosts | `app-prod-05` |
| Users | `www-data` |
| Destination IPs | — |
| Sensors | `auditd` |
| Related tickets | [TRI-0004](#tri-0004) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +8.0 | 'privilege_escalation' is a high-impact category |
| Correlation | +7.5 | same source also raised: credential_dumping |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 14:22:31 | `SOC-1188-00077` | High | www-data executed 'sudo -u root /bin/bash' via misconfigured sudoers entry |

**Recommended first response**

1. Identify the account and process that gained elevated rights.
2. Verify against change tickets; revoke if unauthorized.
3. Review activity performed with the elevated privileges.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0006"></a>
### 🟡 P3 · TRI-0006 · Geo Anomaly from 203.0.113.240

| Field | Value |
| :--- | :--- |
| Priority | **P3 – Medium** (acknowledge within 4 h) |
| Score | **42.0** / 100 |
| Max severity | Medium |
| Source IP | `203.0.113.240` (external) |
| Occurrences | 2 alerts over 1m 10s (2026-09-30 15:40:00 UTC → 2026-09-30 15:41:10 UTC) |
| Hosts | — |
| Users | `svc_api` |
| Destination IPs | — |
| Sensors | `entra-id` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +40.0 | highest alert severity is Medium |
| Frequency | +5.0 | 2 alert(s) over 1m |
| Blast radius | +0.0 | 0 asset(s), 1 user(s) |
| Threat category | -3.0 | 'geo_anomaly' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 15:40:00 | `SOC-1188-00082` | Medium | API service principal authenticated from new country (RO) |
| 15:41:10 | `SOC-1188-00083` | Medium | API service principal authenticated from new country (RO) - repeat |

**Recommended first response**

1. Validate the alert against raw logs to rule out a false positive.
2. Determine scope: other hosts, users or IPs involved.
3. Contain if malicious, then escalate per the IR plan.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0007"></a>
### 🟡 P3 · TRI-0007 · Port Scan from 10.0.0.5

| Field | Value |
| :--- | :--- |
| Priority | **P3 – Medium** (acknowledge within 4 h) |
| Score | **45.0** / 100 |
| Max severity | Low |
| Source IP | `10.0.0.5` (internal) |
| Occurrences | 22 alerts over 19m 09s (2026-09-30 09:01:03 UTC → 2026-09-30 09:20:12 UTC) |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.3.14`, `10.0.3.17`, `10.0.3.22`, `10.0.3.25`, `10.0.3.29`, `10.0.3.34`, `10.0.3.35`, `10.0.3.37` +10 more |
| Sensors | `suricata-core` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +15.0 | 22 alert(s) over 19m |
| Blast radius | +10.0 | 18 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:01:03 | `SOC-1188-00025` | Low | ET SCAN Nessus User-Agent / TCP SYN sweep (host: vulnscan-01) |
| 09:01:34 | `SOC-1188-00026` | Low | ET SCAN Nessus User-Agent / TCP SYN sweep (host: vulnscan-01) |
| 09:02:08 | `SOC-1188-00027` | Low | ET SCAN Nessus User-Agent / TCP SYN sweep (host: vulnscan-01) |
| 09:02:50 | `SOC-1188-00028` | Low | ET SCAN Nessus User-Agent / TCP SYN sweep (host: vulnscan-01) |
| 09:20:12 | `SOC-1188-00046` | Low | ET SCAN Nessus User-Agent / TCP SYN sweep (host: vulnscan-01) |

_…and 17 more alert(s) in this incident._

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0008"></a>
### 🟡 P3 · TRI-0008 · Brute Force SSH from 10.0.3.50

| Field | Value |
| :--- | :--- |
| Priority | **P3 – Medium** (acknowledge within 4 h) |
| Score | **40.0** / 100 |
| Max severity | Low |
| Source IP | `10.0.3.50` (internal) |
| Occurrences | 30 alerts over 5h 48m (2026-09-30 07:12:00 UTC → 2026-09-30 13:00:00 UTC) |
| Hosts | `backup-01` |
| Users | `svc_backup` |
| Destination IPs | `10.0.3.12` |
| Sensors | `wazuh-mgr` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +15.0 | 30 alert(s) over 5h 48m |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 07:12:00 | `SOC-1188-00047` | Low | sshd: 6 failed publickey attempts for 'svc_backup' from 10.0.3.50 (rsync job) |
| 07:24:00 | `SOC-1188-00048` | Low | sshd: 6 failed publickey attempts for 'svc_backup' from 10.0.3.50 (rsync job) |
| 07:36:00 | `SOC-1188-00049` | Low | sshd: 6 failed publickey attempts for 'svc_backup' from 10.0.3.50 (rsync job) |
| 07:48:00 | `SOC-1188-00050` | Low | sshd: 6 failed publickey attempts for 'svc_backup' from 10.0.3.50 (rsync job) |
| 13:00:00 | `SOC-1188-00076` | Low | sshd: 6 failed publickey attempts for 'svc_backup' from 10.0.3.50 (rsync job) |

_…and 25 more alert(s) in this incident._

**Recommended first response**

1. Check auth logs on targeted hosts for any *successful* login from the source IP.
2. Block the source IP at the perimeter firewall if it is external.
3. Confirm targeted accounts have MFA / key-only auth; lock any that were guessed.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0009"></a>
### 🔵 P4 · TRI-0009 · Port Scan from 203.0.113.77

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `203.0.113.77` (external) |
| Occurrences | 1 alert at 2026-09-30 13:56:53 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.20` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 13:56:53 | `SOC-1188-00022` | Low | ET SCAN Masscan probe from 203.0.113.77 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0010"></a>
### 🔵 P4 · TRI-0010 · Port Scan from 198.51.100.199

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `198.51.100.199` (external) |
| Occurrences | 1 alert at 2026-09-30 13:10:38 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.26` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 13:10:38 | `SOC-1188-00024` | Low | ET SCAN Masscan probe from 198.51.100.199 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0011"></a>
### 🔵 P4 · TRI-0011 · Port Scan from 203.0.113.9

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `203.0.113.9` (external) |
| Occurrences | 1 alert at 2026-09-30 12:34:17 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.20` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 12:34:17 | `SOC-1188-00021` | Low | ET SCAN Masscan probe from 203.0.113.9 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0012"></a>
### 🔵 P4 · TRI-0012 · Port Scan from 198.51.100.4

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `198.51.100.4` (external) |
| Occurrences | 1 alert at 2026-09-30 12:26:20 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.25` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 12:26:20 | `SOC-1188-00019` | Low | ET SCAN Masscan probe from 198.51.100.4 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0013"></a>
### 🔵 P4 · TRI-0013 · Port Scan from 192.0.2.150

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `192.0.2.150` (external) |
| Occurrences | 1 alert at 2026-09-30 10:27:31 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.27` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 10:27:31 | `SOC-1188-00023` | Low | ET SCAN Masscan probe from 192.0.2.150 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0014"></a>
### 🔵 P4 · TRI-0014 · Port Scan from 198.51.100.61

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `198.51.100.61` (external) |
| Occurrences | 1 alert at 2026-09-30 09:41:57 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.2.28` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 09:41:57 | `SOC-1188-00020` | Low | ET SCAN Masscan probe from 198.51.100.61 |

**Recommended first response**

1. Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).
2. If unknown and external, add to blocklist and watch for follow-on exploitation.
3. Note which open services were discovered; check them for unpatched CVEs.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0015"></a>
### 🔵 P4 · TRI-0015 · Policy Violation from 10.0.6.30

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **5.0** / 100 |
| Max severity | Info |
| Source IP | `10.0.6.30` (internal) |
| Occurrences | 1 alert at 2026-09-30 14:26:00 UTC |
| Hosts | `eng-lt-07` |
| Users | `h.yamada` |
| Destination IPs | — |
| Sensors | `zscaler` |
| Related tickets | [TRI-0017](#tri-0017) |

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
| 14:26:00 | `SOC-1188-00081` | Info | Unapproved remote access tool (AnyDesk) launched |

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

<a id="tri-0016"></a>
### 🔵 P4 · TRI-0016 · Policy Violation from 10.0.6.21

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **5.0** / 100 |
| Max severity | Info |
| Source IP | `10.0.6.21` (internal) |
| Occurrences | 1 alert at 2026-09-30 13:11:00 UTC |
| Hosts | `sales-lt-22` |
| Users | `b.ross` |
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
| 13:11:00 | `SOC-1188-00079` | Info | Personal cloud storage upload (2.1 GB) |

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

<a id="tri-0017"></a>
### 🔵 P4 · TRI-0017 · Policy Violation from 10.0.6.30

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **5.0** / 100 |
| Max severity | Info |
| Source IP | `10.0.6.30` (internal) |
| Occurrences | 1 alert at 2026-09-30 10:22:00 UTC |
| Hosts | `eng-lt-07` |
| Users | `h.yamada` |
| Destination IPs | — |
| Sensors | `zscaler` |
| Related tickets | [TRI-0015](#tri-0015) |

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
| 10:22:00 | `SOC-1188-00080` | Info | Unapproved remote access tool (AnyDesk) installed |

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

## Appendix: Rejected Alerts

These records failed validation and were **not** triaged. Fix the upstream sensor/export or review them manually.

| File | Index | Reason | Raw (truncated) |
| :--- | ---: | :--- | :--- |
| `batch_03_mixed_day_shift.json` | 83 | missing required field(s): source_ip | `{"alert_id":"SOC-1188-90001","timestamp":"2026-09-30T11:02:00Z","alert_type":"m…` |
| `batch_03_mixed_day_shift.json` | 84 | unparseable timestamp 'yesterday 11pm' (expected ISO-8601) | `{"alert_id":"SOC-1188-90002","timestamp":"yesterday 11pm","source_ip":"10.0.6.5…` |
| `batch_03_mixed_day_shift.json` | 85 | invalid source_ip '999.10.1.1' | `{"alert_id":"SOC-1188-90003","timestamp":"2026-09-30T12:00:00Z","source_ip":"99…` |
| `batch_03_mixed_day_shift.json` | 86 | unknown severity 'urgent' | `{"alert_id":"SOC-1188-90004","timestamp":"2026-09-30T12:05:00Z","source_ip":"10…` |
| `batch_03_mixed_day_shift.json` | 87 | alert must be a JSON object, got str | `RAW SYSLOG: <134>Sep 30 12:10:00 fw01 DROP src=203.0.113.5` |

<sub>Generated by AlertTriage. Scores are decision support, not a verdict — verify before acting.</sub>
