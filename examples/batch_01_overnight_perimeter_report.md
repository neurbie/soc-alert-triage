# SOC Triage Queue

**Generated:** 2026-10-03 08:00:00 UTC  
**Input:** `batch_01_overnight_perimeter.json`  
**Alert window:** 2026-09-28 01:58:19 UTC → 2026-09-28 04:05:05 UTC  
**Dedup window:** 15m 00s rolling, keyed on source IP + alert type

## Shift Summary

| Alerts received | Rejected (malformed) | Exact duplicates | Tickets after dedup | Noise reduction |
| ---: | ---: | ---: | ---: | ---: |
| 46 | 0 | 1 | 7 | 85% |

| Priority | Tickets | Underlying alerts | Ack SLA |
| :--- | ---: | ---: | ---: |
| 🔴 P1 Critical | 2 | 27 | 15 min |
| 🟠 P2 High | 1 | 6 | 1 h |
| 🟡 P3 Medium | 1 | 3 | 4 h |
| 🔵 P4 Low | 3 | 9 | 24 h |

> **⚠ 2 P1 ticket(s) need acknowledgement within 15 min.** Start at the top of the queue.

## Queue

Work top-down. Ticket numbers follow queue order.

| # | Ticket | Pri | Score | Alert type | Source | Max sev | Alerts | Targets | Last seen |
| ---: | :--- | :--- | ---: | :--- | :--- | :--- | ---: | ---: | :--- |
| 1 | [TRI-0001](#tri-0001) | 🔴 P1 | 93.0 | Successful Login After Failures | `203.0.113.45` | Critical | 1 | 1 | 09-28 02:51 |
| 2 | [TRI-0002](#tri-0002) | 🔴 P1 | 95.0 | Brute Force SSH | `203.0.113.45` | High | 26 | 6 | 09-28 02:50 |
| 3 | [TRI-0003](#tri-0003) | 🟠 P2 | 72.9 | Port Scan | `203.0.113.45` | Medium | 6 | 6 | 09-28 02:01 |
| 4 | [TRI-0004](#tri-0004) | 🟡 P3 | 47.9 | Brute Force RDP | `198.51.100.88` | Medium | 3 | 1 | 09-28 04:05 |
| 5 | [TRI-0005](#tri-0005) | 🔵 P4 | 33.6 | TOR Exit Node Connection | `192.0.2.200` | Low | 5 | 1 | 09-28 03:11 |
| 6 | [TRI-0006](#tri-0006) | 🔵 P4 | 20.0 | Port Scan | `198.51.100.23` | Low | 1 | 1 | 09-28 03:30 |
| 7 | [TRI-0007](#tri-0007) | 🔵 P4 | 12.9 | Policy Violation | `10.0.4.17` (int) | Info | 3 | 1 | 09-28 02:58 |

## Tickets

<a id="tri-0001"></a>
### 🔴 P1 · TRI-0001 · Successful Login After Failures from 203.0.113.45

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **93.0** / 100 |
| Max severity | Critical |
| Source IP | `203.0.113.45` (external) |
| Occurrences | 1 alert at 2026-09-28 02:51:01 UTC |
| Hosts | `bastion-01` |
| Users | `deploy` |
| Destination IPs | `10.0.1.10` |
| Sensors | `wazuh-mgr` |
| Related tickets | [TRI-0002](#tri-0002), [TRI-0003](#tri-0003) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +70.0 | highest alert severity is Critical |
| Frequency | +0.0 | 1 alert(s) (single event) |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +8.0 | 'successful_login_after_failures' is a high-impact category |
| Correlation | +15.0 | same source also raised: brute_force_ssh, port_scan |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 02:51:01 | `IDS-0412-00033` | Critical | Accepted password for 'deploy' from 203.0.113.45 port 51122 after 143 failed attempts |

**Recommended first response**

1. Treat as a likely account compromise until proven otherwise.
2. Disable the account / revoke sessions, then contact the user out-of-band.
3. Review post-login activity on the host (processes, new users, persistence).

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0002"></a>
### 🔴 P1 · TRI-0002 · Brute Force SSH from 203.0.113.45

| Field | Value |
| :--- | :--- |
| Priority | **P1 – Critical** (acknowledge within 15 min) |
| Score | **95.0** / 100 |
| Max severity | High |
| Source IP | `203.0.113.45` (external) |
| Occurrences | 26 alerts over 38m 31s (2026-09-28 02:11:42 UTC → 2026-09-28 02:50:13 UTC) |
| Hosts | `bastion-01` |
| Users | `admin`, `deploy`, `git`, `postgres`, `root`, `ubuntu` |
| Destination IPs | `10.0.1.10` |
| Sensors | `wazuh-mgr` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0003](#tri-0003) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +55.0 | highest alert severity is High |
| Frequency | +15.0 | 26 alert(s) over 38m |
| Blast radius | +10.0 | 1 asset(s), 6 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +15.0 | same source also raised: port_scan, successful_login_after_failures |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 02:11:42 | `IDS-0412-00007` | High | sshd: 10 failed password attempts for 'deploy' from 203.0.113.45 within 60s |
| 02:13:21 | `IDS-0412-00008` | High | sshd: 8 failed password attempts for 'deploy' from 203.0.113.45 within 60s |
| 02:15:07 | `IDS-0412-00009` | High | sshd: 11 failed password attempts for 'root' from 203.0.113.45 within 60s |
| 02:16:15 | `IDS-0412-00010` | High | sshd: 10 failed password attempts for 'git' from 203.0.113.45 within 60s |
| 02:50:13 | `IDS-0412-00032` | High | sshd: 10 failed password attempts for 'postgres' from 203.0.113.45 within 60s |

_…and 21 more alert(s) in this incident._

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

<a id="tri-0003"></a>
### 🟠 P2 · TRI-0003 · Port Scan from 203.0.113.45

| Field | Value |
| :--- | :--- |
| Priority | **P2 – High** (acknowledge within 1 h) |
| Score | **72.9** / 100 |
| Max severity | Medium |
| Source IP | `203.0.113.45` (external) |
| Occurrences | 6 alerts over 3m 06s (2026-09-28 01:58:19 UTC → 2026-09-28 02:01:25 UTC) |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.1.10`, `10.0.1.11`, `10.0.1.12`, `10.0.1.13`, `10.0.1.14`, `10.0.1.15` |
| Sensors | `suricata-edge-01` |
| Related tickets | [TRI-0001](#tri-0001), [TRI-0002](#tri-0002) |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +40.0 | highest alert severity is Medium |
| Frequency | +12.9 | 6 alert(s) over 3m |
| Blast radius | +10.0 | 6 asset(s), 0 user(s) |
| Threat category | -5.0 | 'port_scan' is a high-volume, low-fidelity category |
| Correlation | +15.0 | same source also raised: brute_force_ssh, successful_login_after_failures |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 01:58:19 | `IDS-0412-00001` | Medium | ET SCAN Nmap SYN scan detected against 10.0.1.10:22 |
| 01:58:57 | `IDS-0412-00002` | Medium | ET SCAN Nmap SYN scan detected against 10.0.1.11:80 |
| 01:59:31 | `IDS-0412-00003` | Medium | ET SCAN Nmap SYN scan detected against 10.0.1.12:443 |
| 02:00:18 | `IDS-0412-00004` | Medium | ET SCAN Nmap SYN scan detected against 10.0.1.13:3389 |
| 02:01:25 | `IDS-0412-00006` | Medium | ET SCAN Nmap SYN scan detected against 10.0.1.15:5432 |

_…and 1 more alert(s) in this incident._

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

<a id="tri-0004"></a>
### 🟡 P3 · TRI-0004 · Brute Force RDP from 198.51.100.88

| Field | Value |
| :--- | :--- |
| Priority | **P3 – Medium** (acknowledge within 4 h) |
| Score | **47.9** / 100 |
| Max severity | Medium |
| Source IP | `198.51.100.88` (external) |
| Occurrences | 3 alerts over 2m 00s (2026-09-28 04:03:05 UTC → 2026-09-28 04:05:05 UTC) |
| Hosts | `jump-win-02` |
| Users | `Administrator` |
| Destination IPs | `10.0.1.40` |
| Sensors | `windows-evt` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +40.0 | highest alert severity is Medium |
| Frequency | +7.9 | 3 alert(s) over 2m |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | +0.0 | no category adjustment |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 04:03:05 | `IDS-0412-00035` | Medium | EventID 4625: 20+ failed logons for 'Administrator' (LogonType 10) from 198.51.100.88 |
| 04:04:05 | `IDS-0412-00036` | Medium | EventID 4625: 20+ failed logons for 'Administrator' (LogonType 10) from 198.51.100.88 |
| 04:05:05 | `IDS-0412-00037` | Medium | EventID 4625: 20+ failed logons for 'Administrator' (LogonType 10) from 198.51.100.88 |

**Recommended first response**

1. Check Windows Security log (4624/4625) for successful logons from the source IP.
2. Block the source IP; confirm RDP is not exposed to the internet.
3. Reset credentials for any account with a success following failures.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0005"></a>
### 🔵 P4 · TRI-0005 · TOR Exit Node Connection from 192.0.2.200

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **33.6** / 100 |
| Max severity | Low |
| Source IP | `192.0.2.200` (external) |
| Occurrences | 5 alerts over 43m 00s (2026-09-28 02:28:00 UTC → 2026-09-28 03:11:00 UTC) |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.1.11` |
| Sensors | `suricata-edge-01` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +25.0 | highest alert severity is Low |
| Frequency | +11.6 | 5 alert(s) over 43m |
| Blast radius | +0.0 | 1 asset(s), 0 user(s) |
| Threat category | -3.0 | 'tor_exit_node_connection' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 02:28:00 | `IDS-0412-00038` | Low | Inbound connection from known Tor exit node 192.0.2.200 to 10.0.1.11:443 |
| 02:39:00 | `IDS-0412-00039` | Low | Inbound connection from known Tor exit node 192.0.2.200 to 10.0.1.11:443 |
| 02:50:00 | `IDS-0412-00040` | Low | Inbound connection from known Tor exit node 192.0.2.200 to 10.0.1.11:443 |
| 03:01:00 | `IDS-0412-00041` | Low | Inbound connection from known Tor exit node 192.0.2.200 to 10.0.1.11:443 |
| 03:11:00 | `IDS-0412-00042` | Low | Inbound connection from known Tor exit node 192.0.2.200 to 10.0.1.11:443 |

**Recommended first response**

1. Determine if the connection was inbound (scanning/abuse) or outbound (user/implant).
2. Outbound from a server is suspicious - investigate the originating process.

**Analyst checklist**

- [ ] Acknowledged — analyst: ________  time: ________
- [ ] Investigated / scoped
- [ ] Contained or escalated
- [ ] Closed — disposition: ☐ True positive ☐ Benign true positive ☐ False positive

**Notes:**

---

<a id="tri-0006"></a>
### 🔵 P4 · TRI-0006 · Port Scan from 198.51.100.23

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **20.0** / 100 |
| Max severity | Low |
| Source IP | `198.51.100.23` (external) |
| Occurrences | 1 alert at 2026-09-28 03:30:12 UTC |
| Hosts | — |
| Users | — |
| Destination IPs | `10.0.1.12` |
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
| 03:30:12 | `IDS-0412-00034` | Low | ET SCAN Shodan scanner probe on TCP/443 |

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

<a id="tri-0007"></a>
### 🔵 P4 · TRI-0007 · Policy Violation from 10.0.4.17

| Field | Value |
| :--- | :--- |
| Priority | **P4 – Low** (acknowledge within 24 h) |
| Score | **12.9** / 100 |
| Max severity | Info |
| Source IP | `10.0.4.17` (internal) |
| Occurrences | 3 alerts over 14m 00s (2026-09-28 02:44:00 UTC → 2026-09-28 02:58:00 UTC) |
| Hosts | `mktg-lt-114` |
| Users | `p.okafor` |
| Destination IPs | — |
| Sensors | `zscaler` |
| Related tickets | — |

**Why this score**

| Component | Points | Reason |
| :--- | ---: | :--- |
| Severity | +10.0 | highest alert severity is Info |
| Frequency | +7.9 | 3 alert(s) over 14m |
| Blast radius | +0.0 | 1 asset(s), 1 user(s) |
| Threat category | -5.0 | 'policy_violation' is a high-volume, low-fidelity category |
| Correlation | +0.0 | no other activity from this source |

**Evidence**

| Time (UTC) | Alert ID | Sev | Description |
| :--- | :--- | :--- | :--- |
| 02:44:00 | `IDS-0412-00043` | Info | BitTorrent protocol traffic detected (policy: P2P prohibited) |
| 02:51:00 | `IDS-0412-00044` | Info | BitTorrent protocol traffic detected (policy: P2P prohibited) |
| 02:58:00 | `IDS-0412-00045` | Info | BitTorrent protocol traffic detected (policy: P2P prohibited) |

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
