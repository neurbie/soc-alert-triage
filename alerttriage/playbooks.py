"""First-response playbook steps per alert type.

These are the "what do I do first" steps printed on each ticket. They are
intentionally short; a real SOC would link out to full runbooks. Keys are
normalized alert types (see ``ingest.normalize_alert_type``).
"""

from __future__ import annotations

PLAYBOOKS: dict[str, list[str]] = {
    "brute_force_ssh": [
        "Check auth logs on targeted hosts for any *successful* login from the source IP.",
        "Block the source IP at the perimeter firewall if it is external.",
        "Confirm targeted accounts have MFA / key-only auth; lock any that were guessed.",
    ],
    "brute_force_rdp": [
        "Check Windows Security log (4624/4625) for successful logons from the source IP.",
        "Block the source IP; confirm RDP is not exposed to the internet.",
        "Reset credentials for any account with a success following failures.",
    ],
    "successful_login_after_failures": [
        "Treat as a likely account compromise until proven otherwise.",
        "Disable the account / revoke sessions, then contact the user out-of-band.",
        "Review post-login activity on the host (processes, new users, persistence).",
    ],
    "port_scan": [
        "Confirm whether the source is an authorized scanner (vuln mgmt, pentest window).",
        "If unknown and external, add to blocklist and watch for follow-on exploitation.",
        "Note which open services were discovered; check them for unpatched CVEs.",
    ],
    "phishing_email": [
        "Pull the message from all mailboxes (search by sender / subject / hash).",
        "Check proxy and email logs for recipients who clicked or opened attachments.",
        "Block sender domain and any embedded URLs; submit IOCs to threat intel.",
    ],
    "malware_detected": [
        "Isolate the host via EDR if the detection was not auto-remediated.",
        "Retrieve the file hash and check prevalence across the fleet.",
        "Identify the infection vector (email, download, USB) and scope other victims.",
    ],
    "c2_beacon": [
        "Isolate the internal host immediately; beaconing implies an active implant.",
        "Block the C2 destination at DNS and proxy; hunt for other hosts contacting it.",
        "Capture memory before reimaging if forensics are required.",
    ],
    "data_exfiltration": [
        "Engage incident response lead - potential breach notification event.",
        "Block the destination and isolate the source host.",
        "Quantify what left: volume, file names, data classification.",
    ],
    "dns_tunneling": [
        "Inspect the queried domain (length/entropy of subdomains, registration age).",
        "Sinkhole or block the domain; isolate the querying host.",
        "Hunt for the process generating the queries on the endpoint.",
    ],
    "sql_injection": [
        "Check web server responses: did any injected request return 200 with data?",
        "Review database logs for unexpected queries in the same window.",
        "Block source at WAF; file a ticket with the app owner to fix the input handling.",
    ],
    "web_shell_upload": [
        "Locate and quarantine the uploaded file on the web server.",
        "Review web server access logs for requests to the uploaded path.",
        "Treat the server as compromised; check for lateral movement from it.",
    ],
    "privilege_escalation": [
        "Identify the account and process that gained elevated rights.",
        "Verify against change tickets; revoke if unauthorized.",
        "Review activity performed with the elevated privileges.",
    ],
    "impossible_travel": [
        "Confirm with the user whether both logins are theirs (VPN, travel).",
        "If not, revoke sessions and force a password reset with MFA re-enrollment.",
        "Review mailbox rules and OAuth grants created during the suspicious session.",
    ],
    "policy_violation": [
        "Verify the activity against acceptable-use policy.",
        "Notify the user's manager or IT per policy if confirmed.",
    ],
    "tor_exit_node_connection": [
        "Determine if the connection was inbound (scanning/abuse) or outbound (user/implant).",
        "Outbound from a server is suspicious - investigate the originating process.",
    ],
}

DEFAULT_PLAYBOOK: list[str] = [
    "Validate the alert against raw logs to rule out a false positive.",
    "Determine scope: other hosts, users or IPs involved.",
    "Contain if malicious, then escalate per the IR plan.",
]


def playbook_for(alert_type: str) -> list[str]:
    return PLAYBOOKS.get(alert_type, DEFAULT_PLAYBOOK)
