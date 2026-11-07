PROCESSES = {
    "ir": {
        "name": "Incident Response (Ransomware)",
        "steps": [
            ("ir1", "Confirm the incident and open a case ticket"),
            ("ir2", "Isolate affected hosts from the network"),
            ("ir3", "Preserve logs and take forensic disk images"),
            ("ir4", "Reset compromised credentials and revoke sessions"),
            ("ir5", "Remove malware and close the attacker's access"),
            ("ir6", "Restore from clean backups and verify integrity"),
            ("ir7", "Write the post-incident report"),
        ],
    },
    "phish": {
        "name": "Phishing Report Triage",
        "steps": [
            ("ph1", "Pull the reported email with full headers"),
            ("ph2", "Detonate links and attachments in a sandbox"),
            ("ph3", "Block sender domain and malicious URLs"),
            ("ph4", "Search mailboxes and purge copies of the email"),
            ("ph5", "Reset passwords for anyone who clicked"),
        ],
    },
    "patch": {
        "name": "Monthly Patch & Vulnerability Check",
        "steps": [
            ("pv1", "Run authenticated vulnerability scan"),
            ("pv2", "Triage critical/high findings (CVSS 7+)"),
            ("pv3", "Apply patches to the test group and verify"),
            ("pv4", "Roll out patches to production"),
            ("pv5", "Re-scan and confirm findings are closed"),
        ],
    },
    "access": {
        "name": "Access Review & Offboarding",
        "steps": [
            ("ac1", "Disable the user's accounts and SSO sessions"),
            ("ac2", "Revoke VPN, API keys and SSH keys"),
            ("ac3", "Rotate shared secrets the user knew"),
            ("ac4", "Collect laptop and tokens, and wipe devices"),
            ("ac5", "Review privileged-group membership"),
        ],
    },
}
STEP_NAMES = {sid: n for p in PROCESSES.values() for sid, n in p["steps"]}
