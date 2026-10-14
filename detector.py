"""
detector.py
Detection logic for identifying suspicious activity in parsed log events.
Includes threat detection, risk scoring, and investigation metrics.
"""

from collections import Counter, defaultdict
import re
from utils import is_private_ip, get_ip_type

# --- Default Thresholds (tune as needed or override via CLI) ---------------

DEFAULT_SSH_BRUTE_FORCE_THRESHOLD = 10     # failed logins from one IP
DEFAULT_FAILED_LOGIN_THRESHOLD = 5         # generic failed-login alert
DEFAULT_HTTP_404_THRESHOLD = 20            # repeated 404s from one IP
DEFAULT_HIGH_REQUEST_THRESHOLD = 200       # total requests from one IP
DEFAULT_INVALID_USER_THRESHOLD = 5         # distinct invalid usernames from one IP
DEFAULT_HTTP_5XX_THRESHOLD = 10            # 5xx server errors from one IP

# Known sensitive patterns for web reconnaissance & exploitation detection
SENSITIVE_PATTERNS = [
    # Config & Credential files
    (re.compile(r"/\.(?:env|git|svn|htaccess|htpasswd|aws)", re.IGNORECASE), "Credential / Repository Exposure Probe"),
    (re.compile(r"/(?:wp-config|config|configuration|settings|database)\.(?:php|inc|bak|old|yml|json)", re.IGNORECASE), "Configuration File Probe"),
    # Backups & Archives
    (re.compile(r"/(?:backup|dump|db|export|data|site|archive)\.(?:zip|tar|tar\.gz|tgz|sql|bak|old)", re.IGNORECASE), "Backup / Database Archive Probe"),
    # Admin & Management portals
    (re.compile(r"/(?:phpmyadmin|pma|admin|wp-admin|wp-login\.php|xmlrpc\.php|cpanel|webmin|dashboard)", re.IGNORECASE), "Admin / CMS Portal Scan"),
    # Web shells & Exploit payloads
    (re.compile(r"/(?:shell|cmd|c99|r57|wso|alfa|b374k|eval-stdin)\.php", re.IGNORECASE), "Web Shell / Backdoor Probe"),
    # Directory Traversal / Path Manipulation
    (re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE), "Directory Traversal Attempt"),
    # SQL Injection / Command Injection / XSS signatures
    (re.compile(r"(?:union\s+select|information_schema|<script|/etc/passwd|/bin/sh|cmd\.exe)", re.IGNORECASE), "Web Attack Signature (SQLi/XSS/Command)"),
]


def detect_ssh_brute_force(auth_events, brute_threshold=DEFAULT_SSH_BRUTE_FORCE_THRESHOLD,
                           failed_threshold=DEFAULT_FAILED_LOGIN_THRESHOLD):
    """Detect SSH brute-force attempts: many failed logins from one IP."""
    failed_by_ip = Counter(
        e["ip"] for e in auth_events if e["type"] == "failed"
    )

    alerts = []
    for ip, count in failed_by_ip.items():
        ip_type = get_ip_type(ip)
        if count >= brute_threshold:
            alerts.append({
                "severity": "HIGH",
                "title": "SSH Brute Force Detected",
                "ip": ip,
                "ip_type": ip_type,
                "detail": f"Failed Attempts: {count} (Threshold: {brute_threshold})",
                "count": count,
                "category": "Authentication",
            })
        elif count >= failed_threshold:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Repeated Failed Login Attempts",
                "ip": ip,
                "ip_type": ip_type,
                "detail": f"Failed Attempts: {count} (Threshold: {failed_threshold})",
                "count": count,
                "category": "Authentication",
            })
    return alerts


def detect_invalid_users(auth_events, threshold=DEFAULT_INVALID_USER_THRESHOLD):
    """Detect repeated login attempts using invalid/non-existent usernames."""
    invalid_by_ip = defaultdict(set)
    for e in auth_events:
        if e["type"] in ("invalid_user", "failed"):
            invalid_by_ip[e["ip"]].add(e["user"])

    alerts = []
    for ip, users in invalid_by_ip.items():
        if len(users) >= threshold:
            sample_users = ", ".join(sorted(list(users))[:5])
            if len(users) > 5:
                sample_users += f", ... (+{len(users)-5} more)"
            alerts.append({
                "severity": "MEDIUM",
                "title": "Multiple Invalid Usernames Attempted",
                "ip": ip,
                "ip_type": get_ip_type(ip),
                "detail": f"Distinct Usernames Tried: {len(users)} [{sample_users}]",
                "count": len(users),
                "category": "Reconnaissance",
            })
    return alerts


def detect_root_logins(auth_events):
    """Detect direct SSH logins to the root account (violates security hardening policies)."""
    root_logins = [
        e for e in auth_events
        if e["type"] == "success" and e["user"].lower() == "root"
    ]

    alerts = []
    # Count per IP
    by_ip = Counter(e["ip"] for e in root_logins)
    for ip, count in by_ip.items():
        is_priv = is_private_ip(ip)
        # External root login is HIGH severity; internal is MEDIUM severity
        severity = "HIGH" if not is_priv else "MEDIUM"
        ip_type = get_ip_type(ip)
        alerts.append({
            "severity": severity,
            "title": f"Direct Root SSH Login Accepted ({ip_type})",
            "ip": ip,
            "ip_type": ip_type,
            "detail": f"Successful root logins: {count}. Direct root logins pose privilege escalation risks.",
            "count": count,
            "category": "Privilege Access",
        })
    return alerts


def detect_compromised_accounts(auth_events, min_failures=3):
    """
    Detect potential account compromise: an IP or user that experienced repeated
    authentication failures followed by a successful login.
    """
    failures_by_ip = defaultdict(int)
    failures_by_user = defaultdict(int)
    alerts = []
    reported_pairs = set()

    for e in auth_events:
        ip = e["ip"]
        user = e["user"]
        etype = e["type"]

        if etype in ("failed", "invalid_user"):
            failures_by_ip[ip] += 1
            failures_by_user[user] += 1
        elif etype == "success":
            ip_fails = failures_by_ip.get(ip, 0)
            user_fails = failures_by_user.get(user, 0)

            if (ip_fails >= min_failures or user_fails >= min_failures) and (ip, user) not in reported_pairs:
                reported_pairs.add((ip, user))
                alerts.append({
                    "severity": "CRITICAL",
                    "title": "Potential Account Compromise (Brute Force Followed by Success)",
                    "ip": ip,
                    "ip_type": get_ip_type(ip),
                    "detail": (
                        f"Account '{user}' logged in successfully after {ip_fails} failures from IP {ip} "
                        f"({user_fails} total failures for user). High risk of compromised credential."
                    ),
                    "count": ip_fails,
                    "category": "Compromise",
                })
    return alerts


def detect_web_scanning(access_events, threshold=DEFAULT_HTTP_404_THRESHOLD):
    """Detect web scanning behavior via repeated 404 responses."""
    not_found_by_ip = Counter(
        e["ip"] for e in access_events if e["status"] == 404
    )

    alerts = []
    for ip, count in not_found_by_ip.items():
        if count >= threshold:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Repeated 404 Requests (Web Scanning)",
                "ip": ip,
                "ip_type": get_ip_type(ip),
                "detail": f"404 Not Found Errors: {count} (Threshold: {threshold})",
                "count": count,
                "category": "Web Reconnaissance",
            })
    return alerts


def detect_sensitive_probes(access_events):
    """
    Detect web requests probing for known sensitive endpoints, backups,
    git/env leaks, admin portals, and web shells.
    """
    probes_by_ip = defaultdict(lambda: defaultdict(list))

    for e in access_events:
        path = e.get("path", "")
        ip = e.get("ip", "")
        for pattern, label in SENSITIVE_PATTERNS:
            if pattern.search(path):
                probes_by_ip[ip][label].append(path)

    alerts = []
    for ip, categories in probes_by_ip.items():
        total_probes = sum(len(paths) for paths in categories.values())
        summary_lines = []
        for label, paths in categories.items():
            unique_paths = list(dict.fromkeys(paths))[:3]
            sample = ", ".join(unique_paths)
            if len(set(paths)) > 3:
                sample += f", ... (+{len(set(paths))-3} more)"
            summary_lines.append(f"{label} ({len(paths)}x: {sample})")

        # Escalate severity if webshells, credential files, or multiple categories probed
        has_high_risk = any(k in categories for k in ("Web Shell / Backdoor Probe", "Credential / Repository Exposure Probe"))
        severity = "HIGH" if (has_high_risk or total_probes >= 5) else "MEDIUM"

        alerts.append({
            "severity": severity,
            "title": "Sensitive Path & Vulnerability Probing Detected",
            "ip": ip,
            "ip_type": get_ip_type(ip),
            "detail": f"Probed {total_probes} sensitive endpoint(s):\n  - " + "\n  - ".join(summary_lines),
            "count": total_probes,
            "category": "Web Exploitation",
        })
    return alerts


def detect_high_frequency_ips(access_events, threshold=DEFAULT_HIGH_REQUEST_THRESHOLD):
    """Detect IPs making an unusually high number of requests overall."""
    total_by_ip = Counter(e["ip"] for e in access_events)

    alerts = []
    for ip, count in total_by_ip.items():
        if count >= threshold:
            alerts.append({
                "severity": "LOW",
                "title": "High Request Frequency (Potential DoS / Crawler)",
                "ip": ip,
                "ip_type": get_ip_type(ip),
                "detail": f"Total HTTP Requests: {count} (Threshold: {threshold})",
                "count": count,
                "category": "Volume Anomaly",
            })
    return alerts


def detect_http_error_spikes(access_events, threshold=DEFAULT_HTTP_5XX_THRESHOLD):
    """Detect high numbers of 5xx server errors, indicating server stress or fuzzing."""
    errors_by_ip = Counter(e["ip"] for e in access_events if 500 <= e.get("status", 0) <= 599)

    alerts = []
    for ip, count in errors_by_ip.items():
        if count >= threshold:
            alerts.append({
                "severity": "MEDIUM",
                "title": "HTTP 5xx Server Error Spike",
                "ip": ip,
                "ip_type": get_ip_type(ip),
                "detail": f"5xx Server Errors Triggered: {count} (Threshold: {threshold})",
                "count": count,
                "category": "Application Error",
            })
    return alerts


def calculate_ip_risk_scores(auth_events=None, access_events=None, alerts=None):
    """
    Calculate an analytical Threat Risk Score (0-100) and Threat Category for every observed IP.
    """
    auth_events = auth_events or []
    access_events = access_events or []
    alerts = alerts or []

    # Map of ip -> metrics
    all_ips = set()
    for e in auth_events:
        all_ips.add(e["ip"])
    for e in access_events:
        all_ips.add(e["ip"])

    # Aggregate telemetry per IP
    auth_fails = Counter(e["ip"] for e in auth_events if e["type"] in ("failed", "invalid_user"))
    auth_succs = Counter(e["ip"] for e in auth_events if e["type"] == "success")
    http_404s = Counter(e["ip"] for e in access_events if e.get("status") == 404)
    total_reqs = Counter(e["ip"] for e in access_events)

    alerts_by_ip = defaultdict(list)
    for a in alerts:
        alerts_by_ip[a["ip"]].append(a)

    results = []

    for ip in sorted(all_ips):
        score = 0
        reasons = []

        fails = auth_fails.get(ip, 0)
        succs = auth_succs.get(ip, 0)
        n404 = http_404s.get(ip, 0)
        reqs = total_reqs.get(ip, 0)
        ip_alerts = alerts_by_ip.get(ip, 0)

        # Failure weight
        if fails >= 20:
            score += 35
            reasons.append(f"Severe SSH brute-force ({fails} failures)")
        elif fails >= 10:
            score += 25
            reasons.append(f"SSH brute-force ({fails} failures)")
        elif fails >= 5:
            score += 15
            reasons.append(f"Repeated auth failures ({fails} failures)")
        elif fails > 0:
            score += 5

        # 404 scans
        if n404 >= 40:
            score += 25
            reasons.append(f"Aggressive web scanning ({n404} 404s)")
        elif n404 >= 20:
            score += 15
            reasons.append(f"Web scanning ({n404} 404s)")

        # High request volume
        if reqs >= 300:
            score += 15
            reasons.append(f"High web volume ({reqs} requests)")
        elif reqs >= 150:
            score += 8

        # Alert weights
        for a in alerts_by_ip.get(ip, []):
            sev = a.get("severity", "LOW")
            cat = a.get("category", "")
            if sev == "CRITICAL":
                score += 45
                reasons.append(f"Critical finding: {a['title']}")
            elif sev == "HIGH":
                score += 25
                reasons.append(f"High finding: {a['title']}")
            elif sev == "MEDIUM":
                score += 12
            elif sev == "LOW":
                score += 5

        # Root login weight
        if any("root" in a.get("title", "").lower() for a in alerts_by_ip.get(ip, [])):
            score += 20
            reasons.append("Direct root SSH login")

        # Public IP multiplier for external attacks
        is_priv = is_private_ip(ip)
        if not is_priv and score > 0:
            score = int(score * 1.15)
            reasons.append("External (Public) Source IP")

        # Clamp between 0 and 100
        score = min(max(score, 0), 100)

        if score >= 80:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        elif score >= 10:
            level = "LOW"
        else:
            level = "BENIGN"

        results.append({
            "ip": ip,
            "ip_type": get_ip_type(ip),
            "risk_score": score,
            "threat_level": level,
            "auth_failures": fails,
            "auth_successes": succs,
            "web_404s": n404,
            "total_requests": reqs,
            "alert_count": len(alerts_by_ip.get(ip, [])),
            "reasons": list(dict.fromkeys(reasons)),
        })

    # Sort descending by risk score
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def get_investigation_stats(auth_events=None, access_events=None, alerts=None):
    """Compile overall metrics and top IOC rankings for investigation reporting."""
    auth_events = auth_events or []
    access_events = access_events or []
    alerts = alerts or []

    # Username counts
    targeted_users = Counter(e["user"] for e in auth_events if e.get("user"))

    # Top requested paths & top 404 paths
    all_paths = Counter(e["path"] for e in access_events if e.get("path"))
    not_found_paths = Counter(e["path"] for e in access_events if e.get("status") == 404)

    # Status breakdown
    status_codes = Counter(e["status"] for e in access_events if e.get("status"))

    # Severity counts
    severities = Counter(a.get("severity", "LOW") for a in alerts)

    # Top IP attackers
    attacker_ips = Counter(a["ip"] for a in alerts)

    return {
        "total_auth_events": len(auth_events),
        "total_access_events": len(access_events),
        "total_alerts": len(alerts),
        "severity_breakdown": {
            "CRITICAL": severities.get("CRITICAL", 0),
            "HIGH": severities.get("HIGH", 0),
            "MEDIUM": severities.get("MEDIUM", 0),
            "LOW": severities.get("LOW", 0),
        },
        "top_targeted_users": targeted_users.most_common(5),
        "top_attack_ips": attacker_ips.most_common(5),
        "top_requested_paths": all_paths.most_common(5),
        "top_404_paths": not_found_paths.most_common(5),
        "status_code_distribution": dict(status_codes.most_common()),
    }


def run_all_detections(auth_events=None, access_events=None, config=None):
    """
    Run all detection rules with optional threshold overrides and return sorted alerts.
    """
    config = config or {}
    ssh_thresh = config.get("ssh_threshold", DEFAULT_SSH_BRUTE_FORCE_THRESHOLD)
    failed_thresh = config.get("failed_threshold", DEFAULT_FAILED_LOGIN_THRESHOLD)
    scan_thresh = config.get("scan_threshold", DEFAULT_HTTP_404_THRESHOLD)
    req_thresh = config.get("req_threshold", DEFAULT_HIGH_REQUEST_THRESHOLD)
    invalid_thresh = config.get("invalid_user_threshold", DEFAULT_INVALID_USER_THRESHOLD)

    alerts = []

    if auth_events:
        alerts.extend(detect_compromised_accounts(auth_events))
        alerts.extend(detect_ssh_brute_force(auth_events, brute_threshold=ssh_thresh, failed_threshold=failed_thresh))
        alerts.extend(detect_invalid_users(auth_events, threshold=invalid_thresh))
        alerts.extend(detect_root_logins(auth_events))

    if access_events:
        alerts.extend(detect_sensitive_probes(access_events))
        alerts.extend(detect_web_scanning(access_events, threshold=scan_thresh))
        alerts.extend(detect_high_frequency_ips(access_events, threshold=req_thresh))
        alerts.extend(detect_http_error_spikes(access_events))

    # Sort so CRITICAL and HIGH severity alerts show first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: order.get(a.get("severity", "LOW"), 4))
    return alerts

