"""
parser.py
Parsing functions for Linux auth logs and Apache/Nginx access logs.
"""

import re
from utils import read_lines

# --- Regex patterns -------------------------------------------------------

# Example auth.log failed password line:
# Jul  6 10:12:03 host sshd[1234]: Failed password for invalid user admin
# from 192.168.1.15 port 51514 ssh2
AUTH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

# Example auth.log successful login lines (password or publickey):
AUTH_SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

AUTH_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)

# Example Apache/Nginx combined log format:
# 10.0.0.8 - - [06/Jul/2026:10:15:00 +0000] "GET /admin HTTP/1.1" 404 512
ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_auth_log(filepath: str):
    """
    Parse a Linux authentication log.

    Returns a list of dicts:
        {"type": "failed"|"success"|"invalid_user", "user": str, "ip": str,
         "timestamp": str, "raw": str}
    """
    events = []
    for line in read_lines(filepath):
        ts_m = AUTH_TIMESTAMP_RE.match(line)
        ts_str = ts_m.group("timestamp") if ts_m else ""

        m = AUTH_FAILED_RE.search(line)
        if m:
            events.append({
                "type": "failed",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "timestamp": ts_str,
                "raw": line,
            })
            continue

        m = AUTH_SUCCESS_RE.search(line)
        if m:
            events.append({
                "type": "success",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "timestamp": ts_str,
                "raw": line,
            })
            continue

        m = INVALID_USER_RE.search(line)
        if m:
            events.append({
                "type": "invalid_user",
                "user": m.group("user"),
                "ip": m.group("ip"),
                "timestamp": ts_str,
                "raw": line,
            })
            continue

    return events


def parse_access_log(filepath: str):
    """
    Parse an Apache/Nginx access log (common or combined log format).

    Returns a list of dicts:
        {"ip": str, "timestamp": str, "method": str, "path": str,
         "status": int, "size": str, "user_agent": str, "raw": str}
    """
    events = []
    for line in read_lines(filepath):
        m = ACCESS_LOG_RE.search(line)
        if m:
            events.append({
                "ip": m.group("ip"),
                "timestamp": m.group("timestamp"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": m.group("size"),
                "user_agent": m.group("user_agent") or "-",
                "raw": line,
            })
    return events

