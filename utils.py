"""
utils.py
Helper functions used across the SOC Log Analyzer project.
"""

import os
import sys
import ipaddress
from datetime import datetime

# ANSI Color Codes for terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"


def init_terminal_colors():
    """Enable ANSI virtual terminal processing on Windows console."""
    if os.name == "nt":
        os.system("")


def colorize(text: str, color: str = "", bold: bool = False, enabled: bool = True) -> str:
    """Wrap text in ANSI escape codes if enabled."""
    if not enabled or not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        # If not enabled or redirected, return plain text unless FORCE_COLOR is set
        if not enabled:
            return text
    prefix = ""
    if bold:
        prefix += BOLD
    if color:
        prefix += color
    return f"{prefix}{text}{RESET}" if prefix else text


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address belongs strictly to RFC 1918 / loopback / link-local."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def get_ip_type(ip_str: str) -> str:
    """Return 'Internal' or 'External' based on RFC 1918 private networking."""
    return "Internal" if is_private_ip(ip_str) else "External"



def ensure_dir(path: str) -> None:
    """Create a directory if it doesn't already exist."""
    os.makedirs(path, exist_ok=True)


def read_lines(filepath: str):
    """Read a log file and return a list of non-empty lines."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def timestamp() -> str:
    """Return a human-readable timestamp for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity_label(level: str) -> str:
    """Normalize severity labels."""
    return level.strip().upper()

