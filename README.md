# SOC Log Analyzer (Python)

> ⚠️ **Educational Purpose**
>
> This project is a Python-based SOC (Security Operations Center) log analyzer developed for educational purposes. It analyzes Linux authentication logs and web server logs to identify common security events such as brute-force attacks, repeated login failures, suspicious IP activity, and web scanning attempts.

---

## Overview

SOC analysts spend much of their time reviewing logs to detect malicious activity. This project automates the analysis of Linux and web server log files by identifying common Indicators of Compromise (IOCs) and generating a simple security report.

The project demonstrates fundamental blue-team skills including log analysis, event correlation, threat detection, and incident reporting.

---

## Features

- **Multi-Log Ingestion**: Analyze Linux authentication logs (`auth.log`, `secure`) and Apache/Nginx web server access logs.
- **SSH Brute-Force & Credential Attack Detection**: Detect high-volume failed authentication attempts, brute-force attacks, and invalid username enumeration.
- **Privilege Access & Compromise Detection**: Identify direct root SSH logins and detect potential account compromise (brute-force failure bursts followed by accepted logins).
- **Web Reconnaissance & Sensitive File Probing**: Detect scans targeting environment files (`.env`), repositories (`.git`), configuration files, backup archives (`.zip`, `.sql`), webshells (`shell.php`), and CMS portals.
- **Threat Risk Scoring Engine (0-100)**: Automatically compute analytical risk scores, classify internal vs external IPs (RFC 1918), and assign threat categories (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`).
- **Investigation Telemetry**: Top targeted usernames, top probed web endpoints, HTTP status code distribution, and attacker rankings.
- **Rich Terminal UI**: Vibrant ANSI color formatting, status tables, and severity badges with Windows virtual terminal support.
- **Multi-Format Exporting**:
  - Plain Text Summary (`--out reports/report.txt`)
  - Structured JSON (`--json reports/report.json`)
  - Spreadsheet-ready CSV (`--csv reports/report.csv`)
  - Interactive HTML Dashboard (`--html reports/dashboard.html`)
  - All formats at once (`--all-reports`)
- **Configurable CLI Parameters**: Override detection thresholds (`--ssh-threshold`, `--scan-threshold`, `--req-threshold`) and filter by minimum severity (`--min-severity HIGH`).

---

## Project Structure

```text
SOC-Log-Analyzer/
│
├── analyzer.py          # Main CLI and orchestration entry point
├── parser.py            # Log parsing regex and event extractors
├── detector.py          # Detection rules, risk scoring engine, and metrics
├── report.py            # Terminal, Text, JSON, CSV, and HTML dashboard exporters
├── utils.py             # Colors, RFC 1918 classification, and file helpers
│
├── logs/                # Sample log files
│   ├── auth.log
│   ├── access.log
│   └── nginx.log
│
├── reports/             # Generated reports (TXT, JSON, CSV, HTML)
│   ├── report.txt
│   ├── report.json
│   ├── report.csv
│   └── dashboard.html
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Requirements

- Python 3.10+ (Standard library only; zero external pip dependencies needed)
- Windows, Linux, or macOS

Install dependencies (optional):

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Analyze Linux auth log only
python analyzer.py --auth logs/auth.log

# Analyze web access log only
python analyzer.py --access logs/access.log

# Analyze both auth and web access logs
python analyzer.py --auth logs/auth.log --access logs/access.log

# Generate all report formats (TXT, JSON, CSV, HTML Dashboard)
python analyzer.py --auth logs/auth.log --access logs/access.log --all-reports

# Export an interactive HTML dashboard
python analyzer.py --auth logs/auth.log --access logs/access.log --html reports/dashboard.html

# Export structured JSON and CSV
python analyzer.py --auth logs/auth.log --json reports/report.json --csv reports/report.csv

# Filter for HIGH and CRITICAL alerts only
python analyzer.py --auth logs/auth.log --access logs/access.log --min-severity HIGH

# Customize detection thresholds
python analyzer.py --auth logs/auth.log --ssh-threshold 5 --scan-threshold 10

# Disable terminal colors or skip saving text file
python analyzer.py --auth logs/auth.log --no-color --no-save
```


---

## Supported Log Types

### Linux Authentication Logs

Examples:

- `/var/log/auth.log`
- `/var/log/secure`

Detects:

- Failed SSH logins
- Successful logins
- Invalid usernames
- Brute-force attempts

---

### Web Server Logs

Supported:

- Apache Access Log
- Nginx Access Log

Detects:

- Repeated HTTP 404 errors
- Directory scanning
- Suspicious requests
- High request frequency from a single IP

---

## Detection Rules

### SSH Brute Force

Triggers when multiple failed login attempts are detected from the same IP address.

---

### Failed Login Detection

Counts authentication failures and identifies suspicious login activity.

---

### Web Scanning

Detects repeated requests for non-existent pages (404 errors), which may indicate automated scanning.

---

### Suspicious IP Detection

Highlights IP addresses responsible for a high number of authentication failures or web requests.

---

## Example Output

```text
==========================================
SOC Log Analyzer
==========================================

[HIGH]

SSH Brute Force Detected

IP Address:
192.168.1.15

Failed Attempts:
27

------------------------------------------

[MEDIUM]

Repeated 404 Requests

IP Address:
10.0.0.8

404 Errors:
41

------------------------------------------

Summary

High Alerts   : 1

Medium Alerts : 1

Low Alerts    : 0

Report saved to:

reports/report.txt
```

---

## Workflow

```text
Log File

↓

Parse Log Entries

↓

Extract Relevant Fields

↓

Apply Detection Rules

↓

Generate Alerts

↓

Display Results

↓

Save Report
```

---

## Technologies Used

- Python
- Regular Expressions (Regex)
- Collections
- Datetime
- File Handling

---

## Learning Objectives

This project helped me understand:

- Security Operations Center (SOC) workflows
- Linux authentication logs
- Apache and Nginx log formats
- Event correlation
- Threat detection
- Incident reporting
- Log parsing using Python

---

## Future Improvements

- Windows Event Log support
- JSON report export
- CSV report export
- Email alerts
- Risk scoring
- Command-line arguments
- Live log monitoring
- YARA rule integration

---

## Sample Log Sources

The project can analyze logs from:

- Linux `/var/log/auth.log`
- Apache `access.log`
- Nginx `access.log`
- Public sample log datasets

---

## Disclaimer

This project is intended for educational purposes only. It is designed to help students learn security log analysis and SOC workflows. Use only log files that you own or are authorized to analyze.

---

## Contributors

- **Apoorva Srivastava** ([@Apoorva921](https://github.com/Apoorva921)) - Lead Developer & Maintainer

---

## License

This project is licensed under the MIT License.

