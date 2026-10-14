"""
analyzer.py
Main entry point for the SOC Log Analyzer.

Usage:
    python analyzer.py --auth logs/auth.log --access logs/access.log
    python analyzer.py --auth logs/auth.log --access logs/access.log --html reports/dashboard.html
    python analyzer.py --auth logs/auth.log --all-reports
    python analyzer.py --access logs/nginx.log --json reports/nginx.json --csv reports/nginx.csv
"""

import argparse
import sys
import os

from parser import parse_auth_log, parse_access_log
from detector import (
    run_all_detections,
    calculate_ip_risk_scores,
    get_investigation_stats,
    DEFAULT_SSH_BRUTE_FORCE_THRESHOLD,
    DEFAULT_HTTP_404_THRESHOLD,
    DEFAULT_HIGH_REQUEST_THRESHOLD,
)
from report import (
    print_report,
    save_report,
    save_json_report,
    save_csv_report,
    save_html_report,
)
from utils import init_terminal_colors


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="SOC Log Analyzer - detect brute force, sensitive probes, "
                    "web attacks, and suspicious IP activity in log files."
    )
    p.add_argument("--auth", help="Path to a Linux auth.log / secure log file")
    p.add_argument("--access", help="Path to an Apache/Nginx access log file")
    p.add_argument(
        "--out", default="reports/report.txt",
        help="Path to save the generated text report (default: reports/report.txt)"
    )
    p.add_argument(
        "--json", nargs="?", const="reports/report.json", default=None,
        help="Export results to a structured JSON file (default if flag passed: reports/report.json)"
    )
    p.add_argument(
        "--csv", nargs="?", const="reports/report.csv", default=None,
        help="Export alerts to CSV file (default if flag passed: reports/report.csv)"
    )
    p.add_argument(
        "--html", nargs="?", const="reports/dashboard.html", default=None,
        help="Generate an interactive SOC Analyst HTML dashboard (default: reports/dashboard.html)"
    )
    p.add_argument(
        "--all-reports", action="store_true",
        help="Generate Text, JSON, CSV, and HTML reports simultaneously in the reports/ directory"
    )
    p.add_argument(
        "--no-save", action="store_true",
        help="Only print the report to the terminal; don't save a file"
    )
    p.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color codes in terminal output"
    )
    p.add_argument(
        "--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
        help="Filter displayed and exported alerts by minimum severity"
    )
    # Threshold overrides
    p.add_argument(
        "--ssh-threshold", type=int, default=DEFAULT_SSH_BRUTE_FORCE_THRESHOLD,
        help=f"Failed SSH login threshold for brute force alert (default: {DEFAULT_SSH_BRUTE_FORCE_THRESHOLD})"
    )
    p.add_argument(
        "--scan-threshold", type=int, default=DEFAULT_HTTP_404_THRESHOLD,
        help=f"HTTP 404 count threshold for web scanning alert (default: {DEFAULT_HTTP_404_THRESHOLD})"
    )
    p.add_argument(
        "--req-threshold", type=int, default=DEFAULT_HIGH_REQUEST_THRESHOLD,
        help=f"Request volume threshold for high-frequency alert (default: {DEFAULT_HIGH_REQUEST_THRESHOLD})"
    )
    return p


def main():
    init_terminal_colors()
    args = build_arg_parser().parse_args()

    if not args.auth and not args.access:
        print("Error: provide at least one of --auth or --access")
        sys.exit(1)

    auth_events = []
    access_events = []
    sources = []

    if args.auth:
        try:
            auth_events = parse_auth_log(args.auth)
            sources.append(args.auth)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    if args.access:
        try:
            access_events = parse_access_log(args.access)
            sources.append(args.access)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    config = {
        "ssh_threshold": args.ssh_threshold,
        "scan_threshold": args.scan_threshold,
        "req_threshold": args.req_threshold,
    }

    # Run detection suite
    raw_alerts = run_all_detections(
        auth_events=auth_events,
        access_events=access_events,
        config=config,
    )

    # Compute risk scoring matrix and overall investigation statistics
    risk_scores = calculate_ip_risk_scores(
        auth_events=auth_events,
        access_events=access_events,
        alerts=raw_alerts,
    )
    stats = get_investigation_stats(
        auth_events=auth_events,
        access_events=access_events,
        alerts=raw_alerts,
    )

    # Filter alerts if --min-severity is requested
    sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    if args.min_severity:
        min_rank = sev_rank.get(args.min_severity, 0)
        alerts = [a for a in raw_alerts if sev_rank.get(a.get("severity", "LOW"), 0) >= min_rank]
    else:
        alerts = raw_alerts

    # Print terminal report
    print_report(
        alerts,
        source_files=sources,
        risk_scores=risk_scores,
        stats=stats,
        use_color=not args.no_color,
    )

    # Save reports
    saved_files = []

    # Text report
    if not args.no_save:
        txt_path = save_report(
            alerts,
            output_path=args.out,
            source_files=sources,
            risk_scores=risk_scores,
            stats=stats,
        )
        saved_files.append(f"  [Text Report]  : {txt_path}")

    # Handle --all-reports shortcut
    json_path = args.json or ("reports/report.json" if args.all_reports else None)
    csv_path = args.csv or ("reports/report.csv" if args.all_reports else None)
    html_path = args.html or ("reports/dashboard.html" if args.all_reports else None)

    # JSON export
    if json_path:
        out = save_json_report(
            alerts,
            output_path=json_path,
            source_files=sources,
            risk_scores=risk_scores,
            stats=stats,
        )
        saved_files.append(f"  [JSON Export]  : {out}")

    # CSV export
    if csv_path:
        out = save_csv_report(alerts, output_path=csv_path)
        saved_files.append(f"  [CSV Export]   : {out}")

    # HTML dashboard
    if html_path:
        out = save_html_report(
            alerts,
            risk_scores=risk_scores,
            stats=stats,
            output_path=html_path,
            source_files=sources,
        )
        saved_files.append(f"  [HTML Dashboard]: {out}")

    if saved_files and not args.no_save:
        print("\nGenerated Reports:")
        for sf in saved_files:
            print(sf)


if __name__ == "__main__":
    main()

