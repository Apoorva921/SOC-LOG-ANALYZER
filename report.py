"""
report.py
Generates terminal-friendly, text, JSON, CSV, and interactive HTML security reports from alerts.
"""

import os
import json
import csv
import html
from utils import (
    timestamp, ensure_dir, colorize,
    RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, BOLD, DIM
)

BANNER = "=" * 60
DIVIDER = "-" * 60


def get_severity_color(severity: str):
    sev = severity.upper()
    if sev == "CRITICAL":
        return RED
    elif sev == "HIGH":
        return RED
    elif sev == "MEDIUM":
        return YELLOW
    elif sev == "LOW":
        return CYAN
    return WHITE


def format_alert(alert: dict, use_color: bool = False) -> str:
    sev = alert.get("severity", "LOW")
    ip_type = alert.get("ip_type", "")
    ip_type_str = f" ({ip_type})" if ip_type else ""
    category = alert.get("category", "")
    cat_str = f" [{category}]" if category else ""

    if use_color:
        sev_color = get_severity_color(sev)
        sev_badge = colorize(f"[{sev}]", color=sev_color, bold=True)
        title_str = colorize(alert["title"] + cat_str, bold=True)
        ip_label = colorize("IP Address:", color=CYAN, bold=True)
        ip_val = colorize(alert["ip"] + ip_type_str, bold=True)
        detail_val = alert["detail"]
    else:
        sev_badge = f"[{sev}]"
        title_str = alert["title"] + cat_str
        ip_label = "IP Address:"
        ip_val = alert["ip"] + ip_type_str
        detail_val = alert["detail"]

    lines = [
        "",
        f"{sev_badge} {title_str}",
        f"{ip_label} {ip_val}",
        f"Details: {detail_val}",
        DIVIDER,
    ]
    return "\n".join(lines)


def build_report_text(alerts, source_files=None, risk_scores=None, stats=None) -> str:
    lines = [
        BANNER,
        "                   SOC LOG ANALYZER REPORT",
        BANNER,
        "",
        f"Generated : {timestamp()}",
    ]

    if source_files:
        lines.append("Sources   : " + ", ".join(source_files))

    # Threat Matrix / IP Risk Section
    if risk_scores:
        high_risk = [r for r in risk_scores if r.get("risk_score", 0) >= 10]
        if high_risk:
            lines.extend([
                "",
                "IP THREAT MATRIX (RISK SCORING)",
                DIVIDER,
                f"{'IP Address':<18} {'Type':<10} {'Score':<8} {'Level':<10} {'Indicators / Activity'}",
                "-" * 60,
            ])
            for r in high_risk[:10]:
                reasons_str = "; ".join(r.get("reasons", [])) or "None"
                lines.append(
                    f"{r['ip']:<18} {r.get('ip_type',''):<10} {r['risk_score']:<8} "
                    f"{r.get('threat_level',''):<10} {reasons_str}"
                )

    lines.extend([
        "",
        "SECURITY INCIDENTS & DETECTIONS",
        DIVIDER,
    ])

    if not alerts:
        lines.append("")
        lines.append("No suspicious activity or threats detected.")
    else:
        for alert in alerts:
            lines.append(format_alert(alert, use_color=False))

    # Top targeted users and top 404 paths
    if stats:
        if stats.get("top_targeted_users"):
            lines.extend([
                "",
                "Top Targeted Users:",
                ", ".join(f"{u} ({c}x)" for u, c in stats["top_targeted_users"]),
            ])
        if stats.get("top_404_paths"):
            lines.extend([
                "",
                "Top 404 / Probed Endpoints:",
                ", ".join(f"{p} ({c}x)" for p, c in stats["top_404_paths"]),
            ])

    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low = sum(1 for a in alerts if a.get("severity") == "LOW")

    lines += [
        "",
        "INVESTIGATION SUMMARY",
        DIVIDER,
        f"Critical Alerts : {critical}",
        f"High Alerts     : {high}",
        f"Medium Alerts   : {medium}",
        f"Low Alerts      : {low}",
        f"Total Alerts    : {len(alerts)}",
        DIVIDER,
    ]

    return "\n".join(lines)


def print_report(alerts, source_files=None, risk_scores=None, stats=None, use_color=True) -> None:
    banner_text = colorize(BANNER, color=CYAN, bold=True, enabled=use_color)
    title_text = colorize("                   SOC LOG ANALYZER REPORT", color=WHITE, bold=True, enabled=use_color)
    print(banner_text)
    print(title_text)
    print(banner_text)
    print(colorize(f"Generated : {timestamp()}", color=WHITE, enabled=use_color))
    if source_files:
        print(colorize("Sources   : " + ", ".join(source_files), color=WHITE, enabled=use_color))

    # IP Threat Matrix
    if risk_scores:
        high_risk = [r for r in risk_scores if r.get("risk_score", 0) >= 10]
        if high_risk:
            print("")
            print(colorize("IP THREAT MATRIX (RISK SCORING)", color=YELLOW, bold=True, enabled=use_color))
            print(DIVIDER)
            hdr = f"{'IP Address':<18} {'Type':<10} {'Score':<8} {'Level':<10} {'Indicators / Activity'}"
            print(colorize(hdr, bold=True, enabled=use_color))
            print("-" * 60)
            for r in high_risk[:10]:
                reasons_str = "; ".join(r.get("reasons", [])) or "None"
                lvl = r.get("threat_level", "LOW")
                lvl_colored = colorize(f"{lvl:<10}", color=get_severity_color(lvl), bold=True, enabled=use_color)
                ip_colored = colorize(f"{r['ip']:<18}", bold=True, enabled=use_color)
                print(f"{ip_colored} {r.get('ip_type',''):<10} {r['risk_score']:<8} {lvl_colored} {reasons_str}")

    print("")
    print(colorize("SECURITY INCIDENTS & DETECTIONS", color=YELLOW, bold=True, enabled=use_color))
    print(DIVIDER)

    if not alerts:
        print("")
        print(colorize("No suspicious activity or threats detected.", color=GREEN, enabled=use_color))
    else:
        for alert in alerts:
            print(format_alert(alert, use_color=use_color))

    if stats:
        if stats.get("top_targeted_users"):
            print("")
            print(colorize("Top Targeted Users: ", color=CYAN, bold=True, enabled=use_color) +
                  ", ".join(f"{u} ({c}x)" for u, c in stats["top_targeted_users"]))
        if stats.get("top_404_paths"):
            print(colorize("Top 404 / Probed Endpoints: ", color=CYAN, bold=True, enabled=use_color) +
                  ", ".join(f"{p} ({c}x)" for p, c in stats["top_404_paths"]))

    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low = sum(1 for a in alerts if a.get("severity") == "LOW")

    print("")
    print(colorize("INVESTIGATION SUMMARY", color=YELLOW, bold=True, enabled=use_color))
    print(DIVIDER)
    if critical > 0:
        print(colorize(f"Critical Alerts : {critical}", color=RED, bold=True, enabled=use_color))
    else:
        print(f"Critical Alerts : {critical}")
    print(colorize(f"High Alerts     : {high}", color=RED if high else WHITE, enabled=use_color))
    print(colorize(f"Medium Alerts   : {medium}", color=YELLOW if medium else WHITE, enabled=use_color))
    print(colorize(f"Low Alerts      : {low}", color=CYAN if low else WHITE, enabled=use_color))
    print(colorize(f"Total Alerts    : {len(alerts)}", bold=True, enabled=use_color))
    print(DIVIDER)


def save_report(alerts, output_path="reports/report.txt", source_files=None, risk_scores=None, stats=None) -> str:
    """Save plain text report."""
    ensure_dir(os.path.dirname(output_path) or ".")
    text = build_report_text(alerts, source_files=source_files, risk_scores=risk_scores, stats=stats)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)
    return output_path


def save_json_report(alerts, output_path="reports/report.json", source_files=None, risk_scores=None, stats=None) -> str:
    """Export complete analysis data in structured JSON format."""
    ensure_dir(os.path.dirname(output_path) or ".")
    data = {
        "report_metadata": {
            "title": "SOC Log Analyzer Report",
            "generated_at": timestamp(),
            "sources": source_files or [],
        },
        "investigation_stats": stats or {},
        "ip_threat_matrix": risk_scores or [],
        "alerts": alerts,
        "summary": {
            "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
            "high": sum(1 for a in alerts if a.get("severity") == "HIGH"),
            "medium": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
            "low": sum(1 for a in alerts if a.get("severity") == "LOW"),
            "total": len(alerts),
        }
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path


def save_csv_report(alerts, output_path="reports/report.csv") -> str:
    """Export alerts to standard CSV format."""
    ensure_dir(os.path.dirname(output_path) or ".")
    headers = ["Severity", "Category", "Title", "IP", "IP_Type", "Detail", "Count"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for a in alerts:
            writer.writerow([
                a.get("severity", "LOW"),
                a.get("category", "General"),
                a.get("title", ""),
                a.get("ip", ""),
                a.get("ip_type", ""),
                a.get("detail", "").replace("\n", " "),
                a.get("count", 1),
            ])
    return output_path


def save_html_report(alerts, risk_scores=None, stats=None, output_path="reports/report.html", source_files=None) -> str:
    """Generate a sleek, modern, interactive SOC Analyst HTML dashboard report."""
    ensure_dir(os.path.dirname(output_path) or ".")
    risk_scores = risk_scores or []
    stats = stats or {}
    source_str = html.escape(", ".join(source_files or ["N/A"]))

    critical_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")
    med_count = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low_count = sum(1 for a in alerts if a.get("severity") == "LOW")
    total_alerts = len(alerts)

    # Render IP threat rows
    threat_rows = []
    for r in risk_scores:
        if r.get("risk_score", 0) <= 0:
            continue
        lvl = r.get("threat_level", "LOW")
        score = r.get("risk_score", 0)
        reasons = html.escape("; ".join(r.get("reasons", [])))
        badge_cls = f"badge-{lvl.lower()}"
        bar_color = "#ef4444" if score >= 80 else "#f97316" if score >= 50 else "#eab308" if score >= 25 else "#06b6d4"
        threat_rows.append(f"""
        <tr>
            <td class="font-mono font-bold text-white">{html.escape(r['ip'])}</td>
            <td><span class="badge badge-outline">{html.escape(r.get('ip_type',''))}</span></td>
            <td>
                <div class="score-container">
                    <div class="score-bar" style="width: {score}%; background: {bar_color}"></div>
                    <span class="score-num font-mono">{score}</span>
                </div>
            </td>
            <td><span class="badge {badge_cls}">{lvl}</span></td>
            <td class="text-muted text-sm">{reasons}</td>
        </tr>
        """)
    threat_table_body = "".join(threat_rows) if threat_rows else "<tr><td colspan='5' class='text-center text-muted'>No elevated risk IPs detected</td></tr>"

    # Render Alerts cards
    alert_cards = []
    for idx, a in enumerate(alerts):
        sev = a.get("severity", "LOW")
        badge_cls = f"badge-{sev.lower()}"
        ip_val = html.escape(a.get("ip", "N/A"))
        ip_type = html.escape(a.get("ip_type", "Unknown"))
        cat = html.escape(a.get("category", "General Security"))
        title = html.escape(a.get("title", "Security Finding"))
        detail = html.escape(a.get("detail", "")).replace("\n", "<br>")

        alert_cards.append(f"""
        <div class="alert-card filter-{sev.lower()}" data-severity="{sev.lower()}" data-ip="{ip_val.lower()}" data-title="{title.lower()}">
            <div class="alert-header">
                <div class="alert-title-wrap">
                    <span class="badge {badge_cls}">{sev}</span>
                    <span class="badge badge-cat">{cat}</span>
                    <h3 class="alert-title">{title}</h3>
                </div>
                <div class="alert-ip-pill">
                    <span class="ip-label">Target/Source:</span>
                    <code class="font-mono text-cyan">{ip_val}</code>
                    <span class="ip-type-badge">({ip_type})</span>
                </div>
            </div>
            <div class="alert-body">
                <div class="detail-box">{detail}</div>
            </div>
        </div>
        """)
    alert_cards_html = "".join(alert_cards) if alert_cards else "<p class='text-muted'>No alerts triggered.</p>"

    # Top users
    top_users_html = "".join(
        f"<li class='metric-list-item'><span class='font-mono text-white'>{html.escape(u)}</span><span class='badge badge-neutral'>{c} attempts</span></li>"
        for u, c in stats.get("top_targeted_users", [])
    ) or "<li class='text-muted'>None</li>"

    # Top 404
    top_404_html = "".join(
        f"<li class='metric-list-item'><code class='font-mono text-amber'>{html.escape(p)}</code><span class='badge badge-neutral'>{c}x</span></li>"
        for p, c in stats.get("top_404_paths", [])
    ) or "<li class='text-muted'>None</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Security Investigation Dashboard</title>
    <style>
        :root {{
            --bg-base: #0b0f19;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --bg-card-hover: #263346;
            --border: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-base);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title {{ font-size: 1.75rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 12px; }}
        .pulse-badge {{
            background: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
            padding: 4px 10px;
            font-size: 0.75rem;
            border-radius: 9999px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .header-meta {{ color: var(--text-muted); font-size: 0.875rem; text-align: right; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .kpi-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .kpi-label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        .kpi-value {{ font-size: 2.2rem; font-weight: 800; }}
        .text-red {{ color: var(--accent-red); }}
        .text-amber {{ color: var(--accent-amber); }}
        .text-cyan {{ color: var(--accent-cyan); }}
        .text-green {{ color: var(--accent-green); }}
        .section-title {{
            font-size: 1.25rem;
            font-weight: 700;
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .threat-table-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 28px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #1a2234;
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #1f2937;
            font-size: 0.9rem;
            vertical-align: middle;
        }}
        tr:hover td {{ background: var(--bg-card-hover); }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .score-container {{
            width: 140px;
            background: #1f2937;
            height: 18px;
            border-radius: 9999px;
            overflow: hidden;
            position: relative;
            display: flex;
            align-items: center;
        }}
        .score-bar {{ height: 100%; border-radius: 9999px; }}
        .score-num {{
            position: absolute;
            right: 8px;
            font-size: 0.7rem;
            font-weight: 700;
            color: #fff;
            text-shadow: 0 1px 2px rgba(0,0,0,0.8);
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-low {{ background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }}
        .badge-cat {{ background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.4); }}
        .badge-outline {{ border: 1px solid var(--border); color: var(--text-muted); }}
        .badge-neutral {{ background: #374151; color: #e5e7eb; }}
        .insight-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }}
        .insight-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .insight-card h4 {{ margin-bottom: 12px; font-size: 1rem; color: #fff; }}
        .metric-list {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
        .metric-list-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: var(--bg-card);
            border-radius: 6px;
            font-size: 0.85rem;
        }}
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .search-box {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: #fff;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 0.9rem;
            width: 320px;
        }}
        .search-box:focus {{ outline: none; border-color: var(--accent-cyan); }}
        .filter-buttons {{ display: flex; gap: 8px; }}
        .filter-btn {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn.active, .filter-btn:hover {{
            background: var(--bg-card);
            color: #fff;
            border-color: var(--accent-cyan);
        }}
        .alert-cards-container {{ display: flex; flex-direction: column; gap: 12px; }}
        .alert-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            transition: transform 0.15s, border-color 0.15s;
        }}
        .alert-card:hover {{ border-color: #4b5563; }}
        .alert-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 12px;
        }}
        .alert-title-wrap {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
        .alert-title {{ font-size: 1rem; font-weight: 700; color: #fff; }}
        .alert-ip-pill {{
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-card);
            padding: 4px 10px;
            border-radius: 6px;
        }}
        .detail-box {{
            background: #0f1523;
            border: 1px solid #1e293b;
            padding: 12px 14px;
            border-radius: 8px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            color: #d1d5db;
            white-space: pre-wrap;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1 class="header-title">
                    SOC Log Analyzer
                    <span class="pulse-badge">Incident Intelligence</span>
                </h1>
                <p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 4px;">
                    Automated Event Correlation, Threat Detection & Risk Scoring
                </p>
            </div>
            <div class="header-meta">
                <div><strong>Generated:</strong> {timestamp()}</div>
                <div><strong>Log Sources:</strong> {source_str}</div>
            </div>
        </header>

        <!-- KPI Summary Cards -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <span class="kpi-label">Total Detections</span>
                <span class="kpi-value text-cyan">{total_alerts}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Critical / High Alerts</span>
                <span class="kpi-value text-red">{critical_count + high_count}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Medium Priority Alerts</span>
                <span class="kpi-value text-amber">{med_count}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Investigated Events</span>
                <span class="kpi-value text-green">{stats.get('total_auth_events', 0) + stats.get('total_access_events', 0)}</span>
            </div>
        </div>

        <!-- IP Threat Matrix -->
        <h2 class="section-title">IP Threat Matrix & Risk Scores</h2>
        <div class="threat-table-card">
            <table>
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Classification</th>
                        <th>Threat Score</th>
                        <th>Threat Level</th>
                        <th>Observed Malicious Behaviors</th>
                    </tr>
                </thead>
                <tbody>
                    {threat_table_body}
                </tbody>
            </table>
        </div>

        <!-- Reconnaissance & Targeting Insights -->
        <div class="insight-grid">
            <div class="insight-card">
                <h4>Top Targeted Usernames</h4>
                <ul class="metric-list">
                    {top_users_html}
                </ul>
            </div>
            <div class="insight-card">
                <h4>Top Recon / 404 Probed Endpoints</h4>
                <ul class="metric-list">
                    {top_404_html}
                </ul>
            </div>
        </div>

        <!-- Detailed Security Alerts -->
        <h2 class="section-title">Security Incidents & Triggered Rules</h2>
        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search IP, alert title, or detail...">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterSeverity('all')">All ({total_alerts})</button>
                <button class="filter-btn" onclick="filterSeverity('critical')">Critical ({critical_count})</button>
                <button class="filter-btn" onclick="filterSeverity('high')">High ({high_count})</button>
                <button class="filter-btn" onclick="filterSeverity('medium')">Medium ({med_count})</button>
                <button class="filter-btn" onclick="filterSeverity('low')">Low ({low_count})</button>
            </div>
        </div>

        <div class="alert-cards-container" id="alertsList">
            {alert_cards_html}
        </div>
    </div>

    <script>
        let currentFilter = 'all';

        function filterSeverity(sev) {{
            currentFilter = sev;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            applyFilters();
        }}

        function applyFilters() {{
            const search = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.alert-card');

            cards.forEach(card => {{
                const sevMatch = currentFilter === 'all' || card.getAttribute('data-severity') === currentFilter;
                const textContent = (card.getAttribute('data-title') + " " + card.getAttribute('data-ip') + " " + card.textContent).toLowerCase();
                const searchMatch = !search || textContent.includes(search);

                if (sevMatch && searchMatch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        document.getElementById('searchInput').addEventListener('input', applyFilters);
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

