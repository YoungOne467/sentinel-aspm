"""
Export module — CSV, JSON, and styled HTML report generation.
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Any


def export_findings_csv(findings: List[Dict[str, Any]]) -> str:
    """Export findings to CSV."""
    output = io.StringIO()
    if not findings:
        return ""
    fieldnames = [
        "id", "title", "severity", "category", "description",
        "evidence", "solution", "status", "first_seen", "last_seen",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    return output.getvalue()


def export_findings_json(findings: List[Dict[str, Any]]) -> str:
    """Export findings to JSON."""
    return json.dumps(
        {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        },
        indent=2,
        default=str,
    )


def export_findings_html(findings: List[Dict[str, Any]], title: str = "Security Findings Report") -> str:
    """Export findings to a styled, dark-themed HTML report."""
    severity_colors = {
        "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
        "low": "#3b82f6", "info": "#6b7280",
    }
    rows = ""
    for f in findings:
        color = severity_colors.get(f.get("severity", "info"), "#6b7280")
        rows += f"""<tr>
            <td>{_esc(f.get('title', ''))}</td>
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">
                {f.get('severity', 'info').upper()}</span></td>
            <td>{_esc(f.get('category', ''))}</td>
            <td>{_esc(f.get('description', '')[:200])}</td>
            <td>{f.get('status', 'open')}</td>
            <td>{f.get('first_seen', '')}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{_esc(title)}</title>
<style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
    h1 {{ color: #38bdf8; font-size: 24px; margin-bottom: 4px; }}
    .meta {{ color: #94a3b8; margin-bottom: 24px; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th {{ background: #334155; padding: 12px 16px; text-align: left; color: #38bdf8; font-size: 12px;
          text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 10px 16px; border-bottom: 1px solid #334155; font-size: 13px; }}
    tr:hover {{ background: #334155; }}
    .footer {{ margin-top: 32px; text-align: center; color: #475569; font-size: 11px; }}
</style></head><body>
<h1>🛡 {_esc(title)}</h1>
<p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &bull;
   Total: {len(findings)} findings</p>
<table>
<thead><tr><th>Title</th><th>Severity</th><th>Category</th><th>Description</th><th>Status</th><th>First Seen</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<p class="footer">SENTINEL Security Telemetry Dashboard</p>
</body></html>"""


def _esc(s: str) -> str:
    """Basic HTML escape."""
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))
