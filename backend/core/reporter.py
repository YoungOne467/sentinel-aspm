"""
AETHER White-Label Reporting Engine (Item 149).
Generates high-fidelity security reports in HTML and Markdown.
"""
import json
from datetime import datetime

class Reporter:
    def generate_html_report(self, results: dict) -> str:
        """Generates a polished HTML report."""
        findings = results.get("vulnerabilities", [])
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "Critical")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Inter', sans-serif; background: #020408; color: white; padding: 40px; }}
                .header {{ border-bottom: 2px solid #00f3ff; padding-bottom: 20px; }}
                .stat-box {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat {{ background: #0a1122; padding: 20px; border-radius: 8px; border: 1px solid #ffffff10; flex: 1; }}
                .finding {{ background: #0a1122; margin: 10px 0; padding: 20px; border-left: 4px solid #00f3ff; }}
                .critical {{ border-left-color: #ff0044; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AETHER Tactical Audit Report</h1>
                <p>Target: {results.get('url')}</p>
                <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <div class="stat-box">
                <div class="stat"><h3>Total Findings</h3><p>{total}</p></div>
                <div class="stat"><h3>Critical</h3><p style="color: #ff0044">{critical}</p></div>
            </div>
            <h2>Findings Breakdown</h2>
            {"".join([f'<div class="finding {f.get("severity").lower()}"><h3>{f.get("name")}</h3><p>{f.get("description")}</p></div>' for f in findings])}
        </body>
        </html>
        """
        return html

reporter = Reporter()
