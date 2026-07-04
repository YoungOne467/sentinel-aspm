import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Finding, Target

logger = logging.getLogger(__name__)

class ReportGenerator:
    @staticmethod
    async def generate_scan_report(target_id: str) -> Dict[str, str]:
        """
        Queries the database for all findings linked to target_id and
        compiles them into Markdown and styled HTML reports.
        """
        async with AsyncSessionLocal() as session:
            target = await session.get(Target, target_id)
            if not target:
                raise ValueError(f"Target scope '{target_id}' not found.")

            result = await session.execute(
                select(Finding).where(Finding.target_id == target_id)
            )
            findings = result.scalars().all()

        # Build Markdown report content
        md_lines = [
            f"# AETHER Tactical Audit Report",
            f"- **Target Scope**: {target.name} ({target.host}:{target.port or '80'})",
            f"- **Generated At**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Vulnerabilities Count**: {len(findings)} Total Findings",
            "\n## Findings Summary Table\n",
            "| Title | Severity | Category | Status | Detected |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for f in findings:
            md_lines.append(
                f"| {f.title} | {f.severity.upper()} | {f.category} | {f.status} | {f.first_seen.strftime('%Y-%m-%d')} |"
            )

        md_lines.append("\n## Detailed Findings breakdown\n")
        for i, f in enumerate(findings, 1):
            md_lines.extend([
                f"### {i}. {f.title} (`{f.severity.upper()}`)",
                f"- **Category**: {f.category}",
                f"- **Status**: {f.status}",
                f"- **Detected**: {f.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                f"- **Description**:\n{f.description}",
                f"- **Vulnerability Evidence / Proof of Concept**:\n```text\n{f.evidence}\n```",
                f"- **Remediation Plan**:\n{f.solution}",
                "\n---\n"
            ])

        markdown_report = "\n".join(md_lines)

        # Build styled HTML report content
        severity_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#3b82f6",
            "info": "#6b7280"
        }

        html_findings = ""
        for i, f in enumerate(findings, 1):
            color = severity_colors.get(f.severity.lower(), "#6b7280")
            html_findings += f"""
            <div class="finding border-l-4 p-4 mb-6 bg-slate-900 rounded-r border-slate-800" style="border-left-color: {color};">
                <div class="flex justify-between items-center mb-2">
                    <h3 class="text-base font-bold text-slate-100">{i}. {f.title}</h3>
                    <span class="text-[10px] font-bold px-2 py-0.5 rounded text-white" style="background-color: {color};">{f.severity.upper()}</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-xs text-slate-400 mb-3 font-mono">
                    <div><strong>Category:</strong> {f.category}</div>
                    <div><strong>Detected:</strong> {f.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                    <div><strong>Status:</strong> {f.status}</div>
                </div>
                <div class="mb-3">
                    <h4 class="text-xs font-semibold text-slate-300 uppercase mb-1">Description</h4>
                    <p class="text-xs text-slate-400 leading-relaxed">{f.description}</p>
                </div>
                <div class="mb-3">
                    <h4 class="text-xs font-semibold text-slate-300 uppercase mb-1">Evidence / Payload</h4>
                    <pre class="bg-slate-950 p-2 rounded text-[10px] text-cyan-400 overflow-x-auto font-mono whitespace-pre-wrap">{f.evidence}</pre>
                </div>
                <div>
                    <h4 class="text-xs font-semibold text-slate-300 uppercase mb-1">Remediation Action</h4>
                    <p class="text-xs text-slate-400">{f.solution}</p>
                </div>
            </div>
            """

        html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AETHER Security Report - {target.name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{
            background-color: #020617;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }}
    </style>
</head>
<body class="text-slate-300 p-8 max-w-5xl mx-auto">
    <div class="border-b border-slate-800 pb-6 mb-8">
        <h1 class="text-2xl font-bold text-cyan-400 uppercase tracking-wider mb-2">AETHER Security Audit Report</h1>
        <div class="grid grid-cols-2 gap-4 text-xs text-slate-400 font-mono mt-4">
            <div><strong>Target scope:</strong> {target.name} ({target.host}:{target.port or '80'})</div>
            <div><strong>Generated At:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
            <div><strong>Total Findings:</strong> {len(findings)} vulnerabilities</div>
        </div>
    </div>

    <div class="mb-8">
        <h2 class="text-lg font-bold text-slate-200 uppercase tracking-wider mb-4 border-b border-slate-900 pb-2">Findings Summary Table</h2>
        <div class="overflow-x-auto border border-slate-850 rounded">
            <table class="w-full text-left text-xs font-mono">
                <thead class="bg-slate-900 text-slate-500 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                        <th class="p-3">Vulnerability Title</th>
                        <th class="p-3">Severity</th>
                        <th class="p-3">Category</th>
                        <th class="p-3">Status</th>
                        <th class="p-3">Detected</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-900 bg-slate-950/40">
                    {"".join([f'<tr><td class="p-3 font-semibold text-slate-350">{f.title}</td><td class="p-3"><span class="px-1.5 py-0.5 rounded text-[9px] font-bold text-white" style="background-color: {severity_colors.get(f.severity.lower(), "#6b7280")}">{f.severity.upper()}</span></td><td class="p-3 text-slate-400">{f.category}</td><td class="p-3 text-slate-400">{f.status}</td><td class="p-3 text-slate-500">{f.first_seen.strftime("%Y-%m-%d")}</td></tr>' for f in findings])}
                </tbody>
            </table>
        </div>
    </div>

    <div>
        <h2 class="text-lg font-bold text-slate-200 uppercase tracking-wider mb-4 border-b border-slate-900 pb-2">Detailed Findings Breakdown</h2>
        {html_findings if findings else '<div class="text-slate-500 italic text-xs py-4 text-center">No vulnerability findings recorded for this target scope.</div>'}
    </div>

    <footer class="mt-16 pt-8 border-t border-slate-900 text-center text-[10px] text-slate-600 font-mono uppercase tracking-wider">
        SENTINEL Security Telemetry and Automation Suite
    </footer>
</body>
</html>
"""

        return {
            "markdown": markdown_report,
            "html": html_report
        }
