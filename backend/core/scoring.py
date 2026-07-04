import logging
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, CrawledURL, DiscoveredSubdomain, Finding, DLPFinding

logger = logging.getLogger("sentinel.scoring")

def get_severity_score(severity: str) -> float:
    sev = severity.lower()
    if sev == "critical":
        return 8.0
    elif sev == "high":
        return 6.0
    elif sev == "medium":
        return 4.0
    elif sev == "low":
        return 2.0
    elif sev == "info":
        return 0.5
    return 0.0

def is_non_standard_port(host_str: str) -> bool:
    if ":" in host_str:
        try:
            port = int(host_str.split(":")[-1])
            if port not in (80, 443):
                return True
        except ValueError:
            pass
    return False

async def update_target_scores(target_id: str):
    """
    Updates the composite risk score and tech stack for a Target and all its subdomains and URLs.
    Caps all final scores at 10.0.
    """
    try:
        async with AsyncSessionLocal() as session:
            # 1. Fetch target
            target = await session.get(Target, target_id)
            if not target:
                return

            # Fetch all findings, crawled URLs, discovered subdomains, and DLP findings for this target
            findings_res = await session.execute(
                select(Finding).where(Finding.target_id == target_id)
            )
            findings = findings_res.scalars().all()

            urls_res = await session.execute(
                select(CrawledURL).where(CrawledURL.target_id == target_id)
            )
            urls = urls_res.scalars().all()

            subs_res = await session.execute(
                select(DiscoveredSubdomain).where(DiscoveredSubdomain.target_id == target_id)
            )
            subdomains = subs_res.scalars().all()

            # 2. Update CrawledURL scores
            url_id_to_dlp = {}
            for url_obj in urls:
                dlp_res = await session.execute(
                    select(DLPFinding).where(DLPFinding.crawled_url_id == url_obj.id)
                )
                dlp_findings = dlp_res.scalars().all()
                url_id_to_dlp[url_obj.id] = dlp_findings

                score = 0.0
                # DLP additions
                for dlp in dlp_findings:
                    if dlp.finding_type == "Credential":
                        score += 3.0
                    elif dlp.finding_type == "PII":
                        score += 1.5

                # Anomalies additions
                for f in findings:
                    if (f.evidence and url_obj.url in f.evidence) or (f.description and url_obj.url in f.description):
                        score += get_severity_score(f.severity)

                # CVE additions
                for cve in (url_obj.known_cves or []):
                    score += get_severity_score(cve.get("severity", "info"))

                # Centrality multiplier for deep endpoints: 1.0x
                score = score * 1.0
                url_obj.risk_score = min(score, 10.0)

            # 3. Update DiscoveredSubdomain scores and tech stack
            for sub_obj in subdomains:
                sub_name = sub_obj.subdomain
                score = 0.0

                # Port scanning exposure: +1.0 for non-standard port
                if is_non_standard_port(sub_name):
                    score += 1.0

                # DLP additions from all crawled URLs on this subdomain
                sub_techs = set()
                for url_obj in urls:
                    if url_obj.host == sub_name or url_obj.host.split(":")[0] == sub_name.split(":")[0]:
                        sub_techs.update(url_obj.tech_stack or [])
                        dlps = url_id_to_dlp.get(url_obj.id, [])
                        for dlp in dlps:
                            if dlp.finding_type == "Credential":
                                score += 3.0
                            elif dlp.finding_type == "PII":
                                score += 1.5

                sub_obj.tech_stack = list(sub_techs)

                # Anomalies matching the subdomain
                for f in findings:
                    if (f.evidence and sub_name.split(":")[0] in f.evidence) or (f.description and sub_name.split(":")[0] in f.description):
                        score += get_severity_score(f.severity)

                # CVE additions from crawled URLs on this subdomain
                for url_obj in urls:
                    if url_obj.host == sub_name or url_obj.host.split(":")[0] == sub_name.split(":")[0]:
                        for cve in (url_obj.known_cves or []):
                            score += get_severity_score(cve.get("severity", "info"))

                # Centrality multiplier for subdomains: 1.2x
                score = score * 1.2
                sub_obj.risk_score = min(score, 10.0)

            # 4. Update root Target score and tech stack
            target_score = 0.0

            # Anomalies
            for f in findings:
                target_score += get_severity_score(f.severity)

            # DLP
            for url_obj in urls:
                dlps = url_id_to_dlp.get(url_obj.id, [])
                for dlp in dlps:
                    if dlp.finding_type == "Credential":
                        target_score += 3.0
                    elif dlp.finding_type == "PII":
                        target_score += 1.5

            # CVE additions
            for cve in (target.known_cves or []):
                target_score += get_severity_score(cve.get("severity", "info"))

            # Exposure: Count distinct non-standard ports
            ports = set()
            for sub_obj in subdomains:
                if ":" in sub_obj.subdomain:
                    try:
                        ports.add(int(sub_obj.subdomain.split(":")[-1]))
                    except ValueError:
                        pass
            for p in ports:
                if p not in (80, 443):
                    target_score += 1.0

            # Centrality multiplier for root target: 1.5x
            target_score = target_score * 1.5
            target.risk_score = min(target_score, 10.0)

            # Update target tech stack from union of all subdomains and urls
            all_techs = set(target.tech_stack or [])
            for sub_obj in subdomains:
                all_techs.update(sub_obj.tech_stack or [])
            for url_obj in urls:
                all_techs.update(url_obj.tech_stack or [])
            target.tech_stack = list(all_techs)

            await session.commit()
            logger.info("Updated risk scores for target '%s': score=%.2f", target.host, target.risk_score)
    except Exception as e:
        logger.error("Failed to update target scores: %s", e)
