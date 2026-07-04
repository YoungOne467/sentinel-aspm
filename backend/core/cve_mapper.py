import os
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger("sentinel.cve_mapper")

CVE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_database.json")

def load_cve_database() -> Dict[str, Any]:
    """Loads known high-impact CVEs from the local JSON database."""
    try:
        if os.path.exists(CVE_DB_PATH):
            with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error("Failed to load CVE database: %s", e)
    return {}

def map_cves_for_tech_stack(tech_stack: List[str]) -> List[Dict[str, Any]]:
    """
    Cross-references a discovered tech_stack list against the local CVE database.
    """
    if not tech_stack:
        return []
    
    cve_db = load_cve_database()
    matched_cves = []
    seen_cves = set()
    
    for tech in tech_stack:
        tech_lower = tech.lower()
        for product, cves in cve_db.items():
            # Match product names as substrings, e.g. "tomcat" in "tomcat 9.0"
            if product in tech_lower:
                for cve in cves:
                    cve_id = cve["cve_id"]
                    if cve_id in seen_cves:
                        continue
                    
                    # Verify version if affected_versions is specified
                    affected = cve.get("affected_versions", [])
                    if affected:
                        version_match = False
                        for v in affected:
                            if v in tech_lower:
                                version_match = True
                                break
                        if not version_match:
                            continue
                    
                    matched_cves.append({
                        "cve_id": cve_id,
                        "severity": cve.get("severity", "info"),
                        "cvss": cve.get("cvss", 0.0),
                        "description": cve.get("description", ""),
                        "matched_tech": tech
                    })
                    seen_cves.add(cve_id)
                    
    return matched_cves
