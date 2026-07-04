"""
Attack Chainer for Multi-Stage Exploit Orchestration.
This module links "low-impact" findings into critical attack chains,
mirroring professional adversary behavior.
"""

import logging
from dataclasses import dataclass
from typing import List, Dict, Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExploitContextEntry:
    secret_type: str
    secret: str
    source_vuln_id: str | None = None
    target_id: str | None = None
    file_path: str | None = None


class ExploitContext:
    """In-memory scan-lifecycle state for multi-stage attack pivots."""

    def __init__(self):
        self._by_host: dict[str, list[ExploitContextEntry]] = {}

    def clear(self) -> None:
        self._by_host.clear()

    def save_secret(self, target_url: str, finding: dict[str, Any]) -> None:
        host = context_key(target_url)
        if not host:
            return
        secret = str(finding.get("secret") or "").strip()
        secret_type = str(finding.get("type") or "").strip()
        if not secret or not is_auth_material(secret_type):
            return
        entry = ExploitContextEntry(
            secret_type=secret_type,
            secret=secret,
            source_vuln_id=finding.get("source_vuln_id"),
            target_id=finding.get("target_id"),
            file_path=finding.get("file_path"),
        )
        existing = self._by_host.setdefault(host, [])
        if not any(item.secret == entry.secret and item.secret_type == entry.secret_type for item in existing):
            existing.append(entry)
            logger.info("Stored exploit context material type=%s for host=%s", secret_type, host)

    def get_entries(self, target_url: str) -> list[ExploitContextEntry]:
        return list(self._by_host.get(context_key(target_url), []))

    def get_auth_headers(self, target_url: str) -> dict[str, str]:
        entry = self._best_auth_entry(target_url)
        if not entry:
            return {}
        if entry.secret_type == "Basic Credentials":
            return {"Authorization": f"Basic {entry.secret}"}
        return {"Authorization": f"Bearer {entry.secret}"}

    def get_primary_vuln_id(self, target_url: str) -> str | None:
        entry = self._best_auth_entry(target_url)
        return entry.source_vuln_id if entry else None

    def _best_auth_entry(self, target_url: str) -> ExploitContextEntry | None:
        entries = self.get_entries(target_url)
        if not entries:
            return None
        priority = {"JWT": 0, "API Key": 1, "Google API Key": 1, "Stripe Secret Key": 1, "AWS Access Key": 2}
        return sorted(entries, key=lambda item: priority.get(item.secret_type, 5))[0]


def context_key(target_url: str) -> str:
    parsed = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
    return (parsed.hostname or parsed.netloc or parsed.path).lower()


def is_auth_material(secret_type: str) -> bool:
    normalized = secret_type.lower()
    return any(term in normalized for term in ("jwt", "api key", "access key", "secret key", "credential"))


exploit_context = ExploitContext()

class AttackChainer:
    def __init__(self):
        # Maps a finding type to potential follow-up research tasks
        self.chain_rules = {
            "Information Disclosure (Sensitive Files)": [
                {"next": "Credential Extraction", "priority": 1, "module": "auth_bypass"},
                {"next": "Endpoint Discovery", "priority": 2, "module": "api_fuzzer"}
            ],
            "Local File Inclusion (LFI)": [
                {"next": "RCE Escalation (Log Poisoning)", "priority": 1, "module": "lfi_rce_escalation"},
                {"next": "RCE Escalation (Filter Chain)", "priority": 1, "module": "lfi_rce_escalation"},
                {"next": "Source Code Extraction", "priority": 2, "module": "sensitive_files"}
            ],
            "Server-Side Request Forgery (SSRF)": [
                {"next": "Cloud Metadata Exfiltration", "priority": 1, "module": "ssrf_oast"},
                {"next": "Internal Port Scanning", "priority": 2, "module": "network_recon"}
            ],
            "Cross-Site Scripting (XSS)": [
                {"next": "Session Token Theft", "priority": 1, "module": "post_exploit"},
                {"next": "CSRF Bypass", "priority": 2, "module": "post_exploit"}
            ]
        }

    def identify_chains(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes a list of findings and returns a prioritized list of 
        attack chain sequences.
        """
        chains = []
        for finding in findings:
            f_type = finding.get("type")
            if f_type in self.chain_rules:
                for rule in self.chain_rules[f_type]:
                    chains.append({
                        "initial_finding": f_type,
                        "vector": finding.get("vector"),
                        "next_step": rule["next"],
                        "target_module": rule["module"],
                        "priority": rule["priority"],
                        "evidence_context": finding.get("evidence")
                    })
        
        # Sort by priority
        return sorted(chains, key=lambda x: x["priority"])

    def generate_attack_path_visualization(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Formats chains into the 'attack_paths' structure used by the UI.
        """
        paths = []
        for chain in chains:
            paths.append({
                "nodes": [chain["initial_finding"], chain["next_step"]],
                "risk_score": 10 if chain["priority"] == 1 else 7,
                "description": f"Escalating {chain['initial_finding']} to {chain['next_step']} via {chain['target_module']}."
            })
        return paths

chainer = AttackChainer()
