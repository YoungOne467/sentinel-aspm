"""Shared finding normalization for scanner modules.

Modules should report observed security evidence, not static exploit demos.
This contract keeps legacy modules compatible while making final scan output
evidence-first and safe to display.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from core.module_metadata import apply_finding_metadata
from core.risk_model import score_finding


EVIDENCE_KEYS = ("evidence", "evidence_details", "observed_request", "observed_response")


def _has_evidence(finding: dict[str, Any]) -> bool:
    return any(bool(finding.get(key)) for key in EVIDENCE_KEYS)


def _verification_state(finding: dict[str, Any]) -> str:
    if finding.get("verified") is True:
        return "verified"
    if _has_evidence(finding):
        return "observed"
    return "candidate"


def _confidence_for(state: str) -> str:
    if state == "verified":
        return "high"
    if state == "observed":
        return "medium"
    return "low"


def _verification_notes(finding: dict[str, Any], state: str) -> list[str]:
    notes = list(finding.get("verification_notes") or [])
    evidence = finding.get("evidence")
    if evidence and not any("Evidence stored at" in note for note in notes):
        notes.append(f"Evidence stored at {evidence}")
    if state == "candidate" and not notes:
        notes.append("Candidate finding requires manual verification.")
    return notes


def normalize_finding(finding: dict[str, Any], target_url: str | None = None) -> dict[str, Any]:
    """Return a sanitized finding that follows the platform output contract."""
    # ⚡ Bolt: Replaced deepcopy with shallow copy. Deepcopy blocks the CPU synchronously
    # and is excessively slow for processing thousands of finding dictionaries.
    normalized = finding.copy()

    normalized.pop("exploit_demo", None)
    normalized["real_work"] = True

    if target_url and not normalized.get("target_url"):
        normalized["target_url"] = target_url

    state = _verification_state(normalized)
    normalized["verification_state"] = state
    normalized["confidence"] = normalized.get("confidence") or _confidence_for(state)
    normalized["verification_notes"] = _verification_notes(normalized, state)
    normalized.setdefault("verified", state == "verified")
    normalized.setdefault("verification_results", None)
    normalized.setdefault("patch_provided", False)
    normalized.setdefault("payload", "")
    normalized.setdefault("vector", "Unknown")
    normalized.setdefault("description", "Observed by scanner module.")
    normalized.setdefault("remediation", "Review the evidence and apply the relevant vendor or secure-coding remediation.")
    normalized.setdefault("proof_chain", [])
    normalized.setdefault("affected_identity", "unknown")
    normalized.setdefault("surface_node", None)
    normalized.setdefault("confidence_score", 0.9 if state == "verified" else 0.65 if state == "observed" else 0.35)
    normalized.setdefault("replay", {
        "method": "GET",
        "url": normalized.get("target_url") or target_url or "",
        "vector": normalized.get("vector", "Unknown"),
        "payload": normalized.get("payload", ""),
    })

    normalized = apply_finding_metadata(normalized)
    normalized["risk_score"] = score_finding(normalized)
    return normalized


def normalize_findings(findings: list[dict[str, Any]], target_url: str | None = None) -> list[dict[str, Any]]:
    return [normalize_finding(finding, target_url) for finding in findings]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(findings),
        "critical": sum(1 for finding in findings if finding.get("severity") == "Critical"),
        "high": sum(1 for finding in findings if finding.get("severity") == "High"),
        "medium": sum(1 for finding in findings if finding.get("severity") == "Medium"),
        "lowInfo": sum(1 for finding in findings if finding.get("severity") in ("Low", "Info")),
    }


def normalize_scan_result(result: dict[str, Any] | None, target_url: str | None = None) -> dict[str, Any] | None:
    """Normalize a full scan result payload, including historical records."""
    if result is None:
        return None

    # ⚡ Bolt: Replaced deepcopy with shallow copy. Deepcopy blocks the CPU synchronously
    # and is excessively slow for processing massive scan result payloads.
    normalized = result.copy()
    vulnerabilities = normalize_findings(list(normalized.get("vulnerabilities") or []), target_url)
    normalized["vulnerabilities"] = vulnerabilities

    module_results = normalized.get("module_results") or {}
    normalized["module_results"] = {
        module_name: normalize_findings(list(findings or []), target_url)
        for module_name, findings in module_results.items()
    }

    normalized.update(_severity_counts(vulnerabilities))
    normalized.setdefault("attack_paths", [])
    normalized["contract_version"] = 2
    return normalized
