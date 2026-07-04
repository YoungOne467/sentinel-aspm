"""Risk scoring for normalized scanner findings."""

from __future__ import annotations

from typing import Any


SEVERITY_BASE = {
    "Critical": 90,
    "High": 75,
    "Medium": 50,
    "Low": 25,
    "Info": 10,
}

CONFIDENCE_DELTA = {
    "high": 10,
    "medium": 0,
    "low": -15,
}

STATE_DELTA = {
    "verified": 20,
    "observed": 8,
    "candidate": -25,
}

HIGH_IMPACT_TERMS = (
    "authentication",
    "authorization",
    "cache poisoning",
    "credential",
    "graphql",
    "metadata",
    "request smuggling",
    "secret",
    "session",
    "ssrf",
    "token",
)


def score_finding(finding: dict[str, Any]) -> int:
    """Return a 0-100 risk score from severity, proof quality, and impact hints."""
    severity = str(finding.get("severity") or "Info")
    confidence = str(finding.get("confidence") or "").lower()
    state = str(finding.get("verification_state") or "").lower()
    if finding.get("verified") is True:
        state = "verified"

    score = SEVERITY_BASE.get(severity, 10)
    score += CONFIDENCE_DELTA.get(confidence, 0)
    score += STATE_DELTA.get(state, 0)

    if finding.get("evidence"):
        score += 5
    evidence_details = finding.get("evidence_details") or {}
    if isinstance(evidence_details, dict):
        score += min(int(evidence_details.get("confidence_score") or 0), 10)
        signals = " ".join(str(signal).lower() for signal in evidence_details.get("signals") or [])
        if any(signal in signals for signal in ("marker_reflection", "oast", "sensitive")):
            score += 5

    haystack = " ".join(
        str(finding.get(key) or "").lower()
        for key in ("type", "vector", "description", "owasp_category")
    )
    if any(term in haystack for term in HIGH_IMPACT_TERMS):
        score += 5

    return max(0, min(100, int(score)))
