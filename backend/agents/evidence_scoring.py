"""Evidence scoring for autonomous verification.

The engine may still run high-impact checks in authorized environments, but it
should only mark a finding verified when the observed signal is specific enough.
This module separates "payload sent" from "impact proven".
"""

from __future__ import annotations

from typing import Any, Iterable


NEGATIVE_TERMS = (
    "unauthorized",
    "access denied",
    "forbidden",
    "login required",
    "not found",
    "invalid request",
)

GENERIC_SIGNATURES = {
    "generic_ai_verification",
    "logic_flaw_check",
    "oast_callback",
    "ssti_contextual_check",
}


def _level(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    if score >= 0.35:
        return "low"
    return "weak"


def _signature_weight(signature: str) -> float:
    lowered = signature.lower()
    if any(token in lowered for token in ("root:x", "uid=", "windows ip configuration", "boot.ini", "win.ini")):
        return 0.8
    if any(token in lowered for token in ("mysql", "postgres", "ora-", "syntax error")):
        return 0.72
    if any(token in lowered for token in ("alert", "onload", "<script", "fetch")):
        return 0.7
    return 0.62


def score_response_evidence(
    *,
    vuln_type: str,
    payload: str,
    response: Any | None,
    signatures: Iterable[str] = (),
    oast_confirmed: bool = False,
    strategy_confirmed: bool = False,
    ai_confirmed: bool = False,
    logic_confirmed: bool = False,
) -> dict[str, Any]:
    signals: list[str] = []
    matched_signatures: list[str] = []
    score = 0.0

    if oast_confirmed:
        score = max(score, 0.95)
        signals.append("oast_callback")

    if strategy_confirmed:
        score = max(score, 0.82)
        signals.append("strategy_confirmed")

    if ai_confirmed:
        score = max(score, 0.75)
        signals.append("ai_confirmed")

    if logic_confirmed:
        score = max(score, 0.68)
        signals.append("logic_transition")

    body = ""
    status_code = None
    if response is not None:
        status_code = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""

    body_lower = body.lower()
    for signature in signatures:
        if not signature:
            continue
        lowered = signature.lower()
        if lowered in GENERIC_SIGNATURES:
            continue
        if lowered in body_lower:
            matched_signatures.append(signature)
            score = max(score, _signature_weight(signature))

    if matched_signatures:
        signals.append("body_signature")

    if status_code and status_code >= 500 and any(token in vuln_type.lower() for token in ("sql", "injection", "ssti")):
        score = max(score, 0.35)
        signals.append("server_error_context")

    if body_lower and any(term in body_lower for term in NEGATIVE_TERMS):
        score = max(score - 0.2, 0.0)
        signals.append("negative_access_control_signal")

    if not signals and status_code is not None:
        signals.append(f"http_{status_code}")

    rounded = round(min(score, 1.0), 2)
    return {
        "score": rounded,
        "level": _level(rounded),
        "signals": signals,
        "matched_signatures": matched_signatures,
        "payload": payload,
        "status_code": status_code,
        "decision": rounded >= 0.65,
    }
