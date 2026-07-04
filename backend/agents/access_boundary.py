"""Operator handoff boundary for autonomous access verification.

The exploit engine can prove that an authorized target exposes an access
primitive, but follow-on decisions should be explicit operator actions. This
module turns a verified response into a compact handoff object and a bounded
action catalog for the UI.
"""


import hashlib
import re
from typing import Any


READONLY_COMMANDS = ("id", "whoami", "pwd", "hostname", "uname -a")
COMMAND_VULN_HINTS = ("command", "cmdi", "rce", "os command")


def _response_text(response: Any, limit: int = 12000) -> str:
    if response is None:
        return ""
    text = getattr(response, "text", "") or ""
    return str(text)[:limit]


def _fingerprint(value: str) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _data_class_labels(exposure_assessment: dict[str, Any] | None) -> set[str]:
    classes = (exposure_assessment or {}).get("data_classes") or []
    return {str(item.get("label")) for item in classes if isinstance(item, dict) and item.get("label")}


def command_channel_for(vuln_type: str, payload: str | None = None) -> dict[str, Any]:
    lowered = str(vuln_type or "").lower()
    available = any(token in lowered for token in COMMAND_VULN_HINTS)
    payload_text = str(payload or "")
    replaceable = any(re.search(rf"(?<![\w-]){re.escape(cmd)}(?![\w-])", payload_text) for cmd in READONLY_COMMANDS)
    return {
        "available": bool(available and replaceable),
        "reason": (
            "Verified command-execution primitive with a replaceable read-only proof command."
            if available and replaceable
            else "No bounded command channel was identified for this proof."
        ),
        "allowed_commands": list(READONLY_COMMANDS) if available and replaceable else [],
    }


def build_readonly_command_payload(verified_payload: str, command: str) -> str | None:
    command = str(command or "").strip()
    if command not in READONLY_COMMANDS:
        return None

    payload = str(verified_payload or "")
    for token in sorted(READONLY_COMMANDS, key=len, reverse=True):
        pattern = re.compile(rf"(?<![\w-]){re.escape(token)}(?![\w-])")
        if pattern.search(payload):
            return pattern.sub(command, payload, count=1)
    return None


def _access_level(vuln_type: str, labels: set[str]) -> str:
    lowered = str(vuln_type or "").lower()
    if labels & {"cloud_access_key", "cloud_metadata", "filesystem_identity_file"}:
        return "host_or_cloud_control_material"
    if labels & {"application_secret", "session_or_jwt"}:
        return "application_access_material"
    if labels & {"aspm_canary", "personal_data"}:
        return "sensitive_record_access"
    if any(token in lowered for token in COMMAND_VULN_HINTS):
        return "execution_primitive"
    if any(token in lowered for token in ("idor", "bola", "auth", "authorization", "access control")):
        return "authorization_bypass"
    return "verified_access_primitive"


def build_operator_handoff(
    *,
    vuln_type: str,
    payload: str,
    response: Any,
    evidence_score: dict[str, Any] | None,
    exposure_assessment: dict[str, Any] | None,
    action_mode: str,
    auth_profile: str | None = None,
    surface_node: str | None = None,
    replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    text = _response_text(response)
    labels = _data_class_labels(exposure_assessment)
    score = evidence_score or {}
    exposure_score = int((exposure_assessment or {}).get("exposure_score") or 0)
    access_proven = bool(score.get("decision") or float(score.get("score") or 0) >= 0.65 or exposure_score > 0)
    command_channel = command_channel_for(vuln_type, payload)

    available_actions = [
        {
            "id": "replay_proof_request",
            "label": "Replay Proof Request",
            "description": "Re-send the exact verified request once and refresh the proof fingerprint.",
            "requires_confirmation": True,
        },
        {
            "id": "inspect_access_evidence",
            "label": "Inspect Access Evidence",
            "description": "Review the captured proof classes, access level, and response fingerprint.",
            "requires_confirmation": False,
        },
        {
            "id": "export_handoff_report",
            "label": "Export Handoff Report",
            "description": "Return a structured operator report with proof, replay, and remediation context.",
            "requires_confirmation": False,
        },
    ]
    if str(action_mode).lower() == "access mode" and command_channel["available"]:
        available_actions.append({
            "id": "run_readonly_command",
            "label": "Run Read-Only Command",
            "description": "Replace the verified proof command with an approved read-only command and run it once.",
            "requires_confirmation": True,
            "parameters": {"command": command_channel["allowed_commands"]},
        })

    return {
        "state": "operator_handoff" if access_proven else "verification_incomplete",
        "stop_reason": "access_proof_reached" if access_proven else "access_not_proven",
        "next_owner": "operator" if access_proven else "scanner",
        "access_proven": access_proven,
        "access_level": _access_level(vuln_type, labels),
        "action_mode": action_mode,
        "auth_profile": auth_profile or "unknown",
        "surface_node": surface_node,
        "payload": payload,
        "status_code": getattr(response, "status_code", None) if response is not None else None,
        "proof_signals": list(dict.fromkeys((score.get("signals") or []) + sorted(labels))),
        "confidence_score": score.get("score", 0),
        "exposure_score": exposure_score,
        "response_fingerprint": _fingerprint(text),
        "response_bytes_reviewed": len(text.encode("utf-8", errors="ignore")),
        "command_channel": command_channel,
        "available_actions": available_actions,
        "replay": replay or {},
    }
