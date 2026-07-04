"""Deep exfiltration impact assessment for verified responses.

The assessor consumes the live response produced by the autonomous engine and
classifies the exposed data classes, impact level, and response proof signals.
"""


import hashlib
import re
from typing import Any


DATA_CLASS_PATTERNS = [
    {
        "label": "aspm_canary",
        "severity": "critical",
        "patterns": [
            r"\bASPM_CANARY_[A-Z0-9_]+\s*=\s*\S+",
            r"\baspm_canary_[a-z0-9_]+\s*[:=]\s*\S+",
            r"\bseeded-(?:customer|secret|token|account)-[A-Za-z0-9_-]+\b",
        ],
        "impact": "A seeded ASPM canary value is reachable, proving the vulnerable path can expose controlled sensitive records.",
    },
    {
        "label": "cloud_access_key",
        "severity": "critical",
        "patterns": [
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bASIA[0-9A-Z]{16}\b",
            r"\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+",
        ],
        "impact": "Cloud provider credentials or access-key material appear reachable.",
    },
    {
        "label": "application_secret",
        "severity": "critical",
        "patterns": [
            r"\b(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|JWT_SECRET|SECRET_KEY|APP_SECRET|APP_KEY|API_KEY|API_SECRET)\s*=\s*\S+",
            r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
        ],
        "impact": "Application secrets, API tokens, database passwords, or signing material appear reachable.",
    },
    {
        "label": "filesystem_identity_file",
        "severity": "critical",
        "patterns": [
            r"root:x:0:0:",
            r"daemon:x:\d+:\d+:",
            r"\[(?:extensions|fonts|mci extensions)\]",
        ],
        "impact": "Operating-system identity/configuration files appear reachable through the vector.",
    },
    {
        "label": "cloud_metadata",
        "severity": "critical",
        "patterns": [
            r"iam/security-credentials",
            r"\bAccessKeyId\b",
            r"\bSecretAccessKey\b",
            r"\bToken\b.{0,40}\bExpiration\b",
        ],
        "impact": "Cloud instance metadata or temporary credential material appears reachable.",
    },
    {
        "label": "database_metadata",
        "severity": "high",
        "patterns": [
            r"\binformation_schema\b",
            r"\bcurrent_user\b",
            r"\b@@version\b",
            r"\bPostgreSQL\b|\bMySQL\b|\bMariaDB\b|\bSQL Server\b",
            r"SQL syntax|mysql_fetch|ORA-\d+|SQLite/JDBCDriver",
        ],
        "impact": "Database metadata, engine details, or SQL error context is reachable.",
    },
    {
        "label": "personal_data",
        "severity": "high",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"\b(?:email|phone|address|first_name|last_name|full_name|username)\b\s*[:=]",
        ],
        "impact": "User-identifying data appears in the reachable response.",
    },
    {
        "label": "session_or_jwt",
        "severity": "high",
        "patterns": [
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            r"\b(?:sessionid|connect\.sid|sid|csrf|xsrf|remember_token)\b\s*[:=]",
        ],
        "impact": "Session, CSRF, remember-me, or JWT-like material appears reachable.",
    },
    {
        "label": "internal_service",
        "severity": "medium",
        "patterns": [
            r"SSH-\d\.\d-",
            r"\bRedis\b|\bMongoDB\b|\bElasticsearch\b|\bMemcached\b",
            r"\b127\.0\.0\.1\b|\blocalhost\b|\b10\.\d+\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b",
        ],
        "impact": "Internal service banners or private-network references appear reachable.",
    },
]

SEVERITY_POINTS = {
    "critical": 35,
    "high": 24,
    "medium": 14,
    "low": 6,
}


def _response_text(response: Any, limit: int = 12000) -> str:
    if response is None:
        return ""
    if hasattr(response, "text"):
        return str(response.text)[:limit]
    content = getattr(response, "content", b"") or b""
    if isinstance(content, bytes):
        return content[:limit].decode("utf-8", errors="ignore")
    return str(content)[:limit]


def _proof_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _match_pattern(pattern: str, text: str) -> list[str]:
    try:
        return [match.group(0) for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.MULTILINE)]
    except re.error:
        return []


def _level_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _label_set(data_classes: list[dict[str, Any]]) -> set[str]:
    return {item["label"] for item in data_classes}


def _build_blast_radius(data_classes: list[dict[str, Any]], score: int) -> dict[str, Any]:
    labels = _label_set(data_classes)
    if not data_classes:
        return {
            "level": "none",
            "scope": "No sensitive class detected in the reviewed response.",
            "score": 0,
        }
    if labels & {"cloud_access_key", "cloud_metadata", "filesystem_identity_file"}:
        return {
            "level": "host_or_cloud_compromise",
            "scope": "The response proves access to host/cloud control material or OS identity files.",
            "score": score,
        }
    if labels & {"application_secret", "session_or_jwt"}:
        return {
            "level": "application_compromise",
            "scope": "The response proves access to application secrets or session material.",
            "score": score,
        }
    if labels & {"aspm_canary", "personal_data"}:
        return {
            "level": "sensitive_record_exposure",
            "scope": "The response proves access to user-specific or seeded sensitive records.",
            "score": score,
        }
    return {
        "level": "technical_information_exposure",
        "scope": "The response exposes technical details useful for follow-on validation.",
        "score": score,
    }


def _build_impact_paths(data_classes: list[dict[str, Any]], vuln_type: str) -> list[dict[str, Any]]:
    labels = _label_set(data_classes)
    paths = []
    if "aspm_canary" in labels:
        paths.append({
            "name": "seeded_canary_exposure",
            "precondition": "A controlled canary value exists in the tested environment.",
            "impact": "The verified vector reached seeded sensitive data, proving the path is not theoretical.",
            "evidence": "aspm_canary data class detected",
        })
    if {"application_secret", "database_metadata"} <= labels or ("application_secret" in labels and "sql" in vuln_type.lower()):
        paths.append({
            "name": "secret_to_database_access",
            "precondition": "Application secret material and database context are reachable from the vector.",
            "impact": "A production-equivalent exposure could allow database authentication or query expansion.",
            "evidence": "application_secret + database_metadata",
        })
    if labels & {"cloud_access_key", "cloud_metadata"}:
        paths.append({
            "name": "cloud_control_plane_exposure",
            "precondition": "Cloud credential or metadata material is visible in the response.",
            "impact": "Cloud resources associated with the exposed identity may be reachable depending on IAM scope.",
            "evidence": "cloud data class detected",
        })
    if "filesystem_identity_file" in labels:
        paths.append({
            "name": "host_file_read_exposure",
            "precondition": "The vector returns host identity/configuration file content.",
            "impact": "Additional local files may be reachable through the same file-read primitive.",
            "evidence": "filesystem_identity_file",
        })
    if "session_or_jwt" in labels:
        paths.append({
            "name": "session_material_exposure",
            "precondition": "Session, CSRF, remember-me, or JWT-like material is present.",
            "impact": "Account/session integrity may be affected if the material is valid and not bound to context.",
            "evidence": "session_or_jwt",
        })
    if "personal_data" in labels:
        paths.append({
            "name": "user_data_exposure",
            "precondition": "User-identifying fields are reachable from the tested vector.",
            "impact": "The vulnerable path may expose user records or tenant-specific information.",
            "evidence": "personal_data",
        })
    return paths


def _build_priority_actions(data_classes: list[dict[str, Any]]) -> list[str]:
    labels = _label_set(data_classes)
    actions = []
    if labels & {"cloud_access_key", "cloud_metadata"}:
        actions.append("Rotate exposed cloud credentials and review IAM permissions for the affected identity.")
        actions.append("Block metadata access from application request paths unless explicitly required.")
    if "application_secret" in labels:
        actions.append("Rotate exposed application, API, signing, and database secrets.")
        actions.append("Move runtime secrets out of web-readable paths and response-generating templates.")
    if "filesystem_identity_file" in labels:
        actions.append("Patch the file-read primitive and deny traversal to host configuration files.")
    if "session_or_jwt" in labels:
        actions.append("Invalidate exposed sessions/tokens and enforce HttpOnly/SameSite/context binding.")
    if labels & {"aspm_canary", "personal_data"}:
        actions.append("Trace the vulnerable route to the data access layer and enforce object-level authorization.")
    if "database_metadata" in labels:
        actions.append("Disable verbose SQL errors and restrict database account privileges.")
    if not actions:
        actions.append("Retest with authenticated canary records for stronger exposure proof.")
    actions.append("Add a regression test that asserts the same vector no longer returns sensitive classes.")
    return list(dict.fromkeys(actions))


def assess_deep_exfiltration(vuln_type: str, payload: str, response: Any) -> dict[str, Any]:
    """Classify exposed data classes from a live verified response."""
    text = _response_text(response)
    data_classes = []
    score = 0

    for data_class in DATA_CLASS_PATTERNS:
        matches = []
        for pattern in data_class["patterns"]:
            matches.extend(_match_pattern(pattern, text))
        if not matches:
            continue

        unique_matches = list(dict.fromkeys(matches))
        count = len(unique_matches)
        severity = data_class["severity"]
        score += SEVERITY_POINTS[severity] + min(count, 5)
        first_match = unique_matches[0]
        data_classes.append({
            "label": data_class["label"],
            "severity": severity,
            "count": count,
            "impact": data_class["impact"],
            "proof_fingerprint": _proof_fingerprint(first_match),
            "proof_length": len(first_match),
        })

    if response is not None and getattr(response, "status_code", 0) == 200 and data_classes:
        score += 8
    if "sql" in vuln_type.lower() and any(item["label"] == "database_metadata" for item in data_classes):
        score += 8
    if any(token in vuln_type.lower() for token in ("lfi", "path traversal", "file")) and any(
        item["label"] == "filesystem_identity_file" for item in data_classes
    ):
        score += 8
    if "ssrf" in vuln_type.lower() and any(item["label"] in ("cloud_metadata", "internal_service") for item in data_classes):
        score += 8

    score = min(score, 100)
    total_matches = sum(item["count"] for item in data_classes)
    response_kb = max(len(text.encode("utf-8", errors="ignore")) / 1024, 1)
    canary_hits = [item for item in data_classes if item["label"] == "aspm_canary"]
    return {
        "mode": "Deep Exfiltration",
        "payload": payload,
        "status_code": getattr(response, "status_code", None) if response is not None else None,
        "response_bytes_reviewed": len(text.encode("utf-8", errors="ignore")),
        "data_classes": sorted(data_classes, key=lambda item: SEVERITY_POINTS[item["severity"]], reverse=True),
        "exposure_score": score,
        "exposure_level": _level_for_score(score),
        "sensitive_density_per_kb": round(total_matches / response_kb, 2),
        "canary_hits": canary_hits,
        "blast_radius": _build_blast_radius(data_classes, score),
        "impact_paths": _build_impact_paths(data_classes, vuln_type),
        "priority_actions": _build_priority_actions(data_classes),
        "response_fingerprint": _proof_fingerprint(text) if text else None,
    }
