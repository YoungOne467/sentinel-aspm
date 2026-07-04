"""
Secret and entropy extraction for static assets.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from core.database import AsyncSessionLocal
from core.models import Vulnerability
from core.jwt_downgrader import test_jwt_algorithm_downgrade
from core.attack_chainer import exploit_context

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Stripe Secret Key": re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "JWT": re.compile(r"\beyJh[0-9A-Za-z_\-]+?\.[0-9A-Za-z_\-]+(?:\.[0-9A-Za-z_\-]+)?\b"),
}
HIGH_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9_\-+/=]{21,}\b")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_secrets(body_text: str, file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(body_text or ""):
            value = match.group(0)
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append(build_secret_finding(secret_type, value, body_text, match.start(), match.end(), file_path))

    for match in HIGH_ENTROPY_TOKEN.finditer(body_text or ""):
        value = match.group(0)
        if any(value == existing["secret"] or value in existing["secret"] or existing["secret"] in value for existing in findings):
            continue
        entropy = shannon_entropy(value)
        if entropy >= 4.2:
            findings.append(
                build_secret_finding(
                    "High-Entropy Secret",
                    value,
                    body_text,
                    match.start(),
                    match.end(),
                    file_path,
                    entropy=entropy,
                )
            )
    return findings[:50]


def build_secret_finding(
    secret_type: str,
    value: str,
    body_text: str,
    start: int,
    end: int,
    file_path: str,
    *,
    entropy: float | None = None,
) -> dict[str, Any]:
    left = max(0, start - 40)
    right = min(len(body_text), end + 40)
    context = body_text[left:right].replace("\n", " ").strip()
    evidence = f"{secret_type} exposed in {file_path}: {value}. Context: ...{context}..."
    if entropy is not None:
        evidence += f" Entropy: {entropy:.2f}."
    return {
        "type": secret_type,
        "secret": value,
        "file_path": file_path,
        "context": context,
        "entropy": entropy,
        "evidence": evidence,
    }


async def analyze_static_asset_for_secrets(
    body_text: str,
    file_path: str,
    *,
    target_id: str | None = None,
    crawled_url_id: str | None = None,
    source_vuln_id: str | None = None,
) -> list[dict[str, Any]]:
    findings = extract_secrets(body_text, file_path)
    if not findings:
        return []
    for finding in findings:
        finding["source_vuln_id"] = source_vuln_id
        finding["target_id"] = target_id
        exploit_context.save_secret(file_path, finding)
    async with AsyncSessionLocal() as session:
        for finding in findings:
            session.add(
                Vulnerability(
                    crawled_url_id=crawled_url_id,
                    target_id=target_id,
                    vuln_type="Exposed Secret",
                    severity="critical",
                    title=f"Critical exposed secret: {finding['type']}",
                    description="A static asset exposed a credential, token, or high-entropy secret.",
                    evidence=finding["evidence"],
                    payload=finding["secret"],
                    source="secret_extractor",
                    raw_data=finding,
                    chained_from_vuln_id=source_vuln_id,
                )
            )
        await session.commit()
    for finding in findings:
        if finding["type"] == "JWT":
            try:
                await test_jwt_algorithm_downgrade(
                    file_path,
                    finding["secret"],
                    target_id=target_id,
                    crawled_url_id=crawled_url_id,
                )
            except Exception:
                pass
    return findings
