"""Target validation policy for scan requests."""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse, urlunparse


class TargetPolicyError(ValueError):
    """Raised when a target URL violates platform scan policy."""


ALLOWED_SCHEMES = {"http", "https"}


def _private_targets_allowed() -> bool:
    return os.getenv("ASPM_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {"1", "true", "yes"}


def normalize_target_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise TargetPolicyError("Target URL is required.")

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetPolicyError("Target URL must use http or https.")
    if not parsed.netloc:
        raise TargetPolicyError("Target URL must include a hostname.")

    return urlunparse(parsed._replace(scheme=parsed.scheme.lower()))


def _resolve_host_ips(hostname: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise TargetPolicyError(f"Could not resolve target host: {hostname}") from exc

    resolved = []
    for entry in addresses:
        ip = entry[4][0]
        try:
            resolved.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    return list(dict.fromkeys(resolved))


def _is_public_address(address: ipaddress._BaseAddress) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def validate_scan_target(raw_url: str) -> str:
    url = normalize_target_url(raw_url)
    if _private_targets_allowed():
        return url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise TargetPolicyError("Target URL must include a hostname.")

    resolved = _resolve_host_ips(hostname)
    if not resolved:
        raise TargetPolicyError(f"Could not resolve target host: {hostname}")

    if not all(_is_public_address(address) for address in resolved):
        raise TargetPolicyError(
            "Target resolves to a private, loopback, link-local, reserved, or otherwise non-public address. "
            "Set ASPM_ALLOW_PRIVATE_TARGETS=1 for an authorized lab target."
        )

    return url
