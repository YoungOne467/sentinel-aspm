"""
Fingerprint Engine — technical asset correlation via favicon hashing and TLS certificates.
Groups infrastructure sharing identical cryptographic fingerprints into clusters.
"""
import hashlib
import logging
import struct
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

import httpx
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.models import InfraCluster, gen_id

logger = logging.getLogger(__name__)


# ─── MurmurHash3 (32-bit, x86) ────────────────────────────────────────────────

def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 32-bit implementation."""
    length = len(data)
    h1 = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    rounded_end = (length & 0xFFFFFFFC)
    mask32 = 0xFFFFFFFF

    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & mask32
        k1 = ((k1 << 15) | (k1 >> 17)) & mask32
        k1 = (k1 * c2) & mask32
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & mask32
        h1 = (h1 * 5 + 0xE6546B64) & mask32

    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & mask32
        k1 = ((k1 << 15) | (k1 >> 17)) & mask32
        k1 = (k1 * c2) & mask32
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & mask32
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & mask32
    h1 ^= (h1 >> 16)

    # Return signed int for Shodan compatibility
    return struct.unpack("i", struct.pack("I", h1))[0]


class FingerprintEngine:
    """Captures technical asset markers and clusters infrastructure."""

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout

    async def fingerprint_host(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Collect fingerprints for a host:
          - Favicon MMH3 hash
          - TLS certificate Subject Alternative Names
          - Server header
        """
        result = {
            "host": host,
            "favicon_hash": None,
            "tls_sans": [],
            "server_header": None,
        }

        # Favicon hash
        favicon_hash = await self._get_favicon_hash(host)
        if favicon_hash is not None:
            result["favicon_hash"] = str(favicon_hash)

        # TLS certificate SANs
        sans = await self._get_tls_sans(host, port)
        result["tls_sans"] = sans

        # Server header
        server = await self._get_server_header(host)
        result["server_header"] = server

        # Cluster by fingerprints
        if result["favicon_hash"]:
            await self._update_cluster(
                "favicon_mmh3", result["favicon_hash"], host,
            )
        for san in sans:
            await self._update_cluster("tls_san", san, host)

        return result

    async def _get_favicon_hash(self, host: str) -> Optional[int]:
        """Fetch /favicon.ico and compute MMH3 hash."""
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout, verify=False, follow_redirects=True,
                ) as client:
                    resp = await client.get(f"{scheme}://{host}/favicon.ico")
                    if resp.status_code == 200 and len(resp.content) > 0:
                        import base64
                        encoded = base64.encodebytes(resp.content)
                        return _mmh3_32(encoded)
            except Exception:
                continue
        return None

    async def _get_tls_sans(self, host: str, port: int = 443) -> List[str]:
        """Extract Subject Alternative Names from TLS certificate."""
        import ssl
        import asyncio

        sans: List[str] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self._timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    for field_type, field_value in cert.get("subjectAltName", []):
                        if field_type == "DNS":
                            sans.append(field_value)
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug("TLS SAN extraction failed for %s:%d: %s", host, port, e)
        return sans

    async def _get_server_header(self, host: str) -> Optional[str]:
        """Get the Server HTTP header."""
        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout, verify=False, follow_redirects=False,
                ) as client:
                    resp = await client.head(f"{scheme}://{host}/")
                    return resp.headers.get("server")
            except Exception:
                continue
        return None

    async def _update_cluster(self, fp_type: str, fp_value: str, host: str):
        """Add host to an existing cluster or create a new one."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(InfraCluster).where(
                    InfraCluster.fingerprint_type == fp_type,
                    InfraCluster.fingerprint_value == fp_value,
                )
            )
            cluster = result.scalar_one_or_none()

            if cluster:
                members = cluster.members or []
                if host not in members:
                    members.append(host)
                    cluster.members = members
                    cluster.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            else:
                cluster = InfraCluster(
                    id=gen_id(),
                    cluster_name=f"{fp_type}:{fp_value[:16]}",
                    fingerprint_type=fp_type,
                    fingerprint_value=fp_value,
                    members=[host],
                )
                session.add(cluster)
            await session.commit()

    async def get_clusters(self) -> List[Dict[str, Any]]:
        """Get all infrastructure clusters."""
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(InfraCluster))
            return [
                {
                    "id": c.id,
                    "cluster_name": c.cluster_name,
                    "fingerprint_type": c.fingerprint_type,
                    "fingerprint_value": c.fingerprint_value,
                    "members": c.members or [],
                    "notes": c.notes,
                    "updated_at": c.updated_at.isoformat() if c.updated_at else None,
                }
                for c in result.scalars().all()
            ]


# Global singleton
fingerprint_engine = FingerprintEngine()
