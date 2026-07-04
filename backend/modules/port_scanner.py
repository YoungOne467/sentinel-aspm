"""
TCP Port Scanner Module.
Performs async TCP connect scanning against common service ports.
Identifies exposed services and flags high-risk ports.
"""
import asyncio
import logging
from core.evidence_manager import save_evidence

from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Ports grouped by risk and common service
HIGH_RISK_PORTS = {
    21: ("FTP", "Critical", "FTP often allows anonymous access or uses plaintext credentials."),
    22: ("SSH", "Info", "SSH is expected but should use key-based auth only."),
    23: ("Telnet", "Critical", "Telnet transmits credentials in plaintext. Must be disabled."),
    25: ("SMTP", "Medium", "Open SMTP relay can be abused for spam."),
    53: ("DNS", "Low", "DNS service exposed. Check for zone transfer vulnerabilities."),
    110: ("POP3", "Medium", "POP3 transmits credentials in plaintext."),
    135: ("RPC", "High", "Windows RPC exposed. Common target for exploits."),
    139: ("NetBIOS", "High", "NetBIOS exposed. Can leak system information."),
    143: ("IMAP", "Medium", "IMAP without TLS transmits credentials in plaintext."),
    445: ("SMB", "Critical", "SMB exposed to internet. EternalBlue and other exploits."),
    1433: ("MSSQL", "Critical", "Microsoft SQL Server exposed. Brute-force and injection risk."),
    1521: ("Oracle DB", "Critical", "Oracle Database exposed. Brute-force risk."),
    2049: ("NFS", "High", "NFS exposed. Can leak filesystem contents."),
    3306: ("MySQL", "Critical", "MySQL exposed to internet. Brute-force and data theft risk."),
    3389: ("RDP", "Critical", "Remote Desktop exposed. BlueKeep and brute-force risk."),
    5432: ("PostgreSQL", "Critical", "PostgreSQL exposed. Brute-force risk."),
    5900: ("VNC", "Critical", "VNC exposed. Often weak/no authentication."),
    5984: ("CouchDB", "High", "CouchDB exposed. Often no authentication by default."),
    6379: ("Redis", "Critical", "Redis exposed. Usually no authentication. Full server takeover possible."),
    8080: ("HTTP-Alt", "Low", "Alternative HTTP port. Check for admin panels or debug interfaces."),
    8443: ("HTTPS-Alt", "Low", "Alternative HTTPS port."),
    8888: ("HTTP-Dev", "Medium", "Common development server port. May have debug features."),
    9200: ("Elasticsearch", "Critical", "Elasticsearch exposed. No default authentication. Full data access."),
    9300: ("ES-Transport", "Critical", "Elasticsearch transport port."),
    11211: ("Memcached", "High", "Memcached exposed. No authentication. Data leakage risk."),
    27017: ("MongoDB", "Critical", "MongoDB exposed. Often no authentication. Full database access."),
    27018: ("MongoDB-Shard", "Critical", "MongoDB shard server exposed."),
}

STANDARD_PORTS = {
    80: ("HTTP", "Info", "Standard HTTP port."),
    443: ("HTTPS", "Info", "Standard HTTPS port."),
    8000: ("HTTP-Dev", "Low", "Common development server port."),
}

ALL_SCAN_PORTS = {**STANDARD_PORTS, **HIGH_RISK_PORTS}

async def _scan_port(host, port, timeout=3):
    """Attempt a TCP connection to a single port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        # Try to grab a banner
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            banner = data.decode(errors="replace").strip()[:200]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True, banner
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False, ""

async def run_port_scan(url, intensity, broadcast_cb):
    """Run TCP port scanning against the target."""
    await broadcast_cb({"type":"log","message":"Port Scanner: Resolving target host..."})
    parsed = urlparse(url)
    host = parsed.hostname
    findings = []

    if not host:
        await broadcast_cb({"type":"log","message":"Port Scanner: Could not resolve hostname."})
        return findings

    # Select ports based on intensity
    if intensity == "stealth":
        ports = list(STANDARD_PORTS.keys()) + [22, 3306, 5432, 6379, 27017]
    elif intensity == "normal":
        ports = list(ALL_SCAN_PORTS.keys())
    else:  # aggressive
        ports = list(ALL_SCAN_PORTS.keys()) + list(range(1, 1024))  # Top 1024
        ports = list(set(ports))

    await broadcast_cb({"type":"log","message":f"Port Scanner: Scanning {len(ports)} ports on {host}..."})

    # Scan in batches to avoid overwhelming the target
    batch_size = 50
    open_ports = []
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i+batch_size]
        tasks = [_scan_port(host, p) for p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, tuple) and r[1]:
                port_num, is_open, banner = r
                open_ports.append((port_num, banner))
                info = ALL_SCAN_PORTS.get(port_num, ("Unknown", "Info", "Unknown service."))
                await broadcast_cb({"type":"log","message":f"  ✓ Port {port_num} OPEN — {info[0]}" + (f" (Banner: {banner[:60]})" if banner else "")})
        if (i + batch_size) % 200 == 0:
            await broadcast_cb({"type":"log","message":f"Port Scanner: Scanned {min(i+batch_size, len(ports))}/{len(ports)} ports..."})

    # Generate findings for risky open ports
    for port_num, banner in open_ports:
        info = ALL_SCAN_PORTS.get(port_num, ("Unknown", "Info", "Unknown service on this port."))
        service_name, severity, desc = info
        if severity in ("Critical", "High", "Medium"):
            finding = {
                "type": f"Exposed Service: {service_name} (Port {port_num})",
                "severity": severity,
                "vector": f"TCP Port {port_num}",
                "payload": "TCP connect scan",
                "evidence": save_evidence(__name__, locals().get("test_url") or locals().get("url") or "unknown_url", locals().get("resp") or locals().get("response") or locals().get("r") or locals().get("result") or locals().get("resp2") or locals().get("res"), extra_info=f"Port {port_num} is open" + (f". Banner: {banner[:100]}" if banner else "")),
                "description": desc,
                "remediation": f"Restrict access to port {port_num} using firewall rules (iptables/security groups). Only allow connections from trusted IP ranges. Consider using VPN or SSH tunneling for administrative access.",
                "patch_provided": True,
            }
            findings.append(finding)

    await broadcast_cb({"type":"log","message":f"Port Scanner: Scan complete. {len(open_ports)} open port(s) found."})

    if not findings:
        await broadcast_cb({"type":"log","message":"Port Scanner: No high-risk exposed ports detected."})
    return findings
