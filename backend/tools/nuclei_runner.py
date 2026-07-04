"""
AETHER Nuclei Runner.

Integrates ProjectDiscovery's Nuclei for template-based vulnerability scanning.
Expects the 'nuclei' binary to be available in the system PATH.
"""

import asyncio
import json
import logging
import os
import shutil
import time
import subprocess
from typing import Callable, Awaitable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


async def run_nuclei_scan(
    url: str,
    intensity: str,
    broadcast_cb: Callable[[dict], Awaitable[None]],
) -> list[dict]:
    """
    Execute Nuclei against the target URL.
    Returns a list of findings in the AETHER format.
    """
    findings = []
    start_time = time.monotonic()
    
    await broadcast_cb({"type": "log", "message": "Nuclei Engine: Starting template-based vulnerability scanning..."})
    
    # Check if nuclei is installed
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        await broadcast_cb({
            "type": "log",
            "message": "    ✗ Nuclei binary not found in PATH. Skipping template scanning. Please install it: https://github.com/projectdiscovery/nuclei"
        })
        return []
        
    # Map intensity to severity profiles
    severities = "critical,high"
    if intensity in ("normal", "aggressive", "extreme"):
        severities = "critical,high,medium"
    if intensity in ("aggressive", "extreme"):
        severities = "critical,high,medium,low"
        
    # Build command
    cmd = [
        nuclei_path,
        "-u", url,
        "-severity", severities,
        "-json-export", "-", # Output JSON to stdout
        "-silent", # Don't print banner
        "-disable-update-check"
    ]
    
    if intensity == "stealth":
        cmd.extend(["-rate-limit", "10", "-bulk-size", "5"])
    elif intensity == "normal":
        cmd.extend(["-rate-limit", "50", "-bulk-size", "25"])
    elif intensity == "aggressive":
        cmd.extend(["-rate-limit", "150", "-bulk-size", "50"])
    elif intensity == "extreme":
        cmd.extend(["-rate-limit", "300", "-bulk-size", "100"])
        
    await broadcast_cb({"type": "log", "message": f"    Executing: {' '.join(cmd)}"})
    
    proc_container = [None]
    
    def run_proc():
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc_container[0] = proc
        try:
            stdout, stderr = proc.communicate(timeout=300.0)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise asyncio.TimeoutError()
        except Exception:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
            raise

    try:
        # Offload the blocking process execution to a thread pool
        returncode, stdout, stderr = await asyncio.to_thread(run_proc)
        
        if returncode != 0 and not stdout:
            err = stderr.decode('utf-8', errors='ignore')
            logger.error("Nuclei failed: %s", err)
            await broadcast_cb({"type": "log", "message": f"    ✗ Nuclei execution error (exit {returncode})"})
            return []
            
        # Parse JSON output (one JSON object per line)
        for line in stdout.decode('utf-8', errors='ignore').splitlines():
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info").title()
                
                # Filter out info findings unless extreme
                if severity == "Info" and intensity != "extreme":
                    continue
                    
                finding = {
                    "type": f"Nuclei: {info.get('name', 'Unknown')}",
                    "severity": severity,
                    "module": "nuclei_runner",
                    "vector": f"{data.get('type', 'http').upper()} {data.get('matched-at', '')}",
                    "payload": data.get("matcher-name", ""),
                    "evidence": f"Template: {data.get('template-id')}\nMatched: {data.get('matched-at')}\n\n{data.get('extracted-results', [])}",
                    "description": info.get("description", "Vulnerability detected by Nuclei template."),
                    "confidence": "high",
                    "confidence_score": 0.95,
                    "verification_state": "verified",
                    "remediation": info.get("remediation", "Review the finding and apply necessary patches."),
                    "patch_provided": True,
                    "target_url": data.get("matched-at", url),
                    "cwe": info.get("classification", {}).get("cwe-id", []),
                }
                
                findings.append(finding)
                await broadcast_cb({"type": "log", "message": f"    🔴 NUCLEI FOUND: {info.get('name')} ({severity})"})
                
            except json.JSONDecodeError:
                continue
                
    except asyncio.CancelledError:
        logger.warning("Nuclei execution cancelled.")
        await broadcast_cb({"type": "log", "message": "    ⚠ Nuclei execution cancelled."})
        proc = proc_container[0]
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        raise
    except asyncio.TimeoutError:
        logger.warning("Nuclei execution timed out.")
        await broadcast_cb({"type": "log", "message": "    ⚠ Nuclei execution timed out."})
    except Exception as e:
        logger.error("Nuclei execution failed: %s", e)
        await broadcast_cb({"type": "log", "message": f"    ✗ Nuclei exception: {e}"})

    elapsed = time.monotonic() - start_time
    await broadcast_cb({
        "type": "log",
        "message": f"    Nuclei Engine Complete ({elapsed:.1f}s): {len(findings)} findings."
    })
    
    return findings
