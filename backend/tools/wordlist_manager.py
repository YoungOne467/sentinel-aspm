"""
AETHER Wordlist Manager

Downloads, caches, and manages wordlists (e.g., SecLists) for fuzzing 
and brute-force discovery tools like ffuf.
"""

import asyncio
import hashlib
import logging
import os
import zipfile
from pathlib import Path
from typing import Callable, Awaitable

import httpx

logger = logging.getLogger(__name__)

WORDLISTS_DIR = Path(__file__).parent.parent / "scratch" / "wordlists"

# Minimal required wordlists to save space and time, derived from SecLists
ESSENTIAL_WORDLISTS = {
    "discovery_web_content": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "filename": "raft-small-directories.txt"
    },
    "discovery_web_files": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt",
        "filename": "raft-small-files.txt"
    },
    "discovery_api": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "filename": "api-endpoints.txt"
    },
    "fuzzing_parameters": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
        "filename": "burp-parameter-names.txt"
    }
}


async def ensure_wordlists(broadcast_cb: Callable[[dict], Awaitable[None]] = None) -> dict[str, str]:
    """
    Ensure essential wordlists are downloaded.
    Returns a dictionary mapping wordlist logical names to their absolute file paths.
    """
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    paths = {}
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for name, info in ESSENTIAL_WORDLISTS.items():
            file_path = WORDLISTS_DIR / info["filename"]
            paths[name] = str(file_path.absolute())
            
            if file_path.exists() and file_path.stat().st_size > 100:
                continue # Already downloaded and valid
                
            if broadcast_cb:
                await broadcast_cb({"type": "log", "message": f"    Downloading wordlist: {info['filename']}..."})
                
            try:
                resp = await client.get(info["url"])
                resp.raise_for_status()
                with open(file_path, "wb") as f:
                    f.write(resp.content)
            except Exception as e:
                logger.error("Failed to download wordlist %s: %s", info['filename'], e)
                if broadcast_cb:
                    await broadcast_cb({"type": "log", "message": f"    ✗ Failed to download {info['filename']}: {e}"})
                paths[name] = "" # Mark as failed
                
    return paths


def get_wordlist_path(name: str) -> str | None:
    """Get the absolute path to a wordlist by its logical name, if it exists."""
    if name not in ESSENTIAL_WORDLISTS:
        return None
    
    file_path = WORDLISTS_DIR / ESSENTIAL_WORDLISTS[name]["filename"]
    if file_path.exists() and file_path.stat().st_size > 100:
        return str(file_path.absolute())
    return None
