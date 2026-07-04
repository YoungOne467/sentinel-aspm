import httpx
import logging
import urllib.parse
from typing import List

logger = logging.getLogger("sentinel.osint_fetcher")

async def fetch_wayback_subdomains(domain: str) -> List[str]:
    """
    Queries Wayback Machine CDX API to fetch legacy URLs and extract subdomains.
    """
    subdomains = set()
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    # First row is header: ["original"]
                    for row in data[1:]:
                        if row and len(row) > 0:
                            orig_url = row[0]
                            try:
                                parsed = urllib.parse.urlparse(orig_url)
                                netloc = parsed.netloc.split(":")[0]  # remove port if any
                                if netloc.endswith(domain):
                                    subdomains.add(netloc.lower())
                            except Exception:
                                pass
    except Exception as e:
        logger.debug("Failed to fetch Wayback subdomains for %s: %s", domain, e)
    return list(subdomains)
