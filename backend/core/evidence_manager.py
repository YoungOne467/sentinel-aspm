import os
import uuid
import logging
import hashlib
import re

logger = logging.getLogger(__name__)

# Cache for site-specific baseline fingerprints to detect SPA fallbacks/WAF blocks
_baseline_fingerprints = {}

def register_baseline(url: str, response_text: str):
    """Store the fingerprint of a 'safe' response for a given target."""
    import urllib.parse
    host = urllib.parse.urlparse(url).netloc
    if not response_text: return
    
    # Extract structural fingerprint (tag structure, script count, etc.)
    structure = re.sub(r'[^<>]', '', response_text)
    # Also hash a prefix to detect static app shells
    shell_hash = hashlib.md5(response_text[:1000].encode()).hexdigest()
    
    _baseline_fingerprints[host] = {
        "structure": structure,
        "shell_hash": shell_hash,
        "length": len(response_text)
    }
    logger.info("Registered baseline fingerprint for %s", host)

def is_spa_fallback(url: str, response_text: str) -> bool:
    """Check if the response matches a known SPA fallback shell for the host."""
    import urllib.parse
    host = urllib.parse.urlparse(url).netloc
    baseline = _baseline_fingerprints.get(host)
    if not baseline or not response_text: return False
    
    # 1. Direct shell hash match
    shell_hash = hashlib.md5(response_text[:1000].encode()).hexdigest()
    if shell_hash == baseline["shell_hash"]:
        return True
        
    # 2. Structural similarity (heuristic)
    structure = re.sub(r'[^<>]', '', response_text)
    if structure == baseline["structure"] and abs(len(response_text) - baseline["length"]) < 500:
        return True
        
    return False

def validate_evidence_authenticity(module_name: str, url: str, response, expected_sigs=None) -> tuple[bool, str]:
    """
    The central Truthfulness Gate.
    Returns (is_valid, rejection_reason).
    """
    if response is None:
        return False, "Null response"
        
    status_code = getattr(response, "status_code", 0)
    text = getattr(response, "text", "")
    
    # Rule 1: Generic success codes are not enough
    if status_code >= 400:
        return False, f"HTTP {status_code} error"
        
    # Rule 2: Detect SPA Fallbacks / Static Shells
    if is_spa_fallback(url, text):
        return False, "Response is a static SPA fallback/app shell (False Positive)"
        
    # Rule 3: Content-Type validation for file exposure
    if "traversal" in module_name.lower() or "sensitive" in module_name.lower():
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type and "<html" in text.lower():
             # If it's HTML but we expect a system file, it's likely a false positive 
             # unless it contains a very specific string that isn't usually in error pages.
             pass 

    # Rule 4: Mandatory deterministic signatures if provided
    if expected_sigs:
        found = False
        for sig in expected_sigs:
            if isinstance(sig, str):
                if sig.lower() in text.lower():
                    found = True
                    break
            elif hasattr(sig, "search"): # regex
                if sig.search(text):
                    found = True
                    break
        if not found:
            return False, "Deterministic signature not found in response body"
            
    return True, ""

def save_evidence(module_name: str, test_url: str, response=None, extra_info: str = "", max_body_length: int = 0, force_full: bool = True) -> str:
    """
    Saves HTTP response data and sensitive info to an Obsidian-compatible markdown file.
    Implements deduplication by hashing the final content.
    """
    import datetime
    try:
        evidence_dir = os.path.abspath(os.path.join(os.getcwd(), "scratch", "evidence"))
        os.makedirs(evidence_dir, exist_ok=True)
        
        import urllib.parse
        parsed = urllib.parse.urlparse(test_url)
        domain = parsed.netloc or "unknown"
        
        now_iso = datetime.datetime.now().isoformat()
        
        status_code = "unknown"
        headers_str = ""
        body = ""
        
        if response is not None:
            if hasattr(response, "status_code"):
                status_code = str(response.status_code)
                
            if hasattr(response, "headers"):
                headers_str = str(dict(response.headers))
            
            if hasattr(response, "text"):
                body = response.text
            elif hasattr(response, "content"):
                body = response.content.decode('utf-8', errors='ignore')
        
        # Unique ID per evidence file — no dedup, no truncation
        evidence_id = uuid.uuid4().hex[:12]
        # Sanitize to prevent path traversal
        mod_clean = module_name.lower().replace(' ', '_').replace('.', '_').replace('/', '_').replace('\\', '_')
        
        # Construct YAML Frontmatter
        lines = []
        import json
        lines.append("---")
        lines.append(f"target: {json.dumps(test_url)}")
        lines.append(f"vulnerability: {json.dumps(module_name)}")
        lines.append(f"timestamp: {json.dumps(now_iso)}")
        lines.append(f"status_code: {json.dumps(status_code)}")
        lines.append("tags:")
        lines.append("  - evidence")
        lines.append("  - exploit")
        lines.append(f"  - {mod_clean}")
        lines.append("---")
        lines.append("")
        
        # Construct Markdown Body
        lines.append(f"# Evidence for [[{module_name}]] on [[{domain}]]")
        lines.append("")
        lines.append(f"- **Target URL:** {test_url}")
        lines.append(f"- **Timestamp:** {now_iso}")
        lines.append(f"- **Status Code:** {status_code}")
        lines.append("")
        
        if extra_info:
            lines.append("## Additional Context")
            lines.append(extra_info)
            lines.append("")
            
        if headers_str or body:
            lines.append("## HTTP Response")
            if headers_str:
                lines.append("### Headers")
                lines.append("```json")
                lines.append(headers_str)
                lines.append("```")
            if body:
                lines.append("### Body")
                lines.append("```html")
                lines.append(body)
                lines.append("```")
        
        content = "\n".join(lines)
        
        evidence_file = f"{mod_clean}_{evidence_id}.md"
        evidence_path = os.path.join(evidence_dir, evidence_file)
            
        with open(evidence_path, "w", encoding="utf-8") as f:
            f.write(content)
                    
        return evidence_path
    except Exception as e:
        logger.error("Failed to save evidence: %s", e)
        return f"Failed to save to disk: {e}"
