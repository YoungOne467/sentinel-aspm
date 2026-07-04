import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ReflectionContext:
    def __init__(self, type: str, parent_tag: str = "", attribute: str = "", raw_snippet: str = ""):
        self.type = type # html_text, html_attr, js_string, js_var, sql_query, shell_cmd
        self.parent_tag = parent_tag
        self.attribute = attribute
        self.raw_snippet = raw_snippet

    def __repr__(self):
        return f"Context({self.type}, tag={self.parent_tag}, attr={self.attribute})"

class ARESContextEngine:
    """
    Analyzes responses to determine the exact reflection context of a payload.
    This allows ARES to generate precise breakout characters.
    """
    
    def __init__(self):
        self.sql_error_patterns = {
            "mysql": [r"SQL syntax.*?MySQL", r"valid MySQL result", r"MySqlClient\."],
            "postgresql": [r"PostgreSQL.*?ERROR", r"psycopg2\.ProgrammingError", r"operator does not exist"],
            "mssql": [r"Microsoft OLE DB Provider for SQL Server", r"Unclosed quotation mark after the character string"],
            "oracle": [r"ORA-\d{5}", r"Oracle error", r"TNS-"]
        }

    def identify_context(self, response_body: str, marker: str) -> Optional[ReflectionContext]:
        """
        Locates the marker in the response and analyzes its surrounding environment.
        """
        if marker not in response_body:
            return None
            
        # Find the reflection in a small window
        index = response_body.find(marker)
        window_start = max(0, index - 100)
        window_end = min(len(response_body), index + len(marker) + 100)
        snippet = response_body[window_start:window_end]
        
        # 1. Check for Script context
        if "<script" in snippet.lower() and "</script>" not in snippet[snippet.lower().find("<script"):index]:
            if "'" in snippet[max(0, snippet.rfind("<script")):index] or "\"" in snippet[max(0, snippet.rfind("<script")):index]:
                return ReflectionContext("js_string", raw_snippet=snippet)
            return ReflectionContext("js_var", raw_snippet=snippet)
            
        # 2. Check for HTML Attribute context
        attr_match = re.search(r'<[a-z0-9]+\s+[^>]*?([a-z-]+)=["\'][^>]*?' + re.escape(marker), snippet, re.I)
        if attr_match:
            return ReflectionContext("html_attr", attribute=attr_match.group(1), raw_snippet=snippet)
            
        # 3. Check for HTML Tag context
        tag_match = re.search(r'<([a-z0-9]+)>[^<]*?' + re.escape(marker), snippet, re.I)
        if tag_match:
            return ReflectionContext("html_text", parent_tag=tag_match.group(1), raw_snippet=snippet)
            
        return ReflectionContext("html_text", raw_snippet=snippet)

    def analyze_db_flavor(self, response_body: str) -> Optional[str]:
        """
        Determines the database flavor based on error messages.
        """
        for flavor, patterns in self.sql_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.I):
                    return flavor
        return None

context_engine = ARESContextEngine()
