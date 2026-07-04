"""
Cognitive Fuzzer for Business Logic Research.
Analyzes API responses to identify structural patterns and generate 
payloads for logic-level exploitation (IDOR, Mass Assignment, etc.)
"""

import logging
import json
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class CognitiveFuzzer:
    def __init__(self):
        # Patterns for identifying sensitive ID-like fields
        self.id_patterns = [
            re.compile(r"id$", re.I),
            re.compile(r"uuid$", re.I),
            re.compile(r"user_?id", re.I),
            re.compile(r"account_?id", re.I),
            re.compile(r"owner", re.I)
        ]

    def analyze_api_response(self, body: str) -> Dict[str, Any]:
        """
        Parses an API response to find interesting fields for logic testing.
        """
        try:
            data = json.loads(body)
            interesting_fields = self._extract_fields(data)
            return {
                "format": "JSON",
                "logic_targets": interesting_fields,
                "potential_idor": [f for f in interesting_fields if any(p.search(f) for p in self.id_patterns)]
            }
        except json.JSONDecodeError:
            return {"format": "HTML/Other", "logic_targets": []}

    def _extract_fields(self, data: Any, prefix: str = "") -> List[str]:
        fields = []
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                fields.append(full_key)
                fields.extend(self._extract_fields(v, full_key))
        elif isinstance(data, list) and data:
            fields.extend(self._extract_fields(data[0], prefix))
        return fields

    def generate_logic_payloads(self, target_field: str, current_value: Any) -> List[Dict[str, Any]]:
        """
        Generates invasive mutations for a specific logic target.
        """
        payloads = []
        
        # 1. Parameter Pollution / Mass Assignment
        payloads.append({"action": "Mass Assignment", "payload": {target_field: "admin", "role": "admin", "is_admin": True}})
        
        # 2. Numeric IDOR
        if isinstance(current_value, (int, float)):
            payloads.append({"action": "IDOR (Numeric)", "payload": {target_field: current_value + 1}})
            payloads.append({"action": "IDOR (Negative)", "payload": {target_field: -1}})
            
        # 3. Type Juggling
        payloads.append({"action": "Type Juggling", "payload": {target_field: True}})
        payloads.append({"action": "Array Wrap", "payload": {target_field: [current_value]}})
        
        return payloads

fuzzer = CognitiveFuzzer()
