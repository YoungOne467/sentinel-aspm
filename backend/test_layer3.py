"""Quick functional test for Layer 3 safeguards."""
import json
import sys
sys.path.insert(0, ".")

from core.cognitive_engine import count_tokens, truncate_telemetry_to_budget, validate_sql_payload

# ─── Test 1: Token counting ─────────────────────────────────────────────────────
print("=== Test 1: Token Counting ===")
tokens = count_tokens("Hello, world!")
print(f"  'Hello, world!' = {tokens} tokens")
assert tokens > 0, "Token count should be positive"
print("  PASS")

# ─── Test 2: Truncation under budget ────────────────────────────────────────────
print("\n=== Test 2: Telemetry under budget (no truncation) ===")
small_telemetry = {
    "target": {"host": "example.com", "port": 443, "tech_stack": [], "known_cves": [], "notes": ""},
    "endpoints": [{"url": "/api/v1/login", "method": "POST", "status_code": 200, "tech_stack": ["Express"]}]
}
result = truncate_telemetry_to_budget(small_telemetry, budget=14000)
assert len(result["endpoints"]) == 1, "No endpoints should be removed for small telemetry"
print("  PASS — no endpoints removed")

# ─── Test 3: Truncation over budget ─────────────────────────────────────────────
print("\n=== Test 3: Telemetry over budget (truncation required) ===")
# Create a large telemetry object
large_telemetry = {
    "target": {"host": "example.com", "port": 443, "tech_stack": [], "known_cves": [], "notes": ""},
    "endpoints": [
        {"url": f"/api/endpoint_{i}", "method": "GET", "status_code": 200, "tech_stack": ["Django", "PostgreSQL"]}
        for i in range(2000)  # This will definitely exceed 14k tokens
    ]
}
before_count = len(large_telemetry["endpoints"])
result = truncate_telemetry_to_budget(large_telemetry, budget=500)  # Very tight budget
after_count = len(result["endpoints"])
print(f"  Endpoints before: {before_count}, after: {after_count}")
assert after_count < before_count, "Endpoints should have been truncated"
print("  PASS — endpoints truncated to fit budget")

# ─── Test 4: SQL payload validation (valid SQL) ─────────────────────────────────
print("\n=== Test 4: SQL Payload Validation ===")
# Non-SQL payload should pass through
assert validate_sql_payload("../../../etc/passwd") is True, "Non-SQL payload should pass"
print("  Non-SQL payload: PASS (allowed through)")

# Valid SQL payload should pass (only PRS parse errors block, not cosmetic rules)
result_sql = validate_sql_payload("SELECT 1")
print(f"  'SELECT 1' validated: {result_sql}")
assert result_sql is True, "Valid SQL 'SELECT 1' should pass (only parse errors block)"
print("  Valid SQL: PASS (allowed through)")

# Definitely malformed SQL — should be rejected due to PRS parse errors
result_bad = validate_sql_payload("SELECT * FROM; DROP TABLE--")
print(f"  Malformed SQL validated: {result_bad}")
assert result_bad is False, "Malformed SQL should be rejected"
print("  Malformed SQL: PASS (rejected)")

# ─── Test 5: CognitiveEngineService instantiation ────────────────────────────────
print("\n=== Test 5: CognitiveEngineService instantiation ===")
from core.cognitive_engine import CognitiveEngineService
svc = CognitiveEngineService()
assert hasattr(svc, "_instructor_client"), "Should have instructor client"
assert hasattr(svc, "_openai_client"), "Should have openai client"
print("  PASS — instructor client initialized")

print("\n[OK] All Layer 3 safeguard tests passed!")
