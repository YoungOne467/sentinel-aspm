import sys
sys.path.insert(0, ".")

import pytest
from core.llm_adapter import compress_http_response, ExploitAnalysisResponse, ExecutableAction

def test_compress_http_response():
    # Test typical HTML document compression
    raw_html = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Thu, 11 Jun 2026 05:00:00 GMT\r\n"
        "Server: Apache\r\n"
        "X-Powered-By: PHP\r\n"
        "Content-Length: 150\r\n\r\n"
        "<html><head><style>body { color: red; }</style></head><body>"
        "<!-- comment -->"
        "<h1>Vulnerable API</h1>"
        "<script>alert(1);</script>"
        "</body></html>"
    )
    compressed = compress_http_response(raw_html)
    assert "Date:" not in compressed
    assert "Server:" not in compressed
    assert "X-Powered-By:" not in compressed
    assert "style" not in compressed
    assert "script" not in compressed
    assert "comment" not in compressed
    assert "Vulnerable API" in compressed

def test_pydantic_schema_validation():
    action = ExecutableAction(
        action_type="curl",
        title="Check SSRF endpoint",
        command="curl -X GET http://127.0.0.1:8000/api/health"
    )
    
    response = ExploitAnalysisResponse(
        summary="Verified SSRF vulnerability via local health endpoint access.",
        vulnerability_detected=True,
        risk_score=8.5,
        remediation_steps=["Restrict internal network access from web containers."],
        actions=[action]
    )
    
    dumped = response.model_dump()
    assert dumped["vulnerability_detected"] is True
    assert dumped["risk_score"] == 8.5
    assert len(dumped["actions"]) == 1
    assert dumped["actions"][0]["action_type"] == "curl"
    
    # Verify validation of dumped object
    validated = ExploitAnalysisResponse.model_validate(dumped)
    assert validated.risk_score == 8.5
    assert validated.actions[0].command == "curl -X GET http://127.0.0.1:8000/api/health"

if __name__ == "__main__":
    test_compress_http_response()
    test_pydantic_schema_validation()
    print("[OK] AI Engine adapter unit tests passed successfully!")
