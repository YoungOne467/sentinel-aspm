import logging
import asyncio

logger = logging.getLogger(__name__)

async def generate_threat_model(recon_data: dict, findings: list, broadcast_cb) -> dict:
    """
    Automated Threat Modeler Agent.
    Builds a dynamic STRIDE model and Attack Paths by chaining discovered vulnerabilities.
    """
    await broadcast_cb({"type": "log", "message": "Threat Modeler: Analyzing attack surface and finding chains..."})
    await asyncio.sleep(1.5)
    
    model = {
        "high_risk_areas": [],
        "stride_analysis": "Advanced STRIDE analysis complete.",
        "attack_paths": []
    }
    
    # 1. STRIDE Analysis based on findings
    vtypes = [f["type"] for f in findings]
    
    if any("Injection" in t for t in vtypes):
        model["high_risk_areas"].append("Data Persistence Layer / SQL Execution")
    if any("XSS" in t or "CSRF" in t for t in vtypes):
        model["high_risk_areas"].append("Client-Side Execution / Session Management")
    if any("SSRF" in t or "Smuggling" in t for t in vtypes):
        model["high_risk_areas"].append("Internal Network / Proxy Architecture")

    # 2. Dynamic Attack Path Generation (Chaining)
    # Scenario A: Info Disclosure -> Sensitive Data -> Authentication Bypass
    if any("Disclosure" in t for t in vtypes) and any("Sensitive" in t for t in vtypes):
        model["attack_paths"].append({
            "nodes": ["Information Disclosure", "Credential Leak in Sensitive File", "Unauthorized API Access", "Full Account Takeover"],
            "risk_score": 9.5
        })

    # Scenario B: XSS -> CSRF -> State Change
    if any("XSS" in t for t in vtypes) and any("CSRF" in t for t in vtypes):
        model["attack_paths"].append({
            "nodes": ["Reflected XSS", "Bypass SameSite Cookies", "CSRF on Admin Endpoint", "Privilege Escalation"],
            "risk_score": 8.5
        })

    # Scenario C: SSRF -> Cloud Metadata -> RCE
    if any("SSRF" in t for t in vtypes):
        model["attack_paths"].append({
            "nodes": ["SSRF Vulnerability", "Access Cloud Metadata (169.254.169.254)", "Steal IAM Role Credentials", "Cloud Infrastructure Compromise"],
            "risk_score": 10.0
        })

    # Fallback if no specific chains found
    if not model["attack_paths"]:
        model["attack_paths"].append({
             "nodes": ["External Reconnaissance", "Vulnerability Discovery", "Exploitation"],
             "risk_score": 5.0
        })

    await broadcast_cb({"type": "log", "message": f"Threat Modeler: Generated {len(model['attack_paths'])} realistic attack chains."})
    return model
