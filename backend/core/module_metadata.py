"""Standards metadata for scanner findings.

The scanner's detection logic remains module-specific, but final findings should
carry stable references that let analysts connect evidence to OWASP WSTG and CWE
language without every module duplicating that mapping.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


REFERENCE_CATALOG: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "wstg": "WSTG-INPV-05",
        "cwe": ["CWE-89"],
        "owasp_category": "Injection",
        "references": [
            {
                "title": "OWASP WSTG: Testing for SQL Injection",
                "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
            }
        ],
    },
    "xss": {
        "wstg": "WSTG-INPV-01",
        "cwe": ["CWE-79"],
        "owasp_category": "Cross-Site Scripting",
        "references": [
            {
                "title": "OWASP WSTG: Testing for Reflected Cross Site Scripting",
                "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
            }
        ],
    },
    "ssti": {
        "wstg": "WSTG-INPV-18",
        "cwe": ["CWE-1336"],
        "owasp_category": "Server-Side Template Injection",
        "references": [
            {
                "title": "OWASP WSTG: Testing for Server-side Template Injection",
                "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
            }
        ],
    },
    "ssrf": {
        "wstg": "WSTG-INPV-19",
        "cwe": ["CWE-918"],
        "owasp_category": "Server-Side Request Forgery",
        "references": [
            {
                "title": "OWASP WSTG: Testing for Server-Side Request Forgery",
                "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
            },
            {
                "title": "OWASP Cheat Sheet: SSRF Prevention",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            },
        ],
    },
    "request_smuggling": {
        "wstg": "WSTG-INPV-16",
        "cwe": ["CWE-444"],
        "owasp_category": "HTTP Request Smuggling",
        "references": [
            {
                "title": "OWASP WSTG: Testing for HTTP Request Smuggling",
                "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling",
            }
        ],
    },
    "cache_poisoning": {
        "wstg": "WSTG-CONF",
        "cwe": ["CWE-444", "CWE-525"],
        "owasp_category": "Web Cache Poisoning",
        "references": [
            {
                "title": "PortSwigger: Web Cache Poisoning",
                "url": "https://portswigger.net/web-security/web-cache-poisoning",
            },
            {
                "title": "PortSwigger Research: Practical Web Cache Poisoning",
                "url": "https://portswigger.net/research/practical-web-cache-poisoning",
            },
        ],
    },
    "graphql": {
        "wstg": "WSTG-APIT-01",
        "cwe": ["CWE-200", "CWE-285"],
        "owasp_category": "API Security Misconfiguration",
        "references": [
            {
                "title": "OWASP WSTG: Testing GraphQL",
                "url": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
            },
            {
                "title": "OWASP API Security Top 10 2023",
                "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            },
        ],
    },
    "attack_surface": {
        "wstg": "WSTG-INFO-01",
        "cwe": ["CWE-200"],
        "owasp_category": "Information Gathering / Attack Surface",
        "references": [
            {
                "title": "OWASP WSTG: Conduct Search Engine Discovery Reconnaissance",
                "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
            }
        ],
    },
    "template_probe": {
        "wstg": "WSTG-CONF-05",
        "cwe": ["CWE-200", "CWE-538"],
        "owasp_category": "Security Misconfiguration / Known Exposure",
        "references": [
            {
                "title": "CISA Known Exploited Vulnerabilities Catalog",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            },
            {
                "title": "OWASP API Security Top 10 2023",
                "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            },
        ],
    },
    "authorization": {
        "wstg": "WSTG-ATHZ-02",
        "cwe": ["CWE-285", "CWE-862"],
        "owasp_category": "Broken Access Control",
        "references": [
            {
                "title": "OWASP API1: Broken Object Level Authorization",
                "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            },
            {
                "title": "OWASP API5: Broken Function Level Authorization",
                "url": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
            },
        ],
    },
    "resource_consumption": {
        "wstg": "WSTG-BUSL",
        "cwe": ["CWE-400", "CWE-770"],
        "owasp_category": "Unrestricted Resource Consumption",
        "references": [
            {
                "title": "OWASP API4: Unrestricted Resource Consumption",
                "url": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            }
        ],
    },
    "client_exposure": {
        "wstg": "WSTG-CLNT",
        "cwe": ["CWE-200", "CWE-922"],
        "owasp_category": "Client-Side Exposure",
        "references": [
            {
                "title": "OWASP WSTG: Client-side Testing",
                "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/README",
            }
        ],
    },
    "csrf": {
        "wstg": "WSTG-SESS-05",
        "cwe": ["CWE-352"],
        "owasp_category": "Cross-Site Request Forgery",
        "references": [
            {
                "title": "OWASP WSTG: Testing for Cross Site Request Forgery",
                "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
            }
        ],
    },
    "clickjacking": {
        "wstg": "WSTG-CLNT-09",
        "cwe": ["CWE-1021"],
        "owasp_category": "Clickjacking",
        "references": [
            {
                "title": "OWASP Cheat Sheet: Content Security Policy",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            }
        ],
    },
    "cors": {
        "wstg": "WSTG-CLNT",
        "cwe": ["CWE-942"],
        "owasp_category": "CORS Misconfiguration",
        "references": [
            {
                "title": "OWASP Cheat Sheet: Cross-Origin Resource Sharing",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
            }
        ],
    },
    "headers": {
        "wstg": "WSTG-CONF",
        "cwe": ["CWE-693"],
        "owasp_category": "Security Misconfiguration",
        "references": [
            {
                "title": "OWASP Cheat Sheet: Content Security Policy",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            }
        ],
    },
    "tls": {
        "wstg": "WSTG-CRYP-01",
        "cwe": ["CWE-319", "CWE-326"],
        "owasp_category": "Cryptographic Failures",
        "references": [
            {
                "title": "OWASP Cheat Sheet: Transport Layer Security",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            }
        ],
    },
    "path_traversal": {
        "wstg": "WSTG-INPV-11",
        "cwe": ["CWE-22", "CWE-98"],
        "owasp_category": "Path Traversal / File Inclusion",
        "references": [
            {
                "title": "OWASP WSTG: Input Validation Testing",
                "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README",
            }
        ],
    },
}


MODULE_TO_KEY = {
    "blind_sqli_time": "sql_injection",
    "injection": "sql_injection",
    "nosql_injection": "sql_injection",
    "dom_xss": "xss",
    "ssti_scanner": "ssti",
    "ssti_blind": "ssti",
    "ssti_oast": "ssti",
    "ssrf_oast": "ssrf",
    "ssrf_chaining": "ssrf",
    "cloud_metadata": "ssrf",
    "smb_relay_web": "ssrf",
    "smuggling": "request_smuggling",
    "http_desync_advanced": "request_smuggling",
    "http2_smuggling": "request_smuggling",
    "cache_poisoning": "cache_poisoning",
    "cache_deception": "cache_poisoning",
    "attack_surface": "attack_surface",
    "template_probe": "template_probe",
    "authorization_matrix": "authorization",
    "api_resource_consumption": "resource_consumption",
    "client_exposure": "client_exposure",
    "graphql_security": "graphql",
    "graphql_introspection": "graphql",
    "graphql_batch_dos": "graphql",
    "csrf_clickjack": "csrf",
    "cors_misconfig": "cors",
    "header_audit": "headers",
    "csp_analyzer": "headers",
    "tls_crypto": "tls",
    "path_traversal": "path_traversal",
    "lfi_rce_escalation": "path_traversal",
}


TYPE_PATTERNS = [
    ("request smuggling", "request_smuggling"),
    ("desync", "request_smuggling"),
    ("cache poisoning", "cache_poisoning"),
    ("cache deception", "cache_poisoning"),
    ("attack surface", "attack_surface"),
    ("high-value route", "attack_surface"),
    ("template exposure", "template_probe"),
    ("metadata exposed", "template_probe"),
    ("document exposed", "template_probe"),
    ("authorization", "authorization"),
    ("function level", "authorization"),
    ("resource consumption", "resource_consumption"),
    ("source map", "client_exposure"),
    ("client-side", "client_exposure"),
    ("graphql", "graphql"),
    ("sql", "sql_injection"),
    ("cross-site scripting", "xss"),
    ("xss", "xss"),
    ("template injection", "ssti"),
    ("ssti", "ssti"),
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("csrf", "csrf"),
    ("clickjacking", "clickjacking"),
    ("cors", "cors"),
    ("content-security-policy", "headers"),
    ("missing header", "headers"),
    ("hsts", "tls"),
    ("tls", "tls"),
    ("ssl", "tls"),
    ("path traversal", "path_traversal"),
    ("file inclusion", "path_traversal"),
    ("lfi", "path_traversal"),
]


def _metadata_key_for(finding: dict[str, Any]) -> str | None:
    module_name = str(finding.get("module") or "").lower()
    if module_name in MODULE_TO_KEY:
        return MODULE_TO_KEY[module_name]

    haystack = " ".join(
        str(finding.get(key) or "").lower()
        for key in ("type", "module", "vector", "description")
    )
    for pattern, key in TYPE_PATTERNS:
        if pattern in haystack:
            return key
    return None


def _merge_list(existing: Any, additions: list[Any]) -> list[Any]:
    values = list(existing or [])
    seen = {repr(value) for value in values}
    for addition in additions:
        marker = repr(addition)
        if marker not in seen:
            values.append(addition)
            seen.add(marker)
    return values


def apply_finding_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach standards metadata without overwriting module-specific fields."""
    key = _metadata_key_for(finding)
    if not key:
        return finding

    metadata = deepcopy(REFERENCE_CATALOG[key])
    finding.setdefault("wstg", metadata["wstg"])
    finding.setdefault("owasp_category", metadata["owasp_category"])
    finding["cwe"] = _merge_list(finding.get("cwe"), metadata["cwe"])
    finding["references"] = _merge_list(finding.get("references"), metadata["references"])
    return finding
