import pytest
from datetime import datetime, timezone
import httpx
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import Target, Finding, CrawledURL, DiscoveredSubdomain, DLPFinding, gen_id
from core.dlp_parser import (
    SSN_REGEX, EMAIL_REGEX, PRIVATE_KEY_REGEX, TOKEN_REGEX,
    analyze_url_telemetry
)
from core.scoring import get_severity_score, is_non_standard_port, update_target_scores

def test_dlp_regex_rules():
    # 1. SSN Regex
    assert SSN_REGEX.search("My SSN is 123-45-6789.") is not None
    assert SSN_REGEX.search("Invalid SSN 12-345-6789.") is None

    # 2. Email Regex
    assert EMAIL_REGEX.search("admin@target.local") is not None
    assert EMAIL_REGEX.search("invalid-email@") is None

    # 3. Private Key Regex
    private_key_text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQE...\n-----END RSA PRIVATE KEY-----"
    assert PRIVATE_KEY_REGEX.search(private_key_text) is not None
    assert PRIVATE_KEY_REGEX.search("not a private key") is None

    # 4. Token Regex
    assert TOKEN_REGEX.search('api_key = "abcdef1234567890"') is not None
    assert TOKEN_REGEX.search('secret: "mysecretstringgoeshere"') is not None
    assert TOKEN_REGEX.search('short_token = "123"') is None


def test_severity_scoring_logic():
    assert get_severity_score("critical") == 8.0
    assert get_severity_score("high") == 6.0
    assert get_severity_score("medium") == 4.0
    assert get_severity_score("low") == 2.0
    assert get_severity_score("info") == 0.5
    assert get_severity_score("unknown") == 0.0


def test_non_standard_port_detection():
    assert is_non_standard_port("localhost:8080") is True
    assert is_non_standard_port("localhost:8443") is True
    assert is_non_standard_port("localhost:80") is False
    assert is_non_standard_port("localhost:443") is False
    assert is_non_standard_port("localhost") is False


@pytest.mark.asyncio
async def test_analyze_url_telemetry_stack_and_dlp():
    # Setup test target and crawled URL
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="Telemetry Test Target",
            host="telemetry.local",
            port=80
        )
        session.add(target)
        await session.commit()
        target_id = target.id

        crawled_url = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="telemetry.local",
            url="http://telemetry.local/index.html",
            is_new=True
        )
        session.add(crawled_url)
        await session.commit()
        crawled_url_id = crawled_url.id

    # Mock response from httpx
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Server": "nginx/1.18.0",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html"
    }
    mock_resp.text = "Hello! My email is support@telemetry.local and SSN is 000-12-3456. We also have react.production.min.js loaded."

    # Patch httpx.AsyncClient.get
    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        await analyze_url_telemetry(crawled_url_id, "http://telemetry.local/index.html", target_id)

    # Verify updates in database
    async with AsyncSessionLocal() as session:
        # Check crawled URL stack and score
        res_url = await session.execute(select(CrawledURL).where(CrawledURL.id == crawled_url_id))
        db_url = res_url.scalar_one()
        assert "nginx" in db_url.tech_stack
        assert "PHP" in db_url.tech_stack
        assert "React" in db_url.tech_stack

        # Check target stack
        res_target = await session.execute(select(Target).where(Target.id == target_id))
        db_target = res_target.scalar_one()
        assert "nginx" in db_target.tech_stack
        assert "PHP" in db_target.tech_stack
        assert "React" in db_target.tech_stack

        # Check DLP findings (should find email and SSN -> 2 findings)
        res_findings = await session.execute(
            select(DLPFinding).where(DLPFinding.crawled_url_id == crawled_url_id)
        )
        db_findings = res_findings.scalars().all()
        assert len(db_findings) == 2
        finding_types = [f.finding_type for f in db_findings]
        assert "PII" in finding_types

        # Clean up
        await session.delete(db_url)
        await session.delete(db_target)
        for f in db_findings:
            await session.delete(f)
        await session.commit()


@pytest.mark.asyncio
async def test_composite_risk_score_calculations():
    # Setup test target, subdomain, crawled URL, and findings
    async with AsyncSessionLocal() as session:
        target = Target(
            id=gen_id(),
            name="Scoring Test Target",
            host="scoring.local",
            port=80
        )
        session.add(target)
        await session.commit()
        target_id = target.id

        subdomain = DiscoveredSubdomain(
            id=gen_id(),
            target_id=target_id,
            subdomain="api.scoring.local:8080",  # non-standard port (+1.0)
            source="subfinder"
        )
        session.add(subdomain)

        crawled_url = CrawledURL(
            id=gen_id(),
            target_id=target_id,
            host="api.scoring.local:8080",
            url="http://api.scoring.local:8080/v1/auth",
            is_new=True
        )
        session.add(crawled_url)
        await session.commit()
        crawled_url_id = crawled_url.id
        subdomain_id = subdomain.id

        # Add an anomaly finding matching the url/subdomain (High severity -> +6.0)
        finding = Finding(
            id=gen_id(),
            target_id=target_id,
            title="SQL Injection",
            severity="high",
            category="vuln",
            evidence="Found on http://api.scoring.local:8080/v1/auth",
            hash="scoring_test_vuln_hash"
        )
        session.add(finding)

        # Add DLP findings for crawled URL: 1 Credential (+3.0) and 1 PII (+1.5)
        dlp_cred = DLPFinding(
            crawled_url_id=crawled_url_id,
            finding_type="Credential",
            value="privatekey...",
            compliance_tags=["PCI-DSS"]
        )
        dlp_pii = DLPFinding(
            crawled_url_id=crawled_url_id,
            finding_type="PII",
            value="user@mail.com",
            compliance_tags=["GDPR"]
        )
        session.add(dlp_cred)
        session.add(dlp_pii)
        await session.commit()

    # Recalculate target scores
    await update_target_scores(target_id)

    # Verify scores matching the exact calculation logic
    async with AsyncSessionLocal() as session:
        # 1. CrawledURL:
        # Score = DLP Credential(3.0) + DLP PII(1.5) + Anomaly High(6.0) = 10.5
        # Capped at 10.0
        db_url = await session.get(CrawledURL, crawled_url_id)
        assert db_url.risk_score == 10.0

        # 2. DiscoveredSubdomain:
        # Base Score = Non-standard port(1.0) + DLP Credential(3.0) + DLP PII(1.5) + Anomaly High(6.0) = 11.5
        # Multiplier: 1.2x -> 11.5 * 1.2 = 13.8 -> Capped at 10.0
        db_sub = await session.get(DiscoveredSubdomain, subdomain_id)
        assert db_sub.risk_score == 10.0

        # 3. Root Target:
        # Base Score = Anomaly High(6.0) + DLP Credential(3.0) + DLP PII(1.5) + Exposure distinct ports(1.0) = 11.5
        # Multiplier: 1.5x -> 11.5 * 1.5 = 17.25 -> Capped at 10.0
        db_target = await session.get(Target, target_id)
        assert db_target.risk_score == 10.0

        # Clean up
        db_finding = await session.get(Finding, finding.id)
        await session.delete(db_url)
        await session.delete(db_sub)
        await session.delete(db_target)
        await session.delete(db_finding)
        await session.delete(dlp_cred)
        await session.delete(dlp_pii)
        await session.commit()
