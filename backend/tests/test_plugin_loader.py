import builtins
import importlib
import json
from unittest import mock

import pytest

# Assuming the plugin loader is accessible as backend.plugin_loader
from backend.plugin_loader import get_plugin, ScanResult

@pytest.fixture
def mock_trivy_output():
    # Sample JSON output that Trivy might produce
    return {
        "Target": "some-image",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2021-1234",
                "PkgName": "openssl",
                "InstalledVersion": "1.1.1",
                "FixedVersion": "1.1.2",
                "Severity": "HIGH",
                "Title": "OpenSSL vulnerability",
                "Description": "Some description",
                "References": ["https://example.com"],
                "CVSS": {"nvd": {"V2Score": 7.5, "V3Score": 9.0}}
            }
        ]
    }

def test_get_plugin_returns_instance():
    plugin = get_plugin("trivy")
    assert plugin is not None
    # The plugin should have a `scan` method
    assert callable(getattr(plugin, "scan", None))

@mock.patch("subprocess.run")
def test_trivy_scan_populates_scan_result(mock_run, mock_trivy_output):
    # Configure the mock to return our sample JSON output
    mock_process = mock.Mock()
    mock_process.stdout = json.dumps(mock_trivy_output).encode()
    mock_process.returncode = 0
    mock_run.return_value = mock_process

    plugin = get_plugin("trivy")
    # Run the scan; arguments can be dummy since subprocess is mocked
    result: ScanResult = plugin.scan(image="dummy-image")

    # Verify that the ScanResult fields are populated correctly
    assert result.target == "some-image"
    assert isinstance(result.vulnerabilities, list)
    assert len(result.vulnerabilities) == 1
    vuln = result.vulnerabilities[0]
    assert vuln.id == "CVE-2021-1234"
    assert vuln.package_name == "openssl"
    assert vuln.installed_version == "1.1.1"
    assert vuln.fixed_version == "1.1.2"
    assert vuln.severity == "HIGH"
    assert vuln.title == "OpenSSL vulnerability"
    assert vuln.description == "Some description"
    assert vuln.references == ["https://example.com"]
    # CVSS scores may be optional; check if present
    if hasattr(vuln, "cvss_score"):
        assert vuln.cvss_score == 9.0  # Prefer V3Score if available

