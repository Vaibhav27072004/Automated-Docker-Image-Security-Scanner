"""
conftest.py — Shared pytest fixtures for Docker Security Scanner tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from docker_security_scanner.utils import ScannerConfig


@pytest.fixture
def config() -> ScannerConfig:
    """Return a default ScannerConfig suitable for unit tests."""
    return ScannerConfig(
        fail_on_severity=["CRITICAL", "HIGH"],
        critical_threshold=0,
        high_threshold=10,
        trivy_path="trivy",
        hadolint_path="hadolint",
        gitleaks_path="gitleaks",
        report_output_dir="test-reports",
        report_formats=["json", "markdown"],
        sbom_formats=["cyclonedx"],
        log_level="WARNING",
    )


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real .env out of the test run.

    ScannerConfig.from_env() reads the process environment, so a local .env
    (or exported CI variables) would otherwise make config tests flaky.
    """
    for var in (
        "FAIL_ON_SEVERITY",
        "CRITICAL_THRESHOLD",
        "HIGH_THRESHOLD",
        "FAIL_ON_DOCKERFILE_ERRORS",
        "FAIL_ON_SCANNER_ERROR",
        "TRIVY_PATH",
        "HADOLINT_PATH",
        "GITLEAKS_PATH",
        "TRIVY_CACHE_DIR",
        "TRIVY_SKIP_UPDATE",
        "HADOLINT_CONFIG",
        "HADOLINT_IGNORE",
        "GITLEAKS_CONFIG",
        "REPORT_OUTPUT_DIR",
        "REPORT_FORMATS",
        "SBOM_FORMATS",
        "MAX_JSON_VULNERABILITIES",
        "LOG_LEVEL",
        "LOG_FILE",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def sample_trivy_output() -> str:
    """Return a realistic Trivy JSON scan output with mixed CVEs."""
    data = {
        "SchemaVersion": 2,
        "ArtifactName": "python:3.9",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "python:3.9 (debian 11.6)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0464",
                        "PkgName": "libssl1.1",
                        "InstalledVersion": "1.1.1n-0+deb11u4",
                        "FixedVersion": "1.1.1n-0+deb11u5",
                        "Severity": "CRITICAL",
                        "Title": "OpenSSL: Excessive Resource Usage Verifying X.509",
                        "Description": "A security vulnerability in OpenSSL.",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 9.8,
                                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        },
                        "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0464"],
                        "PublishedDate": "2023-03-22T17:15:00Z",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-1255",
                        "PkgName": "libssl1.1",
                        "InstalledVersion": "1.1.1n-0+deb11u4",
                        "FixedVersion": "N/A",
                        "Severity": "HIGH",
                        "Title": "OpenSSL: Input buffer over-read in AES-XTS",
                        "Description": "Issue affecting AES-XTS on ARM.",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 7.5,
                                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        },
                        "References": [],
                        "PublishedDate": "2023-04-20T00:00:00Z",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-2650",
                        "PkgName": "libssl1.1",
                        "InstalledVersion": "1.1.1n-0+deb11u4",
                        "FixedVersion": "1.1.1u-1",
                        "Severity": "MEDIUM",
                        "Title": "OpenSSL: Possible DoS translating ASN.1 identifiers",
                        "Description": "DoS issue in ASN.1 handling.",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 5.5,
                                "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                            }
                        },
                        "References": [],
                        "PublishedDate": "2023-05-30T00:00:00Z",
                    },
                ],
            }
        ],
    }
    return json.dumps(data)


@pytest.fixture
def sample_hadolint_output() -> str:
    """Return realistic Hadolint JSON output with various issue levels."""
    data = [
        {
            "code": "DL3007",
            "severity": "warning",
            "level": "warning",
            "message": "Using latest is best avoided",
            "line": 1,
            "column": 1,
            "file": "Dockerfile",
        },
        {
            "code": "DL3002",
            "severity": "warning",
            "level": "warning",
            "message": "Last USER should not be root",
            "line": 15,
            "column": 1,
            "file": "Dockerfile",
        },
        {
            "code": "DL3008",
            "severity": "warning",
            "level": "warning",
            "message": "Pin versions in apt get install",
            "line": 8,
            "column": 1,
            "file": "Dockerfile",
        },
    ]
    return json.dumps(data)


@pytest.fixture
def sample_gitleaks_output() -> str:
    """Return realistic Gitleaks JSON output with a secret finding."""
    data = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "File": "examples/vulnerable-app/.env",
            "StartLine": 4,
            "Commit": "",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Entropy": 3.67,
            "Tags": ["aws", "credentials"],
        }
    ]
    return json.dumps(data)


@pytest.fixture
def vulnerable_dockerfile(tmp_path: Path) -> Path:
    """Create an intentionally insecure Dockerfile for testing."""
    content = """\
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY . .
CMD ["python3", "app.py"]
"""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(content, encoding="utf-8")
    return dockerfile


@pytest.fixture
def secure_dockerfile(tmp_path: Path) -> Path:
    """Create a secure Dockerfile for testing."""
    content = """\
FROM python:3.11.9-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11.9-slim
WORKDIR /app
RUN groupadd --gid 10001 appuser && useradd --uid 10001 --gid 10001 appuser
COPY --from=builder /app /app
USER appuser
EXPOSE 8080
CMD ["python", "app.py"]
"""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(content, encoding="utf-8")
    return dockerfile
