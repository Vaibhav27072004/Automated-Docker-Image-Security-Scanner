"""
test_trivy.py — Unit tests for the Trivy CVE scanner integration.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from docker_security_scanner.trivy_scanner import CVE, TrivyScanner, TrivyScanResult
from docker_security_scanner.utils import (
    ScanExecutionError,
    ScannerConfig,
    ToolNotFoundError,
)


def _report_writer(payload: str, returncode: int = 0, stderr: str = ""):
    """Return a subprocess.run side effect that writes Trivy's --output file.

    The real Trivy writes its JSON to the path given by ``--output``; the
    scanner then reads that file back. Tests must emulate that rather than
    returning JSON on stdout.
    """

    def _run(cmd, *args, **kwargs):
        output_path = Path(cmd[cmd.index("--output") + 1])
        output_path.write_text(payload, encoding="utf-8")
        return MagicMock(returncode=returncode, stdout="", stderr=stderr)

    return _run


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    @patch("subprocess.run")
    def test_check_tool_available_success(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """TrivyScanner initialises when trivy is on PATH."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        assert scanner is not None

    @patch("subprocess.run")
    def test_check_tool_not_found(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ToolNotFoundError raised when trivy is not installed."""
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError) as exc_info:
            TrivyScanner(config)
        assert "trivy" in str(exc_info.value)

    def test_build_command_uses_a_real_file_not_dev_stdout(self, config: ScannerConfig) -> None:
        """The report path must be a real file so the scanner works on Windows."""
        scanner = TrivyScanner.__new__(TrivyScanner)
        scanner.config = config
        cmd = scanner._build_command("alpine:3.19", "/tmp/out.json")
        assert "/dev/stdout" not in cmd
        assert cmd[cmd.index("--output") + 1] == "/tmp/out.json"
        assert cmd[-1] == "alpine:3.19"

    def test_build_command_honours_skip_update(self, config: ScannerConfig) -> None:
        config.trivy_skip_update = True
        scanner = TrivyScanner.__new__(TrivyScanner)
        scanner.config = config
        assert "--skip-db-update" in scanner._build_command("alpine:3.19", "o.json")

    @patch("subprocess.run")
    def test_scan_parses_vulnerabilities(
        self, mock_run: MagicMock, config: ScannerConfig, sample_trivy_output: str
    ) -> None:
        """scan() correctly parses the Trivy JSON report file."""
        mock_run.return_value = MagicMock(returncode=0)  # version check in __init__
        scanner = TrivyScanner(config)

        mock_run.side_effect = _report_writer(sample_trivy_output)
        result = scanner.scan("python:3.9")

        assert result.image == "python:3.9"
        assert result.total_count == 3
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 0
        assert result.ran is True

    @patch("subprocess.run")
    def test_scan_sorts_by_severity_then_cvss(
        self, mock_run: MagicMock, config: ScannerConfig, sample_trivy_output: str
    ) -> None:
        """Vulnerabilities are sorted: CRITICAL first, then by CVSS score."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = _report_writer(sample_trivy_output)
        result = scanner.scan("python:3.9")

        assert result.vulnerabilities[0].severity == "CRITICAL"
        assert result.vulnerabilities[0].cvss_score == 9.8

    @patch("subprocess.run")
    def test_scan_empty_output_sets_error_and_not_ran(
        self, mock_run: MagicMock, config: ScannerConfig
    ) -> None:
        """An empty report is an error, never a clean result."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = _report_writer("", stderr="No image found")
        result = scanner.scan("nonexistent:image")

        assert result.error != ""
        assert result.ran is False
        assert result.passed is False
        assert result.total_count == 0

    @patch("subprocess.run")
    def test_scan_malformed_json_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = _report_writer("{not json")
        result = scanner.scan("broken:image")

        assert "Failed to parse Trivy JSON" in result.error
        assert result.ran is False

    @patch("subprocess.run")
    def test_scan_unexpected_exit_code_raises(
        self, mock_run: MagicMock, config: ScannerConfig
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = _report_writer("", returncode=77, stderr="boom")
        with pytest.raises(ScanExecutionError, match="exited with code 77"):
            scanner.scan("bad:image")

    @patch("subprocess.run")
    def test_scan_timeout_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ScanExecutionError raised on subprocess timeout."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)
        with pytest.raises(ScanExecutionError, match="timed out"):
            scanner.scan("slow:image")

    @patch("subprocess.run")
    def test_scan_tool_vanishes_raises_tool_not_found(
        self, mock_run: MagicMock, config: ScannerConfig
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError):
            scanner.scan("gone:image")

    @patch("subprocess.run")
    def test_scan_no_vulnerabilities(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """scan() returns passed=True when no vulnerabilities are found."""
        clean_output = json.dumps(
            {"SchemaVersion": 2, "ArtifactName": "distroless:latest", "Results": []}
        )
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        mock_run.side_effect = _report_writer(clean_output)
        result = scanner.scan("distroless:latest")

        assert result.passed is True
        assert result.ran is True
        assert result.total_count == 0

    @patch("subprocess.run")
    def test_scan_falls_back_to_stdout(
        self, mock_run: MagicMock, config: ScannerConfig, sample_trivy_output: str
    ) -> None:
        """If no report file appears, stdout is still parsed."""
        mock_run.return_value = MagicMock(returncode=0)
        scanner = TrivyScanner(config)
        # No side effect writes the --output file, so the fallback kicks in.
        mock_run.return_value = MagicMock(returncode=0, stdout=sample_trivy_output, stderr="")
        result = scanner.scan("python:3.9")
        assert result.total_count == 3


class TestParseVuln:
    """Tests for the single-vulnerability parser."""

    def test_missing_id_is_skipped(self) -> None:
        assert TrivyScanner._parse_vuln({"PkgName": "x"}, "t") is None

    def test_severity_is_uppercased(self) -> None:
        cve = TrivyScanner._parse_vuln({"VulnerabilityID": "CVE-1", "Severity": "critical"}, "t")
        assert cve is not None
        assert cve.severity == "CRITICAL"

    def test_null_severity_defaults_to_unknown(self) -> None:
        cve = TrivyScanner._parse_vuln({"VulnerabilityID": "CVE-1", "Severity": None}, "t")
        assert cve is not None
        assert cve.severity == "UNKNOWN"

    def test_cvss_falls_back_through_sources(self) -> None:
        cve = TrivyScanner._parse_vuln(
            {"VulnerabilityID": "CVE-1", "CVSS": {"redhat": {"V3Score": 6.1}}}, "t"
        )
        assert cve is not None
        assert cve.cvss_score == 6.1

    def test_non_numeric_cvss_is_tolerated(self) -> None:
        cve = TrivyScanner._parse_vuln(
            {"VulnerabilityID": "CVE-1", "CVSS": {"nvd": {"V3Score": "bad"}}}, "t"
        )
        assert cve is not None
        assert cve.cvss_score == 0.0

    def test_null_cvss_block_is_tolerated(self) -> None:
        cve = TrivyScanner._parse_vuln({"VulnerabilityID": "CVE-1", "CVSS": None}, "t")
        assert cve is not None
        assert cve.cvss_score == 0.0


class TestCVE:
    """Tests for the CVE data class."""

    def _make_cve(self, **kwargs) -> CVE:
        defaults = dict(
            id="CVE-2023-0001",
            severity="HIGH",
            package_name="openssl",
            installed_version="1.1.1",
            fixed_version="1.1.2",
            title="Test CVE",
            description="A test vulnerability",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
            published_date="2023-01-01T00:00:00Z",
            target="debian:11",
        )
        defaults.update(kwargs)
        return CVE(**defaults)

    def test_nvd_url(self) -> None:
        cve = self._make_cve()
        assert cve.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"

    def test_is_fixable_true(self) -> None:
        assert self._make_cve(fixed_version="1.1.2").is_fixable is True

    def test_is_fixable_false_na(self) -> None:
        assert self._make_cve(fixed_version="N/A").is_fixable is False

    def test_is_fixable_false_empty(self) -> None:
        assert self._make_cve(fixed_version="").is_fixable is False

    def test_to_dict_contains_expected_keys(self) -> None:
        d = self._make_cve().to_dict()
        for key in ("id", "severity", "package_name", "cvss_score", "nvd_url", "is_fixable"):
            assert key in d

    def test_to_dict_truncates_long_description(self) -> None:
        d = self._make_cve(description="x" * 500).to_dict()
        assert len(d["description"]) <= 300

    def test_to_dict_caps_references(self) -> None:
        d = self._make_cve(references=[f"u{i}" for i in range(20)]).to_dict()
        assert len(d["references"]) == 5


class TestTrivyScanResult:
    """Tests for TrivyScanResult helper methods."""

    def _make_result_with_mixed_cves(self) -> TrivyScanResult:
        cves = [
            CVE("CVE-A", "CRITICAL", "pkg1", "1.0", "1.1", "", "", 9.8, "", [], "", "layer1"),
            CVE("CVE-B", "HIGH", "pkg2", "2.0", "N/A", "", "", 7.5, "", [], "", "layer1"),
            CVE("CVE-C", "MEDIUM", "pkg3", "3.0", "3.1", "", "", 5.0, "", [], "", "layer1"),
            CVE("CVE-D", "LOW", "pkg4", "4.0", "4.1", "", "", 2.0, "", [], "", "layer1"),
        ]
        result = TrivyScanResult(image="test:latest")
        result.vulnerabilities = cves
        return result

    def test_severity_counts(self) -> None:
        r = self._make_result_with_mixed_cves()
        assert (r.critical_count, r.high_count, r.medium_count, r.low_count) == (1, 1, 1, 1)
        assert r.total_count == 4

    def test_fixable_count(self) -> None:
        assert self._make_result_with_mixed_cves().fixable_count == 3

    def test_by_severity_filters_correctly(self) -> None:
        criticals = self._make_result_with_mixed_cves().by_severity("CRITICAL")
        assert len(criticals) == 1
        assert criticals[0].id == "CVE-A"

    def test_by_severity_is_case_insensitive(self) -> None:
        assert len(self._make_result_with_mixed_cves().by_severity("critical")) == 1

    def test_top_cvss(self) -> None:
        top = self._make_result_with_mixed_cves().top_cvss(2)
        assert [v.cvss_score for v in top] == [9.8, 7.5]

    def test_passed_when_no_vulns(self) -> None:
        assert TrivyScanResult(image="clean:image").passed is True

    def test_not_passed_when_vulns_exist(self) -> None:
        assert self._make_result_with_mixed_cves().passed is False

    def test_error_means_not_ran_and_not_passed(self) -> None:
        r = TrivyScanResult(image="x", error="trivy exploded")
        assert r.ran is False
        assert r.passed is False

    def test_summary_reports_failure_to_run(self) -> None:
        r = TrivyScanResult(image="x", error="trivy exploded")
        assert "FAILED TO RUN" in r.summary()

    def test_summary_lists_counts(self) -> None:
        assert "CRITICAL: 1" in self._make_result_with_mixed_cves().summary()

    def test_to_dict_uncapped_includes_everything(self) -> None:
        d = self._make_result_with_mixed_cves().to_dict()
        assert len(d["vulnerabilities"]) == 4
        assert d["vulnerabilities_truncated"] is False

    def test_to_dict_respects_cap_but_keeps_summary_complete(self) -> None:
        d = self._make_result_with_mixed_cves().to_dict(max_vulnerabilities=2)
        assert len(d["vulnerabilities"]) == 2
        assert d["vulnerabilities_truncated"] is True
        assert d["vulnerabilities_included"] == 2
        # Summary counts must still describe ALL findings, not just the cap.
        assert d["summary"]["total"] == 4
