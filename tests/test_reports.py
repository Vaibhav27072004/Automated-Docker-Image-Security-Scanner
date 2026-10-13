"""
test_reports.py — Unit tests for report generation.

Covers the two properties that matter most for a report that gets uploaded as a
CI artifact and posted into a pull request: untrusted scanner text must not be
able to break out of the HTML or the Markdown table, and every format must show
the same verdict as the console and the exit code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from docker_security_scanner.gitleaks_scanner import GitleaksResult, SecretFinding
from docker_security_scanner.hadolint_scanner import HadolintResult, LintIssue
from docker_security_scanner.report_generator import ReportGenerator, md_cell
from docker_security_scanner.scanner import AggregatedResult, SecurityScanner
from docker_security_scanner.trivy_scanner import CVE, TrivyScanResult
from docker_security_scanner.utils import ScannerConfig


def _result(image: str = "demo:latest") -> AggregatedResult:
    result = AggregatedResult(image=image)
    result.trivy = TrivyScanResult(image=image)
    result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
    result.gitleaks = GitleaksResult(scan_path=".")
    return result


def _evaluated(config: ScannerConfig, result: AggregatedResult) -> AggregatedResult:
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.config = config
    result.policy = scanner.evaluate_policy(result)
    return result


class TestMdCell:
    def test_escapes_pipe(self) -> None:
        assert md_cell("a|b") == r"a\|b"

    def test_collapses_newlines(self) -> None:
        assert "\n" not in md_cell("line1\nline2")

    def test_collapses_crlf(self) -> None:
        assert md_cell("a\r\nb") == "a b"

    def test_escapes_angle_brackets(self) -> None:
        assert md_cell("<img src=x>") == "&lt;img src=x&gt;"

    def test_escapes_backslash(self) -> None:
        assert md_cell("a\\b") == "a\\\\b"

    def test_truncates_long_values(self) -> None:
        out = md_cell("x" * 500, max_len=50)
        assert len(out) == 50
        assert out.endswith("...")

    def test_non_string_input(self) -> None:
        assert md_cell(42) == "42"


class TestJsonReport:
    def test_writes_valid_json(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["json"]
        result = _evaluated(config, _result())

        paths = ReportGenerator(config).generate_all(result, str(tmp_path))

        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        assert data["image"] == "demo:latest"
        assert data["passed"] is True
        assert data["policy"]["evaluated"] is True

    def test_json_verdict_matches_policy(self, config: ScannerConfig, tmp_path: Path) -> None:
        """Regression: console said PASSED while the JSON said passed=false."""
        config.report_formats = ["json"]
        result = _result()
        result.trivy.vulnerabilities = [
            CVE("CVE-1", "CRITICAL", "p", "1", "2", "", "", 9.9, "", [], "", "l")
        ]
        result = _evaluated(config, result)

        paths = ReportGenerator(config).generate_all(result, str(tmp_path))
        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))

        assert result.passed is False
        assert data["passed"] is False
        assert data["policy"]["violations"]

    def test_vulnerability_cap_is_applied(self, config: ScannerConfig, tmp_path: Path) -> None:
        """A 6,000-CVE image must not produce a multi-megabyte JSON artifact."""
        config.report_formats = ["json"]
        config.max_json_vulnerabilities = 5
        result = _result()
        result.trivy.vulnerabilities = [
            CVE(f"CVE-{i}", "LOW", "p", "1", "2", "", "", 1.0, "", [], "", "l") for i in range(100)
        ]
        result = _evaluated(config, result)

        paths = ReportGenerator(config).generate_all(result, str(tmp_path))
        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))

        assert len(data["trivy"]["vulnerabilities"]) == 5
        assert data["trivy"]["vulnerabilities_truncated"] is True
        assert data["trivy"]["summary"]["total"] == 100


class TestMarkdownReport:
    def test_contains_summary_table(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["markdown"]
        result = _evaluated(config, _result())

        paths = ReportGenerator(config).generate_all(result, str(tmp_path))
        md = Path(paths["markdown"]).read_text(encoding="utf-8")

        assert "PASSED" in md
        assert "| Check | Status | Findings |" in md

    def test_lists_policy_violations(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["markdown"]
        result = _result()
        result.gitleaks.findings = [
            SecretFinding("aws-access-token", "AWS", ".env", 4, "", "A" * 20, 3.6)
        ]
        result = _evaluated(config, result)

        md = Path(
            ReportGenerator(config).generate_all(result, str(tmp_path))["markdown"]
        ).read_text(encoding="utf-8")

        assert "FAILED" in md
        assert "Policy Violations" in md
        assert "hardcoded secrets" in md

    def test_explains_a_scanner_that_did_not_run(
        self, config: ScannerConfig, tmp_path: Path
    ) -> None:
        config.report_formats = ["markdown"]
        result = _result()
        result.trivy = TrivyScanResult(image="x", error="trivy not found")
        result = _evaluated(config, result)

        md = Path(
            ReportGenerator(config).generate_all(result, str(tmp_path))["markdown"]
        ).read_text(encoding="utf-8")

        assert "did not run" in md
        assert "not evidence of a clean image" in md

    def test_untrusted_text_cannot_break_the_table(
        self, config: ScannerConfig, tmp_path: Path
    ) -> None:
        """A package name containing a pipe must not split the row."""
        config.report_formats = ["markdown"]
        result = _result()
        result.trivy.vulnerabilities = [
            CVE("CVE-1", "CRITICAL", "evil|pkg\nrow", "1", "2", "", "", 9.9, "", [], "", "l")
        ]
        result = _evaluated(config, result)

        md = Path(
            ReportGenerator(config).generate_all(result, str(tmp_path))["markdown"]
        ).read_text(encoding="utf-8")

        assert "evil\\|pkg" in md
        for line in md.splitlines():
            if line.startswith("| [CVE-1]"):
                # 5 columns => 6 pipes, and no extra unescaped pipe.
                assert line.count("|") - line.count("\\|") == 6

    def test_secret_table_is_capped(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["markdown"]
        result = _result()
        result.gitleaks.findings = [
            SecretFinding("generic", "d", f"f{i}.py", i, "", "x" * 20, 1.0) for i in range(25)
        ]
        result = _evaluated(config, result)

        md = Path(
            ReportGenerator(config).generate_all(result, str(tmp_path))["markdown"]
        ).read_text(encoding="utf-8")

        assert "Showing 10 of 25" in md

    def test_dockerfile_errors_are_listed(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["markdown"]
        result = _result()
        result.hadolint.issues = [LintIssue("DL3002", "error", "root user", 15, 1, "Dockerfile")]
        result = _evaluated(config, result)

        md = Path(
            ReportGenerator(config).generate_all(result, str(tmp_path))["markdown"]
        ).read_text(encoding="utf-8")

        assert "Dockerfile Errors" in md
        assert "DL3002" in md


class TestHtmlReport:
    def test_renders_and_includes_counts(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["html"]
        result = _result()
        result.trivy.vulnerabilities = [
            CVE("CVE-1", "CRITICAL", "openssl", "1", "2", "", "", 9.9, "", [], "", "l")
        ]
        result = _evaluated(config, result)

        html = Path(ReportGenerator(config).generate_all(result, str(tmp_path))["html"]).read_text(
            encoding="utf-8"
        )

        assert "Docker Security Scan Report" in html
        assert "CVE-1" in html
        assert "openssl" in html

    def test_escapes_untrusted_scanner_text(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["html"]
        result = _result(image="x<script>alert(1)</script>:latest")
        result.trivy.vulnerabilities = [
            CVE(
                "CVE-1",
                "CRITICAL",
                "<img src=x onerror=alert(2)>",
                "1",
                "2",
                "",
                "",
                9.9,
                "",
                [],
                "",
                "l",
            )
        ]
        result = _evaluated(config, result)

        html = Path(ReportGenerator(config).generate_all(result, str(tmp_path))["html"]).read_text(
            encoding="utf-8"
        )

        assert "<script>alert(1)</script>" not in html
        assert "onerror=alert(2)>" not in html
        assert "&lt;script&gt;" in html

    def test_shows_scanner_failure_banner(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["html"]
        result = _result()
        result.gitleaks = GitleaksResult(scan_path=".", error="gitleaks not found")
        result = _evaluated(config, result)

        html = Path(ReportGenerator(config).generate_all(result, str(tmp_path))["html"]).read_text(
            encoding="utf-8"
        )

        assert "Scanners that did not run" in html
        assert "gitleaks not found" in html


class TestGenerateAll:
    def test_generates_every_configured_format(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["html", "json", "markdown"]
        result = _evaluated(config, _result())

        paths = ReportGenerator(config).generate_all(result, str(tmp_path))

        assert set(paths) == {"html", "json", "markdown"}
        for path in paths.values():
            assert Path(path).is_file()

    def test_creates_the_output_directory(self, config: ScannerConfig, tmp_path: Path) -> None:
        config.report_formats = ["json"]
        out = tmp_path / "deep" / "nested"
        ReportGenerator(config).generate_all(_evaluated(config, _result()), str(out))
        assert out.is_dir()

    def test_unknown_format_raises(self, config: ScannerConfig, tmp_path: Path) -> None:
        """A typo in REPORT_FORMATS must fail loudly, not silently skip."""
        config.report_formats = ["json", "pdf"]
        with pytest.raises(ValueError, match="Unknown report format"):
            ReportGenerator(config).generate_all(_evaluated(config, _result()), str(tmp_path))
