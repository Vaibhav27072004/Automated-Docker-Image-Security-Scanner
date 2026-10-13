"""
test_scanner.py — Integration tests for the main scanner orchestrator.

The tests in TestFailClosedPolicy are regression tests for the worst bug this
project had: a scan in which every tool failed to run reported
"Security policy: PASSED", because the policy only ever looked at finding
counts and a failed scanner contributes zero findings.
"""

from __future__ import annotations

import pytest

from docker_security_scanner.gitleaks_scanner import GitleaksResult, SecretFinding
from docker_security_scanner.hadolint_scanner import HadolintResult, LintIssue
from docker_security_scanner.sbom_generator import SBOMResult
from docker_security_scanner.scanner import (
    AggregatedResult,
    PolicyDecision,
    SecurityScanner,
)
from docker_security_scanner.trivy_scanner import CVE, TrivyScanResult
from docker_security_scanner.utils import PolicyViolationError, ScannerConfig


def _scanner(config: ScannerConfig) -> SecurityScanner:
    """Build a SecurityScanner without touching the filesystem or subprocesses."""
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.config = config
    return scanner


def _clean_result(image: str = "clean:image") -> AggregatedResult:
    result = AggregatedResult(image=image)
    result.trivy = TrivyScanResult(image=image)
    result.hadolint = HadolintResult(dockerfile_path="Dockerfile")
    result.gitleaks = GitleaksResult(scan_path=".")
    return result


def _cve(severity: str, cve_id: str = "CVE-2023-0001") -> CVE:
    return CVE(cve_id, severity, "pkg", "1.0", "1.1", "", "", 9.8, "", [], "", "layer")


class TestPolicyDecision:
    """An unevaluated decision must never read as a pass."""

    def test_unevaluated_is_not_passed(self) -> None:
        assert PolicyDecision().passed is False

    def test_evaluated_and_empty_is_passed(self) -> None:
        assert PolicyDecision(evaluated=True).passed is True

    def test_evaluated_with_violations_is_not_passed(self) -> None:
        assert PolicyDecision(violations=["boom"], evaluated=True).passed is False

    def test_to_dict_shape(self) -> None:
        d = PolicyDecision(violations=["v"], scanner_errors=["e"], evaluated=True).to_dict()
        assert d == {
            "evaluated": True,
            "passed": False,
            "violations": ["v"],
            "scanner_errors": ["e"],
        }


class TestFailClosedPolicy:
    """Regression tests: a scan that did not run must never pass."""

    def test_all_scanners_failed_is_a_violation(self, config: ScannerConfig) -> None:
        result = AggregatedResult(image="unscanned:latest")
        result.trivy = TrivyScanResult(image="unscanned:latest", error="trivy not found")
        result.hadolint = HadolintResult(dockerfile_path="D", error="hadolint not found")
        result.gitleaks = GitleaksResult(scan_path=".", error="gitleaks not found")

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert len(decision.scanner_errors) == 3
        assert any("did not run" in v for v in decision.violations)

    def test_single_failed_scanner_is_a_violation(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.gitleaks = GitleaksResult(scan_path=".", error="bad --config path")

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert "Gitleaks secret scan" in decision.scanner_errors[0]

    def test_failed_sbom_is_a_violation(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.sbom_results = [
            SBOMResult(image="clean:image", format="cyclonedx", error="trivy died")
        ]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("SBOM" in e for e in decision.scanner_errors)

    def test_fail_open_can_be_opted_into_explicitly(self, config: ScannerConfig) -> None:
        """Operators may opt out, but the default must be fail-closed."""
        config.fail_on_scanner_error = False
        result = _clean_result()
        result.trivy = TrivyScanResult(image="x", error="trivy not found")

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is True
        # The error is still reported even when it is not a violation.
        assert decision.scanner_errors

    def test_enforce_policy_raises_on_scanner_failure(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.trivy = TrivyScanResult(image="x", error="trivy not found")

        with pytest.raises(PolicyViolationError, match="did not run"):
            _scanner(config).enforce_policy(result)


class TestPolicyThresholds:
    """The configured thresholds must actually drive the verdict."""

    def test_policy_passes_with_no_findings(self, config: ScannerConfig) -> None:
        decision = _scanner(config).evaluate_policy(_clean_result())
        assert decision.passed is True
        assert decision.violations == []

    def test_policy_fails_on_critical_cve(self, config: ScannerConfig) -> None:
        result = _clean_result("vuln:image")
        result.trivy.vulnerabilities = [_cve("CRITICAL")]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("CRITICAL" in v for v in decision.violations)

    def test_policy_fails_on_secrets(self, config: ScannerConfig) -> None:
        result = _clean_result("secret:image")
        result.gitleaks.findings = [
            SecretFinding("aws-access-token", "AWS Key", ".env", 4, "", "AKIA...", 3.67)
        ]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("secrets" in v.lower() for v in decision.violations)

    def test_policy_respects_high_threshold(self, config: ScannerConfig) -> None:
        """Policy should pass if HIGH count is within threshold."""
        config.high_threshold = 5
        result = _clean_result("moderate:image")
        result.trivy.vulnerabilities = [_cve("HIGH", f"CVE-2023-000{i}") for i in range(3)]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is True

    def test_policy_fails_above_high_threshold(self, config: ScannerConfig) -> None:
        config.high_threshold = 2
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("HIGH", f"CVE-{i}") for i in range(3)]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("HIGH" in v for v in decision.violations)

    def test_high_threshold_zero_disables_the_high_check(self, config: ScannerConfig) -> None:
        config.high_threshold = 0
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("HIGH", f"CVE-{i}") for i in range(50)]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is True

    def test_low_severity_cves_do_not_fail_the_default_policy(self, config: ScannerConfig) -> None:
        """A LOW CVE in a base image must not turn the gate red by default.

        Previously the exit code came from "zero findings", so no real image
        could ever pass and the thresholds were decorative.
        """
        result = _clean_result("alpine:3.19")
        result.trivy.vulnerabilities = [
            _cve("LOW", "CVE-A"),
            _cve("MEDIUM", "CVE-B"),
        ]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is True

    def test_medium_can_be_made_a_failing_severity(self, config: ScannerConfig) -> None:
        config.fail_on_severity = ["CRITICAL", "HIGH", "MEDIUM"]
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("MEDIUM", "CVE-B")]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("MEDIUM" in v for v in decision.violations)

    def test_low_can_be_made_a_failing_severity(self, config: ScannerConfig) -> None:
        config.fail_on_severity = ["LOW"]
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("LOW", "CVE-C")]

        assert _scanner(config).evaluate_policy(result).passed is False

    def test_critical_threshold_allows_a_budget(self, config: ScannerConfig) -> None:
        config.critical_threshold = 2
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("CRITICAL", f"CVE-{i}") for i in range(2)]

        assert _scanner(config).evaluate_policy(result).passed is True


class TestDockerfilePolicy:
    """Hadolint error-level findings must be able to fail the gate."""

    def test_dockerfile_errors_fail_the_policy(self, config: ScannerConfig) -> None:
        result = _clean_result("bad-dockerfile:latest")
        result.hadolint.issues = [
            LintIssue("DL3002", "error", "Last USER should not be root", 15, 1, "Dockerfile")
        ]

        decision = _scanner(config).evaluate_policy(result)

        assert decision.passed is False
        assert any("DL3002" in v for v in decision.violations)

    def test_dockerfile_warnings_do_not_fail_the_policy(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.hadolint.issues = [
            LintIssue("DL3008", "warning", "Pin versions", 8, 1, "Dockerfile")
        ]

        assert _scanner(config).evaluate_policy(result).passed is True

    def test_dockerfile_gate_can_be_disabled(self, config: ScannerConfig) -> None:
        config.fail_on_dockerfile_errors = False
        result = _clean_result()
        result.hadolint.issues = [LintIssue("DL3002", "error", "root user", 15, 1, "Dockerfile")]

        assert _scanner(config).evaluate_policy(result).passed is True

    def test_skipped_hadolint_does_not_fail_the_policy(self, config: ScannerConfig) -> None:
        result = AggregatedResult(image="x")
        result.trivy = TrivyScanResult(image="x")
        result.gitleaks = GitleaksResult(scan_path=".")
        # Default hadolint field is the "skipped" sentinel.
        assert result.hadolint.skipped is True
        assert _scanner(config).evaluate_policy(result).passed is True


class TestAggregatedResult:
    """Tests for the AggregatedResult data class."""

    def test_passed_reflects_policy_not_raw_findings(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("LOW", "CVE-A")]
        result.policy = _scanner(config).evaluate_policy(result)

        assert result.passed is True  # policy satisfied
        assert result.is_clean is False  # but not spotless

    def test_passed_is_false_before_policy_evaluation(self) -> None:
        assert _clean_result().passed is False

    def test_is_clean_true_for_spotless_scan(self) -> None:
        assert _clean_result().is_clean is True

    def test_is_clean_false_when_a_scanner_failed(self) -> None:
        result = _clean_result()
        result.trivy = TrivyScanResult(image="x", error="boom")
        assert result.is_clean is False

    def test_scanner_errors_lists_every_failure(self) -> None:
        result = _clean_result()
        result.trivy = TrivyScanResult(image="x", error="a")
        result.hadolint = HadolintResult(dockerfile_path="D", error="b")
        result.gitleaks = GitleaksResult(scan_path=".", error="c")
        result.sbom_results = [SBOMResult(image="x", format="spdx", error="d")]
        assert len(result.scanner_errors) == 4

    def test_overall_severity_none_when_clean(self) -> None:
        assert _clean_result().overall_severity == "NONE"

    def test_overall_severity_takes_the_worst_across_tools(self) -> None:
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("MEDIUM", "CVE-A")]
        result.gitleaks.findings = [
            SecretFinding("aws-access-token", "AWS", ".env", 1, "", "AKIA", 3.0)
        ]
        assert result.overall_severity == "CRITICAL"

    def test_summary_says_not_evaluated_before_policy(self) -> None:
        assert "NOT EVALUATED" in _clean_result().summary()

    def test_summary_reports_verdict(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.policy = _scanner(config).evaluate_policy(result)
        assert "PASSED" in result.summary()

    def test_to_dict_contains_all_sections(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.policy = _scanner(config).evaluate_policy(result)
        d = result.to_dict()
        for key in (
            "image",
            "passed",
            "is_clean",
            "overall_severity",
            "policy",
            "trivy",
            "hadolint",
            "gitleaks",
            "sbom_results",
            "report_paths",
        ):
            assert key in d

    def test_to_dict_passes_the_vulnerability_cap_through(self, config: ScannerConfig) -> None:
        result = _clean_result()
        result.trivy.vulnerabilities = [_cve("LOW", f"CVE-{i}") for i in range(10)]
        result.policy = _scanner(config).evaluate_policy(result)

        d = result.to_dict(max_json_vulnerabilities=3)

        assert len(d["trivy"]["vulnerabilities"]) == 3
        assert d["trivy"]["summary"]["total"] == 10
