"""
test_cli.py — End-to-end tests for the orchestrator and the CLI.

These cover the pipeline wiring and the process exit codes, which is where the
"console says PASSED, report says failed, exit code says 1" contradiction used
to live. All three now read the same PolicyDecision.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from docker_security_scanner import scanner as scanner_module
from docker_security_scanner.gitleaks_scanner import GitleaksResult, SecretFinding
from docker_security_scanner.hadolint_scanner import HadolintResult, LintIssue
from docker_security_scanner.sbom_generator import SBOMResult
from docker_security_scanner.scanner import (
    EXIT_OK,
    EXIT_POLICY_VIOLATION,
    EXIT_SCANNER_ERROR,
    SecurityScanner,
    cli,
)
from docker_security_scanner.trivy_scanner import CVE, TrivyScanResult
from docker_security_scanner.utils import (
    DockerfileNotFoundError,
    ScannerConfig,
    ToolNotFoundError,
)


def _cve(severity: str, cve_id: str = "CVE-1") -> CVE:
    return CVE(cve_id, severity, "pkg", "1.0", "1.1", "", "", 9.8, "", [], "", "layer")


@pytest.fixture
def stub_tools(monkeypatch: pytest.MonkeyPatch):
    """Replace the three tool wrappers with configurable stubs.

    Returns a mutable dict the test can adjust to control what each stubbed
    scanner returns.
    """
    state: dict[str, object] = {
        "trivy": TrivyScanResult(image="demo:latest"),
        "hadolint": HadolintResult(dockerfile_path="Dockerfile"),
        "gitleaks": GitleaksResult(scan_path="."),
        "sbom": [SBOMResult(image="demo:latest", format="cyclonedx", output_path="s.json")],
        "trivy_raises": None,
    }

    class _Trivy:
        def __init__(self, config): ...

        def scan(self, image):
            if state["trivy_raises"] is not None:
                raise state["trivy_raises"]
            return state["trivy"]

    class _Hadolint:
        def __init__(self, config): ...

        def scan(self, path):
            return state["hadolint"]

    class _Gitleaks:
        def __init__(self, config): ...

        def scan(self, path):
            return state["gitleaks"]

    class _Sbom:
        def __init__(self, config): ...

        def generate_all(self, image, out_dir):
            return state["sbom"]

    monkeypatch.setattr(scanner_module, "TrivyScanner", _Trivy)
    monkeypatch.setattr(scanner_module, "HadolintScanner", _Hadolint)
    monkeypatch.setattr(scanner_module, "GitleaksScanner", _Gitleaks)
    monkeypatch.setattr(scanner_module, "SBOMGenerator", _Sbom)
    return state


class TestScanImagePipeline:
    def test_clean_scan_passes_and_writes_reports(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json", "markdown"]
        scanner = SecurityScanner(config)

        result = scanner.scan_image(
            "demo:latest", dockerfile_path="Dockerfile", output_dir=str(tmp_path)
        )

        assert result.passed is True
        assert result.policy.evaluated is True
        assert set(result.report_paths) == {"json", "markdown"}
        assert (tmp_path / "security_report.json").is_file()

    def test_all_formats_agree_with_the_policy_verdict(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        """The console, the JSON report and result.passed must never disagree."""
        config.report_formats = ["json"]
        stub_tools["trivy"] = TrivyScanResult(image="demo:latest")
        stub_tools["trivy"].vulnerabilities = [_cve("CRITICAL")]

        result = SecurityScanner(config).scan_image("demo:latest", output_dir=str(tmp_path))

        data = json.loads((tmp_path / "security_report.json").read_text(encoding="utf-8"))
        assert result.passed is False
        assert data["passed"] is False
        assert data["policy"]["violations"]

    def test_reports_are_written_after_policy_evaluation(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        """Regression: reports used to render before the verdict existed."""
        config.report_formats = ["json"]
        result = SecurityScanner(config).scan_image("demo:latest", output_dir=str(tmp_path))

        data = json.loads((tmp_path / "security_report.json").read_text(encoding="utf-8"))
        assert data["policy"]["evaluated"] is True
        assert result.policy.evaluated is True

    def test_missing_tool_fails_closed(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        """A scan where Trivy is absent must FAIL, not report PASSED."""
        config.report_formats = ["json"]
        stub_tools["trivy_raises"] = ToolNotFoundError("trivy")

        result = SecurityScanner(config).scan_image("demo:latest", output_dir=str(tmp_path))

        assert result.passed is False
        assert any("did not run" in v for v in result.policy.violations)
        assert result.trivy.ran is False

    def test_skipping_dockerfile_is_not_a_violation(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json"]
        result = SecurityScanner(config).scan_image(
            "demo:latest", dockerfile_path=None, output_dir=str(tmp_path)
        )
        assert result.hadolint.skipped is True
        assert result.passed is True

    def test_no_sbom_skips_generation(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json"]
        result = SecurityScanner(config).scan_image(
            "demo:latest", output_dir=str(tmp_path), generate_sbom=False
        )
        assert result.sbom_results == []
        assert result.passed is True

    def test_failed_sbom_fails_the_policy(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json"]
        stub_tools["sbom"] = [
            SBOMResult(image="demo:latest", format="cyclonedx", error="trivy db error")
        ]

        result = SecurityScanner(config).scan_image("demo:latest", output_dir=str(tmp_path))

        assert result.passed is False

    def test_dockerfile_error_fails_the_policy(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json"]
        hadolint = HadolintResult(dockerfile_path="Dockerfile")
        hadolint.issues = [LintIssue("DL3002", "error", "root", 15, 1, "Dockerfile")]
        stub_tools["hadolint"] = hadolint

        result = SecurityScanner(config).scan_image(
            "demo:latest", dockerfile_path="Dockerfile", output_dir=str(tmp_path)
        )

        assert result.passed is False
        assert any("DL3002" in v for v in result.policy.violations)

    def test_secrets_fail_the_policy(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        config.report_formats = ["json"]
        gitleaks = GitleaksResult(scan_path=".")
        gitleaks.findings = [SecretFinding("aws-access-token", "AWS", ".env", 4, "", "A" * 20, 3.6)]
        stub_tools["gitleaks"] = gitleaks

        result = SecurityScanner(config).scan_image("demo:latest", output_dir=str(tmp_path))

        assert result.passed is False

    def test_low_severity_findings_still_pass(
        self, config: ScannerConfig, stub_tools, tmp_path: Path
    ) -> None:
        """A real base image with LOW/MEDIUM CVEs must be able to exit 0."""
        config.report_formats = ["json"]
        trivy = TrivyScanResult(image="alpine:3.19")
        trivy.vulnerabilities = [_cve("LOW", "CVE-A"), _cve("MEDIUM", "CVE-B")]
        stub_tools["trivy"] = trivy

        result = SecurityScanner(config).scan_image("alpine:3.19", output_dir=str(tmp_path))

        assert result.passed is True
        assert result.is_clean is False


class TestCli:
    def test_help(self) -> None:
        res = CliRunner().invoke(cli, ["--help"])
        assert res.exit_code == EXIT_OK
        assert "zero-trust container security gate" in res.output

    def test_version(self) -> None:
        res = CliRunner().invoke(cli, ["--version"])
        assert res.exit_code == EXIT_OK
        assert "docker-scan" in res.output

    def test_image_clean_exits_zero(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REPORT_FORMATS", "json")
        res = CliRunner().invoke(
            cli, ["image", "demo:latest", "--output-dir", str(tmp_path), "--no-sbom"]
        )
        assert res.exit_code == EXIT_OK

    def test_image_policy_violation_exits_one(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REPORT_FORMATS", "json")
        trivy = TrivyScanResult(image="demo:latest")
        trivy.vulnerabilities = [_cve("CRITICAL")]
        stub_tools["trivy"] = trivy

        res = CliRunner().invoke(
            cli, ["image", "demo:latest", "--output-dir", str(tmp_path), "--no-sbom"]
        )
        assert res.exit_code == EXIT_POLICY_VIOLATION

    def test_image_missing_tool_exits_one_not_zero(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The headline regression: nothing scanned must never exit 0."""
        monkeypatch.setenv("REPORT_FORMATS", "json")
        stub_tools["trivy_raises"] = ToolNotFoundError("trivy")

        res = CliRunner().invoke(
            cli, ["image", "demo:latest", "--output-dir", str(tmp_path), "--no-sbom"]
        )

        assert res.exit_code == EXIT_POLICY_VIOLATION
        assert "FAILED" in res.output

    def test_fail_on_severity_override_is_applied(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--fail-on-severity LOW must turn a LOW-only scan red."""
        monkeypatch.setenv("REPORT_FORMATS", "json")
        trivy = TrivyScanResult(image="demo:latest")
        trivy.vulnerabilities = [_cve("LOW", "CVE-A")]
        stub_tools["trivy"] = trivy

        clean = CliRunner().invoke(
            cli, ["image", "demo:latest", "--output-dir", str(tmp_path), "--no-sbom"]
        )
        strict = CliRunner().invoke(
            cli,
            [
                "image",
                "demo:latest",
                "--output-dir",
                str(tmp_path),
                "--no-sbom",
                "--fail-on-severity",
                "LOW",
            ],
        )

        assert clean.exit_code == EXIT_OK
        assert strict.exit_code == EXIT_POLICY_VIOLATION

    def test_bad_env_config_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CRITICAL_THRESHOLD", "not-a-number")
        res = CliRunner().invoke(cli, ["image", "demo:latest"])
        assert res.exit_code == EXIT_SCANNER_ERROR
        assert "Configuration error" in res.output

    def test_dockerfile_command_lints(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine:3.19\n", encoding="utf-8")

        result = HadolintResult(dockerfile_path=str(dockerfile))
        result.issues = [LintIssue("DL3007", "warning", "latest tag", 1, 1, "Dockerfile")]

        class _Hadolint:
            def __init__(self, config): ...

            def scan(self, path):
                return result

        monkeypatch.setattr(scanner_module, "HadolintScanner", _Hadolint)

        res = CliRunner().invoke(cli, ["dockerfile", str(dockerfile)])

        assert res.exit_code == EXIT_OK  # warnings only
        assert "DL3007" in res.output

    def test_dockerfile_command_error_level_exits_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        result = HadolintResult(dockerfile_path="Dockerfile")
        result.issues = [LintIssue("DL3002", "error", "root", 15, 1, "Dockerfile")]

        class _Hadolint:
            def __init__(self, config): ...

            def scan(self, path):
                return result

        monkeypatch.setattr(scanner_module, "HadolintScanner", _Hadolint)
        res = CliRunner().invoke(cli, ["dockerfile", "Dockerfile"])
        assert res.exit_code == EXIT_POLICY_VIOLATION

    def test_dockerfile_command_missing_file_is_reported_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: this used to print a 20-line traceback."""

        class _Hadolint:
            def __init__(self, config): ...

            def scan(self, path):
                raise DockerfileNotFoundError(f"Dockerfile not found: {path}")

        monkeypatch.setattr(scanner_module, "HadolintScanner", _Hadolint)

        res = CliRunner().invoke(cli, ["dockerfile", "/nope/Dockerfile"])

        assert res.exit_code == EXIT_SCANNER_ERROR
        assert "Dockerfile not found" in res.output
        assert "Traceback" not in res.output

    def test_dockerfile_command_tool_missing_exits_two(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Hadolint:
            def __init__(self, config):
                raise ToolNotFoundError("hadolint")

        monkeypatch.setattr(scanner_module, "HadolintScanner", _Hadolint)
        res = CliRunner().invoke(cli, ["dockerfile", "Dockerfile"])
        assert res.exit_code == EXIT_SCANNER_ERROR

    def test_empty_fail_on_severity_disables_cve_thresholds(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--fail-on-severity "" is an explicit opt-out, not an absent flag.

        Used for SBOM-only runs. Secrets and scanner failures must still gate.
        """
        monkeypatch.setenv("REPORT_FORMATS", "json")
        trivy = TrivyScanResult(image="demo:latest")
        trivy.vulnerabilities = [_cve("CRITICAL", "CVE-A")]
        stub_tools["trivy"] = trivy

        res = CliRunner().invoke(
            cli,
            [
                "image",
                "demo:latest",
                "--output-dir",
                str(tmp_path),
                "--no-sbom",
                "--fail-on-severity",
                "",
            ],
        )
        assert res.exit_code == EXIT_OK

    def test_empty_fail_on_severity_still_gates_on_secrets(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REPORT_FORMATS", "json")
        gitleaks = GitleaksResult(scan_path=".")
        gitleaks.findings = [SecretFinding("aws-access-token", "AWS", ".env", 4, "", "A" * 20, 3.6)]
        stub_tools["gitleaks"] = gitleaks

        res = CliRunner().invoke(
            cli,
            [
                "image",
                "demo:latest",
                "--output-dir",
                str(tmp_path),
                "--no-sbom",
                "--fail-on-severity",
                "",
            ],
        )
        assert res.exit_code == EXIT_POLICY_VIOLATION

    def test_empty_fail_on_severity_still_gates_on_scanner_failure(
        self, stub_tools, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REPORT_FORMATS", "json")
        stub_tools["trivy_raises"] = ToolNotFoundError("trivy")

        res = CliRunner().invoke(
            cli,
            [
                "image",
                "demo:latest",
                "--output-dir",
                str(tmp_path),
                "--no-sbom",
                "--fail-on-severity",
                "",
            ],
        )
        assert res.exit_code == EXIT_POLICY_VIOLATION
