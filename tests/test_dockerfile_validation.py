"""
test_dockerfile_validation.py — Tests for Hadolint Dockerfile linting.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from docker_security_scanner.hadolint_scanner import (
    HadolintResult,
    HadolintScanner,
    LintIssue,
)
from docker_security_scanner.utils import (
    DockerfileNotFoundError,
    ScanExecutionError,
    ScannerConfig,
    ScannerError,
    ToolNotFoundError,
)


class TestHadolintScanner:
    """Tests for HadolintScanner class."""

    @patch("subprocess.run")
    def test_tool_not_found_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        """ToolNotFoundError raised when hadolint is missing."""
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError) as exc_info:
            HadolintScanner(config)
        assert "hadolint" in str(exc_info.value)

    @patch("subprocess.run")
    def test_scan_parses_issues(
        self,
        mock_run: MagicMock,
        config: ScannerConfig,
        sample_hadolint_output: str,
        vulnerable_dockerfile: Path,
    ) -> None:
        """scan() correctly parses Hadolint JSON output."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # version check
            MagicMock(returncode=0, stdout=sample_hadolint_output, stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(vulnerable_dockerfile))

        assert result.total_count == 3
        assert len(result.warnings) == 3
        assert len(result.errors) == 0
        assert result.ran is True

    @patch("subprocess.run")
    def test_scan_clean_dockerfile(
        self, mock_run: MagicMock, config: ScannerConfig, secure_dockerfile: Path
    ) -> None:
        """Clean Dockerfile produces no issues."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="[]", stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(secure_dockerfile))

        assert result.passed is True
        assert result.total_count == 0

    def test_scan_nonexistent_dockerfile(self, config: ScannerConfig) -> None:
        """A missing Dockerfile raises a ScannerError, not a bare OSError.

        The CLI only catches ScannerError, so a bare FileNotFoundError used to
        escape as an unhandled traceback.
        """
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            scanner = HadolintScanner(config)

        with pytest.raises(DockerfileNotFoundError) as exc_info:
            scanner.scan("/nonexistent/path/Dockerfile")
        assert isinstance(exc_info.value, ScannerError)

    @patch("subprocess.run")
    def test_empty_output_is_an_error_not_a_clean_pass(
        self, mock_run: MagicMock, config: ScannerConfig, secure_dockerfile: Path
    ) -> None:
        """A missing --config makes hadolint print nothing; that is not 'clean'."""
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(
                returncode=1,
                stdout="",
                stderr="hadolint: .hadolint.yaml: does not exist",
            ),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(secure_dockerfile))

        assert result.ran is False
        assert result.passed is False
        assert "does not exist" in result.error

    @patch("subprocess.run")
    def test_malformed_json_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, secure_dockerfile: Path
    ) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="{not json", stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(secure_dockerfile))
        assert "Failed to parse Hadolint JSON" in result.error

    @patch("subprocess.run")
    def test_unexpected_shape_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, secure_dockerfile: Path
    ) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout='{"a": 1}', stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(secure_dockerfile))
        assert "Unexpected Hadolint report shape" in result.error

    @patch("subprocess.run")
    def test_timeout_raises(
        self, mock_run: MagicMock, config: ScannerConfig, secure_dockerfile: Path
    ) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.TimeoutExpired(cmd="hadolint", timeout=60),
        ]
        scanner = HadolintScanner(config)
        with pytest.raises(ScanExecutionError, match="timed out"):
            scanner.scan(str(secure_dockerfile))

    @patch("subprocess.run")
    def test_issues_sorted_by_severity_then_line(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        """Issues are sorted: errors first, then warnings, then by line number."""
        output = json.dumps(
            [
                {
                    "code": "DL3008",
                    "level": "warning",
                    "message": "pin versions",
                    "line": 10,
                    "column": 1,
                    "file": "Dockerfile",
                },
                {
                    "code": "DL3002",
                    "level": "error",
                    "message": "root user",
                    "line": 5,
                    "column": 1,
                    "file": "Dockerfile",
                },
                {
                    "code": "DL3007",
                    "level": "warning",
                    "message": "latest tag",
                    "line": 1,
                    "column": 1,
                    "file": "Dockerfile",
                },
            ]
        )
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:latest\n", encoding="utf-8")

        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout=output, stderr=""),
        ]
        scanner = HadolintScanner(config)
        result = scanner.scan(str(dockerfile))

        assert result.issues[0].code == "DL3002"
        assert result.issues[0].level == "error"
        assert result.passed is False

    def test_build_command_includes_config_and_ignores(self, config: ScannerConfig) -> None:
        config.hadolint_config = ".hadolint.yaml"
        config.hadolint_ignore = ["DL3008", "DL3009"]
        scanner = HadolintScanner.__new__(HadolintScanner)
        scanner.config = config
        cmd = scanner._build_command("Dockerfile")

        assert cmd[cmd.index("--config") + 1] == ".hadolint.yaml"
        assert cmd.count("--ignore") == 2
        assert "--no-fail" in cmd
        assert cmd[-1] == "Dockerfile"


class TestHadolintResult:
    """Tests for the aggregated Hadolint result."""

    @staticmethod
    def _issue(**kwargs) -> LintIssue:
        defaults = dict(
            code="DL3007",
            level="warning",
            message="m",
            line=1,
            column=1,
            file="Dockerfile",
        )
        defaults.update(kwargs)
        return LintIssue(**defaults)

    def test_skipped_result_is_not_an_error(self) -> None:
        r = HadolintResult(dockerfile_path="N/A", skipped=True)
        assert r.ran is True
        assert r.passed is True
        assert "skipped" in r.summary()

    def test_error_result_is_not_passed(self) -> None:
        r = HadolintResult(dockerfile_path="Dockerfile", error="boom")
        assert r.ran is False
        assert r.passed is False
        assert "FAILED TO RUN" in r.summary()

    def test_level_buckets(self) -> None:
        r = HadolintResult(dockerfile_path="Dockerfile")
        r.issues = [
            self._issue(level="error"),
            self._issue(level="warning"),
            self._issue(level="info"),
            self._issue(level="style"),
        ]
        assert len(r.errors) == 1
        assert len(r.warnings) == 1
        assert len(r.infos) == 2
        assert r.total_count == 4

    def test_to_dict_exposes_ran_and_skipped(self) -> None:
        d = HadolintResult(dockerfile_path="Dockerfile").to_dict()
        for key in ("ran", "skipped", "passed", "error", "summary", "issues"):
            assert key in d

    def test_security_critical_count(self) -> None:
        r = HadolintResult(dockerfile_path="Dockerfile")
        r.issues = [self._issue(code="DL3002"), self._issue(code="DL3048")]
        assert r.security_critical_count == 1


class TestLintIssue:
    """Tests for the LintIssue data class."""

    def _make_issue(self, **kwargs) -> LintIssue:
        defaults = dict(
            code="DL3007",
            level="warning",
            message="Using latest is best avoided",
            line=1,
            column=1,
            file="Dockerfile",
        )
        defaults.update(kwargs)
        return LintIssue(**defaults)

    def test_severity_error_maps_to_high(self) -> None:
        assert self._make_issue(level="error").severity == "HIGH"

    def test_severity_warning_maps_to_medium(self) -> None:
        assert self._make_issue(level="warning").severity == "MEDIUM"

    def test_severity_info_maps_to_low(self) -> None:
        assert self._make_issue(level="info").severity == "LOW"

    def test_severity_style_maps_to_low(self) -> None:
        assert self._make_issue(level="style").severity == "LOW"

    def test_severity_unknown_level(self) -> None:
        assert self._make_issue(level="weird").severity == "UNKNOWN"

    def test_category_dl3_is_package_management(self) -> None:
        assert self._make_issue(code="DL3008").category == "Package Management"

    def test_category_dl1_is_base_image(self) -> None:
        assert self._make_issue(code="DL1000").category == "Base Image"

    def test_category_dl6_is_permissions(self) -> None:
        assert self._make_issue(code="DL6000").category == "Permissions"

    def test_category_shellcheck_rules_are_shell_script(self) -> None:
        """SC rules must resolve through the short 'SC' prefix.

        The old lookup sliced code[:3], so 'SC2035' keyed on 'SC2' and every
        ShellCheck rule silently fell through to 'General'.
        """
        assert self._make_issue(code="SC2035").category == "Shell Script"
        assert self._make_issue(code="SC1091").category == "Shell Script"

    def test_category_unknown_prefix_is_general(self) -> None:
        assert self._make_issue(code="ZZ9999").category == "General"

    def test_is_security_critical_for_high_risk_rule(self) -> None:
        assert self._make_issue(code="DL3002", level="warning").is_security_critical is True

    def test_is_security_critical_for_error_level(self) -> None:
        assert self._make_issue(code="DL9999", level="error").is_security_critical is True

    def test_is_not_security_critical_for_ordinary_warning(self) -> None:
        assert self._make_issue(code="DL3048", level="warning").is_security_critical is False

    def test_url_generated_for_dl_rules(self) -> None:
        issue = self._make_issue(
            code="DL3007", url="https://github.com/hadolint/hadolint/wiki/DL3007"
        )
        assert "DL3007" in issue.url

    def test_to_dict_has_required_keys(self) -> None:
        d = self._make_issue().to_dict()
        for key in ("code", "level", "severity", "message", "line", "category"):
            assert key in d
