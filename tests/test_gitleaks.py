"""
test_gitleaks.py — Unit tests for the Gitleaks secret scanner integration.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from docker_security_scanner.gitleaks_scanner import (
    GitleaksResult,
    GitleaksScanner,
    SecretFinding,
)
from docker_security_scanner.utils import (
    ScanExecutionError,
    ScannerConfig,
    ScanPathNotFoundError,
    ToolNotFoundError,
)


def _report_writer(payload: str | None, returncode: int = 0, stderr: str = ""):
    """Return a subprocess.run side effect that writes Gitleaks' report file.

    ``payload=None`` emulates Gitleaks failing before it writes any report,
    which is the signal that distinguishes a failure from a clean scan.
    """

    def _run(cmd, *args, **kwargs):
        if payload is not None:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(payload, encoding="utf-8")
        return MagicMock(returncode=returncode, stdout="", stderr=stderr)

    return _run


@pytest.fixture
def scan_dir(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


class TestGitleaksScanner:
    @patch("subprocess.run")
    def test_tool_not_found_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError, match="gitleaks"):
            GitleaksScanner(config)

    @patch("subprocess.run")
    def test_missing_scan_path_raises_scanner_error(
        self, mock_run: MagicMock, config: ScannerConfig
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        with pytest.raises(ScanPathNotFoundError):
            scanner.scan("/definitely/not/here")

    def test_build_command_uses_a_real_file_not_dev_stdout(self, config: ScannerConfig) -> None:
        """Regression: '/dev/stdout' does not exist on Windows."""
        scanner = GitleaksScanner.__new__(GitleaksScanner)
        scanner.config = config
        cmd = scanner._build_command(".", "/tmp/report.json")
        assert "/dev/stdout" not in cmd
        assert cmd[cmd.index("--report-path") + 1] == "/tmp/report.json"
        assert "--no-git" in cmd

    def test_build_command_includes_config(self, config: ScannerConfig) -> None:
        config.gitleaks_config = ".gitleaks.toml"
        scanner = GitleaksScanner.__new__(GitleaksScanner)
        scanner.config = config
        cmd = scanner._build_command(".", "r.json")
        assert cmd[cmd.index("--config") + 1] == ".gitleaks.toml"

    @patch("subprocess.run")
    def test_scan_parses_findings(
        self,
        mock_run: MagicMock,
        config: ScannerConfig,
        sample_gitleaks_output: str,
        scan_dir: Path,
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer(sample_gitleaks_output)

        result = scanner.scan(str(scan_dir))

        assert result.total_count == 1
        assert result.critical_count == 1
        assert result.findings[0].rule_id == "aws-access-token"
        assert result.ran is True
        assert result.passed is False

    @patch("subprocess.run")
    def test_scan_clean_directory(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer("[]")

        result = scanner.scan(str(scan_dir))

        assert result.passed is True
        assert result.ran is True
        assert result.total_count == 0

    @patch("subprocess.run")
    def test_empty_report_file_is_clean(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer("")

        assert scanner.scan(str(scan_dir)).passed is True

    @patch("subprocess.run")
    def test_missing_report_file_is_an_error_not_a_clean_pass(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        """Regression: a fatal gitleaks config error looked like 'no secrets'.

        This is the exact failure the project's own .env.example used to cause.
        """
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer(
            None, returncode=1, stderr="FTL unable to load gitleaks config"
        )

        result = scanner.scan(str(scan_dir))

        assert result.ran is False
        assert result.passed is False
        assert "unable to load gitleaks config" in result.error

    @patch("subprocess.run")
    def test_nonzero_exit_is_an_error(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer("[]", returncode=2, stderr="bad source")

        result = scanner.scan(str(scan_dir))
        assert result.ran is False

    @patch("subprocess.run")
    def test_malformed_json_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer("{not json")

        result = scanner.scan(str(scan_dir))
        assert "Failed to parse Gitleaks JSON" in result.error

    @patch("subprocess.run")
    def test_unexpected_shape_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer('{"a": 1}')

        result = scanner.scan(str(scan_dir))
        assert "Unexpected Gitleaks report shape" in result.error

    @patch("subprocess.run")
    def test_timeout_raises(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gitleaks", timeout=120)
        with pytest.raises(ScanExecutionError, match="timed out"):
            scanner.scan(str(scan_dir))

    @patch("subprocess.run")
    def test_lowercase_field_names_are_accepted(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        payload = json.dumps(
            [
                {
                    "ruleID": "generic-api-key",
                    "description": "key",
                    "file": "a.py",
                    "startLine": 3,
                    "secret": "x" * 30,
                    "entropy": 4.9,
                }
            ]
        )
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer(payload)

        result = scanner.scan(str(scan_dir))
        assert result.findings[0].rule_id == "generic-api-key"
        assert result.findings[0].severity == "HIGH"

    @patch("subprocess.run")
    def test_findings_sorted_critical_first(
        self, mock_run: MagicMock, config: ScannerConfig, scan_dir: Path
    ) -> None:
        payload = json.dumps(
            [
                {"RuleID": "generic-api-key", "File": "b.py", "Entropy": 1.0},
                {"RuleID": "aws-access-token", "File": "a.py", "Entropy": 1.0},
            ]
        )
        mock_run.return_value = MagicMock(returncode=0)
        scanner = GitleaksScanner(config)
        mock_run.side_effect = _report_writer(payload)

        result = scanner.scan(str(scan_dir))
        assert result.findings[0].severity == "CRITICAL"


class TestSecretFinding:
    @staticmethod
    def _finding(**kwargs) -> SecretFinding:
        defaults = dict(
            rule_id="generic-api-key",
            description="d",
            file="a.py",
            line_number=1,
            commit="",
            secret_snippet="s" * 30,
            entropy=1.0,
        )
        defaults.update(kwargs)
        return SecretFinding(**defaults)

    @pytest.mark.parametrize(
        "rule", ["aws-access-token", "gcp-api-key", "private-key", "slack-webhook"]
    )
    def test_known_high_risk_rules_are_critical(self, rule: str) -> None:
        assert self._finding(rule_id=rule).severity == "CRITICAL"

    def test_high_entropy_is_high(self) -> None:
        assert self._finding(entropy=4.9).severity == "HIGH"

    def test_low_entropy_generic_is_medium(self) -> None:
        assert self._finding(entropy=2.0).severity == "MEDIUM"

    def test_to_dict_never_contains_the_plaintext_secret(self) -> None:
        """The report is a CI artifact and a PR comment; it must stay clean."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        d = self._finding(secret_snippet=secret).to_dict()
        assert secret not in json.dumps(d)
        assert "REDACTED" in d["secret_snippet"]

    def test_to_dict_does_not_leak_a_short_secret(self) -> None:
        d = self._finding(secret_snippet="abc").to_dict()
        assert "abc" not in d["secret_snippet"]

    def test_to_dict_keys(self) -> None:
        d = self._finding().to_dict()
        for key in ("rule_id", "file", "line_number", "severity", "secret_snippet"):
            assert key in d


class TestGitleaksResult:
    def test_error_result_is_not_passed(self) -> None:
        r = GitleaksResult(scan_path=".", error="boom")
        assert r.ran is False
        assert r.passed is False
        assert "FAILED TO RUN" in r.summary()

    def test_clean_result_summary(self) -> None:
        assert "Secrets found: 0" in GitleaksResult(scan_path=".").summary()

    def test_by_file_groups_findings(self) -> None:
        r = GitleaksResult(scan_path=".")
        r.findings = [
            SecretFinding("r1", "d", "a.py", 1, "", "x" * 20, 1.0),
            SecretFinding("r2", "d", "a.py", 9, "", "y" * 20, 1.0),
            SecretFinding("r3", "d", "b.py", 2, "", "z" * 20, 1.0),
        ]
        grouped = r.by_file()
        assert set(grouped) == {"a.py", "b.py"}
        assert len(grouped["a.py"]) == 2

    def test_counts(self) -> None:
        r = GitleaksResult(scan_path=".")
        r.findings = [
            SecretFinding("aws-access-token", "d", "a", 1, "", "x" * 20, 1.0),
            SecretFinding("generic", "d", "b", 1, "", "y" * 20, 4.9),
        ]
        assert (r.total_count, r.critical_count, r.high_count) == (2, 1, 1)

    def test_to_dict_shape(self) -> None:
        d = GitleaksResult(scan_path=".").to_dict()
        for key in ("scan_path", "summary", "ran", "passed", "error", "findings"):
            assert key in d
