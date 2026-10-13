"""
gitleaks_scanner.py — Gitleaks secret detection integration.

Detects hardcoded secrets, API keys, credentials, and other sensitive data
in source files, Dockerfiles, and environment files before they reach production.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .utils import (
    ScanExecutionError,
    ScannerConfig,
    ScanPathNotFoundError,
    ToolNotFoundError,
    clean_tool_error,
    mask_secret,
    utc_now_iso,
)

logger = logging.getLogger("docker_security_scanner.gitleaks")

# Risk tier by rule type
HIGH_RISK_RULE_PATTERNS = {
    "aws",
    "gcp",
    "azure",
    "private-key",
    "rsa",
    "ssh",
    "github-pat",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
}

_SCAN_TIMEOUT_SECONDS = 120


@dataclass
class SecretFinding:
    """A single secret detected by Gitleaks.

    Attributes:
        rule_id: Gitleaks rule that triggered the detection.
        description: Human-readable rule description.
        file: File path where the secret was found.
        line_number: Line number of the finding.
        commit: Git commit SHA (empty for filesystem scans).
        secret_snippet: The raw matched value. Never serialised directly —
            :meth:`to_dict` always emits :attr:`redacted_snippet` instead.
        entropy: Shannon entropy of the matched value.
        tags: List of tags from the rule.
    """

    rule_id: str
    description: str
    file: str
    line_number: int
    commit: str
    secret_snippet: str
    entropy: float
    tags: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """Estimate severity based on rule ID and entropy."""
        rule_lower = self.rule_id.lower()
        if any(pattern in rule_lower for pattern in HIGH_RISK_RULE_PATTERNS):
            return "CRITICAL"
        if self.entropy > 4.5:
            return "HIGH"
        return "MEDIUM"

    @property
    def redacted_snippet(self) -> str:
        """Return a safely redacted representation of the matched secret.

        The mask is fixed-width and reveals no plaintext, so a short or
        low-entropy secret cannot be reconstructed from a report that is
        uploaded as a CI artifact or posted into a pull request comment.
        """
        return mask_secret(self.secret_snippet)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "file": self.file,
            "line_number": self.line_number,
            "commit": self.commit,
            "secret_snippet": self.redacted_snippet,
            "entropy": self.entropy,
            "severity": self.severity,
            "tags": self.tags,
        }


@dataclass
class GitleaksResult:
    """Aggregated result from a Gitleaks scan.

    Attributes:
        scan_path: Directory or file path that was scanned.
        scan_timestamp: ISO-8601 timestamp.
        findings: All secret findings.
        error: Non-empty if scan encountered an error.
    """

    scan_path: str
    scan_timestamp: str = field(default_factory=utc_now_iso)
    findings: list[SecretFinding] = field(default_factory=list)
    error: str = ""

    @property
    def ran(self) -> bool:
        """True when the scan executed without an error."""
        return not self.error

    @property
    def passed(self) -> bool:
        """True when the scan ran and found no secrets."""
        return len(self.findings) == 0 and self.ran

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    def by_file(self) -> dict[str, list[SecretFinding]]:
        """Group findings by file path."""
        result: dict[str, list[SecretFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.file, []).append(finding)
        return result

    def summary(self) -> str:
        if not self.ran:
            return f"Gitleaks scan for {self.scan_path} - FAILED TO RUN: {self.error}"
        return (
            f"Gitleaks scan for {self.scan_path} - "
            f"Secrets found: {self.total_count} "
            f"(CRITICAL: {self.critical_count}, HIGH: {self.high_count})"
        )

    def to_dict(self) -> dict:
        return {
            "scan_path": self.scan_path,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total": self.total_count,
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "ran": self.ran,
            "passed": self.passed,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


class GitleaksScanner:
    """Wrapper around the Gitleaks CLI for secret detection.

    Args:
        config: ScannerConfig instance.

    Example::

        scanner = GitleaksScanner(config)
        result = scanner.scan("./examples/vulnerable-app")
        if not result.passed:
            print(f"Secrets found: {result.total_count}")
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._check_tool_available()

    def _check_tool_available(self) -> None:
        try:
            subprocess.run(
                [self.config.gitleaks_path, "version"],
                capture_output=True,
                check=True,
            )
        except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
            raise ToolNotFoundError("gitleaks") from exc

    def _build_command(self, scan_path: str, report_file: str) -> list[str]:
        """Build the Gitleaks CLI command arguments.

        Args:
            scan_path: Directory or file to scan.
            report_file: Path Gitleaks should write its JSON report to.

        Returns:
            Argument list for :func:`subprocess.run`.
        """
        cmd = [
            self.config.gitleaks_path,
            "detect",
            "--source",
            scan_path,
            "--report-format",
            "json",
            "--report-path",
            report_file,
            "--no-git",  # filesystem scan (no git history required)
            "--exit-code",
            "0",  # we handle policy
        ]
        if self.config.gitleaks_config:
            cmd.extend(["--config", self.config.gitleaks_config])
        return cmd

    def scan(self, scan_path: str) -> GitleaksResult:
        """Scan a directory or file for secrets with Gitleaks.

        Args:
            scan_path: Directory or file path to scan.

        Returns:
            GitleaksResult with all findings. If Gitleaks could not run,
            ``result.error`` is set and ``result.ran`` is False.

        Raises:
            ScanPathNotFoundError: If scan_path does not exist.
            ScanExecutionError: If Gitleaks times out.
            ToolNotFoundError: If the gitleaks binary disappeared.
        """
        path = Path(scan_path)
        if not path.exists():
            raise ScanPathNotFoundError(f"Scan path not found: {scan_path}")

        logger.info("Starting Gitleaks scan: %s", scan_path)

        # Gitleaks writes its report to a real file. A temp file rather than
        # "/dev/stdout" is what makes this work on Windows.
        with tempfile.TemporaryDirectory(prefix="docker-scan-gitleaks-") as tmpdir:
            report_file = Path(tmpdir) / "gitleaks-report.json"
            cmd = self._build_command(str(path), str(report_file))
            logger.debug("Running command: %s", " ".join(cmd))

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_SCAN_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                raise ScanExecutionError(f"Gitleaks timed out for {scan_path}") from exc
            except FileNotFoundError as exc:
                raise ToolNotFoundError("gitleaks") from exc

            report = ""
            report_exists = report_file.exists()
            if report_exists:
                report = report_file.read_text(encoding="utf-8", errors="replace")

        return self._parse_output(str(path), report, report_exists, proc)

    def _parse_output(
        self,
        scan_path: str,
        report: str,
        report_exists: bool,
        proc: "subprocess.CompletedProcess[str]",
    ) -> GitleaksResult:
        """Parse a Gitleaks JSON report into a :class:`GitleaksResult`.

        Args:
            scan_path: Path that was scanned.
            report: Contents of the JSON report file (may be empty).
            report_exists: Whether Gitleaks actually created the report file.
                This is the signal that distinguishes "ran and found nothing"
                from "failed to run", which must never look the same.
            proc: The completed Gitleaks process, for exit code and stderr.

        Returns:
            Populated :class:`GitleaksResult`.
        """
        result = GitleaksResult(scan_path=scan_path)
        stderr = clean_tool_error(proc.stderr or "")

        # Gitleaks writes a report file (at minimum "[]") on every successful
        # run. A missing file or a non-zero exit means it never scanned —
        # typically a bad --config path or an unreadable source.
        if not report_exists or proc.returncode != 0:
            result.error = stderr or (
                f"Gitleaks exited with code {proc.returncode} and wrote no report."
            )
            logger.error("Gitleaks failed for %s: %s", scan_path, result.error)
            return result

        if not report.strip():
            logger.info("Gitleaks: no secrets found in %s", scan_path)
            return result

        try:
            raw = json.loads(report)
        except json.JSONDecodeError as exc:
            result.error = f"Failed to parse Gitleaks JSON: {exc}"
            logger.error(result.error)
            return result

        if not isinstance(raw, list):
            result.error = f"Unexpected Gitleaks report shape: {type(raw).__name__}"
            logger.error(result.error)
            return result

        findings: list[SecretFinding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            findings.append(
                SecretFinding(
                    rule_id=item.get("RuleID", item.get("ruleID", "unknown")),
                    description=item.get("Description", item.get("description", "")),
                    file=item.get("File", item.get("file", "")),
                    line_number=item.get("StartLine", item.get("startLine", 0)),
                    commit=item.get("Commit", item.get("commit", "")),
                    secret_snippet=item.get("Secret", item.get("secret", "")),
                    entropy=float(item.get("Entropy", item.get("entropy", 0.0)) or 0.0),
                    tags=item.get("Tags", item.get("tags", [])) or [],
                )
            )

        # Sort by severity then file
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 3), f.file))
        result.findings = findings

        if findings:
            logger.warning(
                "Gitleaks: %d secrets found (%d CRITICAL) in %s",
                result.total_count,
                result.critical_count,
                scan_path,
            )
        else:
            logger.info("Gitleaks: no secrets found in %s", scan_path)
        return result
