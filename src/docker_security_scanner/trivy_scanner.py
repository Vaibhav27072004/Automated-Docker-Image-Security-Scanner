"""
trivy_scanner.py — Trivy CVE scanner integration.

Wraps the Trivy CLI to scan Docker images for OS and library vulnerabilities.
Parses Trivy's JSON output and surfaces CVE details with severity filtering.

Typical usage::

    scanner = TrivyScanner(config)
    result = scanner.scan("python:3.9")
    print(result.summary())
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .utils import (
    ScanExecutionError,
    ScannerConfig,
    ToolNotFoundError,
    clean_tool_error,
    severity_rank,
    truncate_string,
    utc_now_iso,
)

logger = logging.getLogger("docker_security_scanner.trivy")

# Trivy's own progress/log output goes to stderr, but writing the JSON report to
# a real file (rather than "/dev/stdout") is what makes this work on Windows,
# where no /dev/stdout device path exists.
_SCAN_TIMEOUT_SECONDS = 300


# ─── Data classes ─────────────────────────────────────────────────────────────
@dataclass
class CVE:
    """A single vulnerability finding from Trivy.

    Attributes:
        id: CVE identifier (e.g. CVE-2023-12345).
        severity: Severity level string.
        package_name: Affected package name.
        installed_version: Currently installed version.
        fixed_version: Version that resolves the issue (if available).
        title: Short description.
        description: Full description.
        cvss_score: CVSS v3 base score (0.0-10.0).
        cvss_vector: CVSS v3 vector string.
        references: List of reference URLs.
        published_date: Publication date string.
        target: Image layer / target where found.
    """

    id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: str
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    references: list[str]
    published_date: str
    target: str

    @property
    def nvd_url(self) -> str:
        """Return the NVD detail URL for this CVE."""
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"

    @property
    def is_fixable(self) -> bool:
        """Return True if a fixed version is available."""
        return bool(self.fixed_version and self.fixed_version.lower() != "n/a")

    def to_dict(self) -> dict:
        """Serialise to a dictionary."""
        return {
            "id": self.id,
            "severity": self.severity,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "title": self.title,
            "description": truncate_string(self.description, 300),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "references": self.references[:5],
            "published_date": self.published_date,
            "target": self.target,
            "nvd_url": self.nvd_url,
            "is_fixable": self.is_fixable,
        }


@dataclass
class TrivyScanResult:
    """Aggregated result from a Trivy image scan.

    Attributes:
        image: Scanned image reference.
        scan_timestamp: ISO-8601 timestamp of the scan.
        vulnerabilities: All discovered CVEs.
        error: Non-empty string if the scan encountered an error.
        raw_output: Raw JSON string returned by Trivy.
    """

    image: str
    scan_timestamp: str = field(default_factory=utc_now_iso)
    vulnerabilities: list[CVE] = field(default_factory=list)
    error: str = ""
    raw_output: str = ""

    # ── Severity counts ──────────────────────────────────────────────────────
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "LOW")

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.is_fixable)

    @property
    def ran(self) -> bool:
        """True when the scan executed without an error.

        This is deliberately separate from :attr:`passed`: a scan that could not
        run has no findings, and must never be mistaken for a clean result.
        """
        return not self.error

    @property
    def passed(self) -> bool:
        """True when the scan ran and found no vulnerabilities at all.

        This is a strict, factual "is it spotless?" flag. It is NOT the security
        gate — the gate is the configured policy, evaluated in
        :meth:`docker_security_scanner.scanner.SecurityScanner.evaluate_policy`,
        which honours the CRITICAL/HIGH thresholds.
        """
        return self.total_count == 0 and self.ran

    def by_severity(self, severity: str) -> list[CVE]:
        """Filter vulnerabilities by severity level.

        Args:
            severity: Target severity (CRITICAL, HIGH, MEDIUM, LOW).

        Returns:
            Filtered list of :class:`CVE` objects.
        """
        return [v for v in self.vulnerabilities if v.severity == severity.upper()]

    def top_cvss(self, n: int = 10) -> list[CVE]:
        """Return the top-N vulnerabilities sorted by CVSS score descending.

        Args:
            n: Number of results to return.

        Returns:
            Sorted list of :class:`CVE` objects.
        """
        return sorted(self.vulnerabilities, key=lambda v: v.cvss_score, reverse=True)[:n]

    def summary(self) -> str:
        """Return a human-readable summary string."""
        if not self.ran:
            return f"Trivy scan for {self.image} - FAILED TO RUN: {self.error}"
        return (
            f"Trivy scan for {self.image} - "
            f"CRITICAL: {self.critical_count}, HIGH: {self.high_count}, "
            f"MEDIUM: {self.medium_count}, LOW: {self.low_count} "
            f"(Total: {self.total_count}, Fixable: {self.fixable_count})"
        )

    def to_dict(self, max_vulnerabilities: int = 0) -> dict:
        """Serialise to a dictionary for JSON output.

        Args:
            max_vulnerabilities: Cap on individual CVE records included
                (0 = unlimited). Summary counts always reflect every finding,
                so capping only trims the detail list.

        Returns:
            JSON-serialisable mapping.
        """
        vulns = self.vulnerabilities
        truncated = False
        if max_vulnerabilities and len(vulns) > max_vulnerabilities:
            vulns = vulns[:max_vulnerabilities]
            truncated = True

        return {
            "image": self.image,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total": self.total_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "fixable": self.fixable_count,
            },
            "ran": self.ran,
            "passed": self.passed,
            "error": self.error,
            "vulnerabilities_truncated": truncated,
            "vulnerabilities_included": len(vulns),
            "vulnerabilities": [v.to_dict() for v in vulns],
        }


# ─── Scanner class ────────────────────────────────────────────────────────────
class TrivyScanner:
    """Wrapper around the Trivy CLI for Docker image vulnerability scanning.

    Args:
        config: :class:`~docker_security_scanner.utils.ScannerConfig` instance.

    Example::

        config = ScannerConfig.from_env()
        scanner = TrivyScanner(config)
        result = scanner.scan("nginx:1.25")
        if result.critical_count > 0:
            print("Critical vulnerabilities found!")
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._check_tool_available()

    def _check_tool_available(self) -> None:
        """Verify that Trivy is installed and accessible.

        Raises:
            ToolNotFoundError: If trivy is not found on PATH.
        """
        try:
            subprocess.run(
                [self.config.trivy_path, "--version"],
                capture_output=True,
                check=True,
            )
        except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
            raise ToolNotFoundError("trivy") from exc

    def _build_command(self, image: str, output_file: str) -> list[str]:
        """Build the Trivy CLI command arguments.

        Args:
            image: Docker image reference to scan.
            output_file: Path Trivy should write its JSON report to.

        Returns:
            Argument list for :func:`subprocess.run`.
        """
        cmd = [
            self.config.trivy_path,
            "image",
            "--format",
            "json",
            "--output",
            output_file,
            "--exit-code",
            "0",  # never exit non-zero — we handle policy
            "--cache-dir",
            self.config.trivy_cache_dir,
        ]

        if self.config.trivy_skip_update:
            cmd.append("--skip-db-update")

        cmd.append(image)
        return cmd

    def scan(self, image: str) -> TrivyScanResult:
        """Scan a Docker image for vulnerabilities using Trivy.

        Args:
            image: Docker image reference (e.g. ``nginx:1.25``).

        Returns:
            :class:`TrivyScanResult` populated with all findings. If Trivy could
            not run, ``result.error`` is set and ``result.ran`` is False.

        Raises:
            ToolNotFoundError: If the trivy binary disappeared.
            ScanExecutionError: If Trivy timed out or exited unexpectedly.

        Example::

            result = scanner.scan("python:3.9-slim")
            for cve in result.by_severity("CRITICAL"):
                print(cve.id, cve.package_name)
        """
        logger.info("Starting Trivy scan for image: %s", image)

        # Trivy writes its report to a real file. Using a temp file rather than
        # "/dev/stdout" keeps this working on Windows and avoids interleaving
        # the JSON with Trivy's own progress output.
        with tempfile.TemporaryDirectory(prefix="docker-scan-trivy-") as tmpdir:
            output_file = Path(tmpdir) / "trivy-report.json"
            cmd = self._build_command(image, str(output_file))
            logger.debug("Running command: %s", " ".join(cmd))

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_SCAN_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                raise ScanExecutionError(f"Trivy timed out scanning {image}") from exc
            except FileNotFoundError as exc:
                raise ToolNotFoundError("trivy") from exc

            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text(encoding="utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            raise ScanExecutionError(
                f"Trivy exited with code {proc.returncode}: "
                f"{clean_tool_error(proc.stderr or '')}"
            )

        # Older call sites relied on Trivy printing JSON to stdout; fall back to
        # stdout if the report file came back empty for any reason.
        if not raw_output.strip():
            raw_output = proc.stdout

        return self._parse_output(image, raw_output, proc.stderr)

    def _parse_output(self, image: str, report: str, stderr: str) -> TrivyScanResult:
        """Parse Trivy JSON output into a :class:`TrivyScanResult`.

        Args:
            image: Image reference that was scanned.
            report: Raw JSON report text produced by Trivy.
            stderr: Raw stderr from Trivy, used for error reporting.

        Returns:
            Populated :class:`TrivyScanResult`.
        """
        result = TrivyScanResult(image=image, raw_output=report)

        if not report.strip():
            result.error = clean_tool_error(stderr) or "Trivy produced no output."
            logger.warning("Trivy produced no output for %s: %s", image, result.error)
            return result

        try:
            data = json.loads(report)
        except json.JSONDecodeError as exc:
            result.error = f"Failed to parse Trivy JSON: {exc}"
            logger.error(result.error)
            return result

        results_list = data.get("Results") or []
        vulnerabilities: list[CVE] = []

        for target_result in results_list:
            target = target_result.get("Target", "unknown")
            for vuln in target_result.get("Vulnerabilities") or []:
                cve = self._parse_vuln(vuln, target)
                if cve:
                    vulnerabilities.append(cve)

        # Sort: critical first, then by CVSS score descending
        vulnerabilities.sort(
            key=lambda v: (severity_rank(v.severity), v.cvss_score),
            reverse=True,
        )
        result.vulnerabilities = vulnerabilities
        logger.info(
            "Trivy scan complete: %d vulnerabilities found (%d critical, %d high)",
            result.total_count,
            result.critical_count,
            result.high_count,
        )
        return result

    @staticmethod
    def _parse_vuln(vuln: dict, target: str) -> Optional[CVE]:
        """Parse a single Trivy vulnerability dict into a :class:`CVE`.

        Args:
            vuln: Vulnerability dict from Trivy JSON.
            target: Target string (image layer or OS).

        Returns:
            :class:`CVE` or None if required fields are missing.
        """
        cve_id = vuln.get("VulnerabilityID", "")
        if not cve_id:
            return None

        # Extract CVSS v3 score
        cvss_score = 0.0
        cvss_vector = ""
        cvss_data = vuln.get("CVSS") or {}
        for source in ("nvd", "redhat", "ghsa"):
            source_data = cvss_data.get(source)
            if isinstance(source_data, dict) and "V3Score" in source_data:
                try:
                    cvss_score = float(source_data["V3Score"])
                except (TypeError, ValueError):
                    cvss_score = 0.0
                cvss_vector = source_data.get("V3Vector", "")
                break

        return CVE(
            id=cve_id,
            severity=(vuln.get("Severity") or "UNKNOWN").upper(),
            package_name=vuln.get("PkgName", ""),
            installed_version=vuln.get("InstalledVersion", ""),
            fixed_version=vuln.get("FixedVersion", "N/A"),
            title=vuln.get("Title", ""),
            description=vuln.get("Description", ""),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            references=vuln.get("References") or [],
            published_date=vuln.get("PublishedDate", ""),
            target=target,
        )
