"""
scanner.py — Main orchestrator for Docker Image Security Scanner.

This module ties together all scanning components (Trivy, Hadolint, Gitleaks,
SBOM) into a single pipeline. It is the primary CLI entry point and can also
be used programmatically.

Usage (CLI)::

    docker-scan image nginx:1.25
    docker-scan image myapp:latest --dockerfile ./Dockerfile --scan-path ./src
    docker-scan dockerfile ./Dockerfile

Usage (programmatic)::

    from docker_security_scanner.scanner import SecurityScanner
    from docker_security_scanner.utils import ScannerConfig

    config = ScannerConfig.from_env()
    scanner = SecurityScanner(config)
    result = scanner.scan_image("nginx:1.25", dockerfile_path="./Dockerfile")
    print(result.summary())

The security verdict comes from exactly one place: :meth:`SecurityScanner.
evaluate_policy`. The console output, every report format and the process exit
code all read that same decision, and the policy **fails closed** — a scanner
that could not run is a violation, never a silent pass.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

import click
from rich import box
from rich.table import Table

from .gitleaks_scanner import GitleaksResult, GitleaksScanner
from .hadolint_scanner import HadolintResult, HadolintScanner
from .report_generator import ReportGenerator
from .sbom_generator import SBOMGenerator, SBOMResult
from .trivy_scanner import TrivyScanner, TrivyScanResult
from .utils import (
    SEVERITY_COLORS,
    PolicyViolationError,
    ScannerConfig,
    ScannerError,
    console,
    max_severity,
    setup_logging,
    utc_now_iso,
)

logger = logging.getLogger("docker_security_scanner")

# Exit codes — documented in README and relied on by CI.
EXIT_OK = 0
EXIT_POLICY_VIOLATION = 1
EXIT_SCANNER_ERROR = 2


# ─── Policy decision ──────────────────────────────────────────────────────────
@dataclass
class PolicyDecision:
    """The single authoritative verdict for a scan.

    Attributes:
        violations: Human-readable policy violations. Empty means the scan
            satisfied the configured policy.
        scanner_errors: Scanners that could not run. These are also surfaced as
            violations when ``fail_on_scanner_error`` is enabled, but are kept
            separately so reports can explain *why* a scan failed closed.
        evaluated: False until :meth:`SecurityScanner.evaluate_policy` has run.
    """

    violations: list[str] = field(default_factory=list)
    scanner_errors: list[str] = field(default_factory=list)
    evaluated: bool = False

    @property
    def passed(self) -> bool:
        """True only when the policy has been evaluated and found no violations.

        An unevaluated decision is never a pass: that is what keeps a crash
        between scanning and reporting from being read as a clean result.
        """
        return self.evaluated and not self.violations

    def to_dict(self) -> dict:
        return {
            "evaluated": self.evaluated,
            "passed": self.passed,
            "violations": self.violations,
            "scanner_errors": self.scanner_errors,
        }


# ─── Aggregated result ────────────────────────────────────────────────────────
@dataclass
class AggregatedResult:
    """Combined result from all scanning tools.

    Attributes:
        image: Scanned image reference.
        scan_timestamp: ISO-8601 scan start timestamp (UTC, offset-aware).
        trivy: Trivy CVE scan result.
        hadolint: Hadolint Dockerfile lint result.
        gitleaks: Gitleaks secret detection result.
        sbom_results: List of SBOM generation results.
        report_paths: Map of format -> report file path.
        policy: The authoritative policy decision for this scan.
    """

    image: str
    scan_timestamp: str = field(default_factory=utc_now_iso)
    trivy: TrivyScanResult = field(default_factory=lambda: TrivyScanResult(image=""))
    hadolint: HadolintResult = field(
        default_factory=lambda: HadolintResult(dockerfile_path="N/A", skipped=True)
    )
    gitleaks: GitleaksResult = field(default_factory=lambda: GitleaksResult(scan_path="N/A"))
    sbom_results: list[SBOMResult] = field(default_factory=list)
    report_paths: dict[str, str] = field(default_factory=dict)
    policy: PolicyDecision = field(default_factory=PolicyDecision)

    @property
    def passed(self) -> bool:
        """The security verdict: True only if the configured policy is satisfied.

        This is deliberately *not* "zero findings". A LOW-severity CVE in a base
        image does not fail a build unless the configured policy says so.
        """
        return self.policy.passed

    @property
    def is_clean(self) -> bool:
        """True if every scanner ran and nothing at all was found.

        Stricter than :attr:`passed` and independent of policy thresholds.
        """
        return (
            self.trivy.passed
            and (self.hadolint.passed or self.hadolint.skipped)
            and self.gitleaks.passed
            and all(s.passed for s in self.sbom_results)
        )

    @property
    def scanner_errors(self) -> list[str]:
        """Return a description of every scanner that failed to run."""
        errors: list[str] = []
        if self.trivy.error:
            errors.append(f"Trivy CVE scan: {self.trivy.error}")
        if self.hadolint.error:
            errors.append(f"Hadolint Dockerfile lint: {self.hadolint.error}")
        if self.gitleaks.error:
            errors.append(f"Gitleaks secret scan: {self.gitleaks.error}")
        for sbom in self.sbom_results:
            if sbom.error:
                errors.append(f"SBOM ({sbom.format}): {sbom.error}")
        return errors

    @property
    def overall_severity(self) -> str:
        """Highest severity across all tools."""
        severities: list[str] = []
        severities.extend(v.severity for v in self.trivy.vulnerabilities)
        severities.extend(i.severity for i in self.hadolint.issues)
        severities.extend(f.severity for f in self.gitleaks.findings)
        return max_severity(severities) if severities else "NONE"

    def summary(self) -> str:
        if not self.policy.evaluated:
            return f"Security scan for {self.image} - Status: NOT EVALUATED"
        return (
            f"Security scan for {self.image} - "
            f"Status: {'PASSED' if self.passed else 'FAILED'} | "
            f"Overall severity: {self.overall_severity}"
        )

    def to_dict(self, max_json_vulnerabilities: int = 0) -> dict:
        """Serialise the full result.

        Args:
            max_json_vulnerabilities: Cap on individual CVE records included
                (0 = unlimited). Summary counts remain complete.
        """
        return {
            "image": self.image,
            "scan_timestamp": self.scan_timestamp,
            "passed": self.passed,
            "is_clean": self.is_clean,
            "overall_severity": self.overall_severity,
            "policy": self.policy.to_dict(),
            "trivy": self.trivy.to_dict(max_json_vulnerabilities),
            "hadolint": self.hadolint.to_dict(),
            "gitleaks": self.gitleaks.to_dict(),
            "sbom_results": [s.to_dict() for s in self.sbom_results],
            "report_paths": self.report_paths,
        }


# ─── Main scanner orchestrator ────────────────────────────────────────────────
class SecurityScanner:
    """Orchestrates all security scanning tools in a unified pipeline.

    Args:
        config: ScannerConfig instance. If None, loaded from environment.

    Example::

        scanner = SecurityScanner()
        result = scanner.scan_image("python:3.11-slim", dockerfile_path="./Dockerfile")
        if not result.passed:
            print("Security gate failed!")
    """

    def __init__(self, config: Optional[ScannerConfig] = None) -> None:
        self.config = config or ScannerConfig.from_env()
        setup_logging(self.config.log_level, self.config.log_file)

    def scan_image(
        self,
        image: str,
        dockerfile_path: Optional[str] = None,
        scan_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        generate_sbom: bool = True,
    ) -> AggregatedResult:
        """Run all security scanners against a Docker image.

        The policy is evaluated *before* reports are written, so the console
        verdict, every report format and the exit code always agree.

        Args:
            image: Docker image reference (e.g. 'nginx:1.25').
            dockerfile_path: Optional path to the Dockerfile for linting.
            scan_path: Optional directory to scan for secrets.
            output_dir: Directory to write reports and SBOMs.
            generate_sbom: Whether to generate SBOM files.

        Returns:
            AggregatedResult with all findings and an evaluated policy decision.
            Inspect ``result.passed`` for the verdict; this method does not raise
            on a policy violation.

        Example::

            result = scanner.scan_image(
                "myapp:latest",
                dockerfile_path="./Dockerfile",
                scan_path="./src",
                output_dir="./security-reports",
            )
        """
        out_dir = output_dir or self.config.report_output_dir
        result = AggregatedResult(image=image)

        console.rule("[bold cyan]🔒 Docker Security Scanner[/bold cyan]")
        console.print(f"[bold]Scanning image:[/bold] {image}")

        # ── Step 1: CVE Scan ─────────────────────────────────────────────────
        console.print("\n[bold cyan]Step 1/4:[/bold cyan] Running Trivy CVE scan...")
        try:
            trivy = TrivyScanner(self.config)
            result.trivy = trivy.scan(image)
            self._print_trivy_summary(result.trivy)
        except ScannerError as exc:
            logger.error("Trivy scan failed: %s", exc)
            result.trivy = TrivyScanResult(image=image, error=str(exc))

        # ── Step 2: Dockerfile Lint ──────────────────────────────────────────
        if dockerfile_path:
            console.print("\n[bold cyan]Step 2/4:[/bold cyan] Running Hadolint Dockerfile lint...")
            try:
                hadolint = HadolintScanner(self.config)
                result.hadolint = hadolint.scan(dockerfile_path)
                self._print_hadolint_summary(result.hadolint)
            except ScannerError as exc:
                logger.error("Hadolint scan failed: %s", exc)
                result.hadolint = HadolintResult(dockerfile_path=dockerfile_path, error=str(exc))
        else:
            console.print("\n[dim]Step 2/4: Skipping Hadolint (no Dockerfile specified).[/dim]")
            result.hadolint = HadolintResult(dockerfile_path="N/A", skipped=True)

        # ── Step 3: Secret Scan ──────────────────────────────────────────────
        effective_scan_path = scan_path or dockerfile_path or "."
        console.print(
            f"\n[bold cyan]Step 3/4:[/bold cyan] Running Gitleaks secret scan "
            f"on {effective_scan_path}..."
        )
        try:
            gitleaks = GitleaksScanner(self.config)
            result.gitleaks = gitleaks.scan(effective_scan_path)
            self._print_gitleaks_summary(result.gitleaks)
        except ScannerError as exc:
            logger.error("Gitleaks scan failed: %s", exc)
            result.gitleaks = GitleaksResult(scan_path=effective_scan_path, error=str(exc))

        # ── Step 4: SBOM Generation ──────────────────────────────────────────
        if generate_sbom:
            console.print("\n[bold cyan]Step 4/4:[/bold cyan] Generating SBOM...")
            try:
                sbom_gen = SBOMGenerator(self.config)
                result.sbom_results = sbom_gen.generate_all(image, out_dir)
                for sbom_r in result.sbom_results:
                    if sbom_r.error:
                        console.print(
                            f"  [yellow]![/yellow] {sbom_r.format.upper()} SBOM failed: "
                            f"{sbom_r.error}"
                        )
                    else:
                        console.print(
                            f"  [green]✓[/green] {sbom_r.format.upper()} SBOM: "
                            f"{sbom_r.output_path}"
                        )
            except ScannerError as exc:
                logger.warning("SBOM generation failed: %s", exc)
                result.sbom_results = [
                    SBOMResult(image=image, format=fmt, error=str(exc))
                    for fmt in self.config.sbom_formats
                ]
        else:
            console.print("\n[dim]Step 4/4: Skipping SBOM generation.[/dim]")

        # ── Policy evaluation (must precede reporting) ────────────────────────
        result.policy = self.evaluate_policy(result)

        # ── Reports ──────────────────────────────────────────────────────────
        console.print("\n[bold]Generating reports...[/bold]")
        report_gen = ReportGenerator(self.config)
        result.report_paths = report_gen.generate_all(result, out_dir)
        for fmt, path in result.report_paths.items():
            console.print(f"  [green]✓[/green] {fmt.upper()} report: {path}")

        self._print_verdict(result)
        return result

    def evaluate_policy(self, result: AggregatedResult) -> PolicyDecision:
        """Evaluate the configured security policy against a scan result.

        The policy **fails closed**. A scanner that could not run contributes a
        violation rather than zero findings, because an unscanned image is not a
        clean image.

        Args:
            result: Aggregated scan result.

        Returns:
            An evaluated :class:`PolicyDecision`.
        """
        violations: list[str] = []
        scanner_errors = result.scanner_errors

        # 1. Scanners that did not run — fail closed.
        if scanner_errors and self.config.fail_on_scanner_error:
            for err in scanner_errors:
                violations.append(f"scanner did not run ({err})")

        # 2. CVE thresholds.
        fail_on = {s.upper() for s in self.config.fail_on_severity}
        trivy = result.trivy
        if "CRITICAL" in fail_on and trivy.critical_count > self.config.critical_threshold:
            violations.append(
                f"{trivy.critical_count} CRITICAL CVEs "
                f"(threshold: {self.config.critical_threshold})"
            )
        if "HIGH" in fail_on and self.config.high_threshold > 0:
            if trivy.high_count > self.config.high_threshold:
                violations.append(
                    f"{trivy.high_count} HIGH CVEs " f"(threshold: {self.config.high_threshold})"
                )
        if "MEDIUM" in fail_on and trivy.medium_count > 0:
            violations.append(f"{trivy.medium_count} MEDIUM CVEs (MEDIUM is a failing severity)")
        if "LOW" in fail_on and trivy.low_count > 0:
            violations.append(f"{trivy.low_count} LOW CVEs (LOW is a failing severity)")

        # 3. Hardcoded secrets — any detected secret is a violation.
        if result.gitleaks.total_count > 0:
            violations.append(f"{result.gitleaks.total_count} hardcoded secrets detected")

        # 4. Dockerfile error-level findings.
        if self.config.fail_on_dockerfile_errors and result.hadolint.errors:
            codes = ", ".join(sorted({i.code for i in result.hadolint.errors}))
            violations.append(
                f"{len(result.hadolint.errors)} Dockerfile error-level findings ({codes})"
            )

        return PolicyDecision(
            violations=violations,
            scanner_errors=scanner_errors,
            evaluated=True,
        )

    def enforce_policy(self, result: AggregatedResult) -> None:
        """Evaluate the policy and raise if it was violated.

        Args:
            result: Aggregated scan result. Its ``policy`` field is updated.

        Raises:
            PolicyViolationError: If findings violate the configured policy or a
                scanner failed to run.
        """
        result.policy = self.evaluate_policy(result)
        self._print_verdict(result)
        if not result.policy.passed:
            raise PolicyViolationError(
                "Security policy violated: " + "; ".join(result.policy.violations)
            )

    # ── Pretty-print helpers ─────────────────────────────────────────────────
    @staticmethod
    def _print_verdict(result: AggregatedResult) -> None:
        """Print the authoritative verdict, including why it failed."""
        if result.policy.passed:
            console.print("\n[bold green]✅ Security policy: PASSED[/bold green]")
            return

        console.print("\n[bold red]❌ Security policy: FAILED[/bold red]")
        for violation in result.policy.violations:
            console.print(f"  [red]•[/red] {violation}")
        if result.policy.scanner_errors:
            console.print(
                "\n[yellow]Note:[/yellow] zero findings from a scanner that failed to "
                "run is not evidence of a clean image."
            )

    @staticmethod
    def _print_trivy_summary(result: TrivyScanResult) -> None:
        if not result.ran:
            console.print(f"  [yellow]![/yellow] Trivy did not run: {result.error}")
            return
        table = Table(title="CVE Summary", box=box.ROUNDED, show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev, count in [
            ("CRITICAL", result.critical_count),
            ("HIGH", result.high_count),
            ("MEDIUM", result.medium_count),
            ("LOW", result.low_count),
        ]:
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        console.print(table)

    @staticmethod
    def _print_hadolint_summary(result: HadolintResult) -> None:
        if not result.ran:
            console.print(f"  [yellow]![/yellow] Hadolint did not run: {result.error}")
            return
        status = "[green]✓ PASSED[/green]" if result.passed else "[red]✗ FAILED[/red]"
        console.print(
            f"  Hadolint: {status} - "
            f"Errors: {len(result.errors)}, Warnings: {len(result.warnings)}"
        )

    @staticmethod
    def _print_gitleaks_summary(result: GitleaksResult) -> None:
        if not result.ran:
            console.print(f"  [yellow]![/yellow] Gitleaks did not run: {result.error}")
            return
        status = "[green]✓ PASSED[/green]" if result.passed else "[red]✗ FAILED[/red]"
        console.print(f"  Gitleaks: {status} - Secrets: {result.total_count}")


# ─── CLI ──────────────────────────────────────────────────────────────────────
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--log-level", default="INFO", show_default=True, help="Logging verbosity.")
@click.version_option(package_name="docker-security-scanner", prog_name="docker-scan")
@click.pass_context
def cli(ctx: click.Context, log_level: str) -> None:
    """Docker Image Security Scanner - zero-trust container security gate.

    Exit codes: 0 = policy passed, 1 = policy violated, 2 = scanner error.
    """
    ctx.ensure_object(dict)
    try:
        config = ScannerConfig.from_env()
    except ScannerError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise SystemExit(EXIT_SCANNER_ERROR) from exc
    config.log_level = log_level
    ctx.obj["config"] = config


@cli.command("image")
@click.argument("image_ref")
@click.option("--dockerfile", "-d", default=None, help="Path to Dockerfile for linting.")
@click.option("--scan-path", "-s", default=None, help="Directory to scan for secrets.")
@click.option("--output-dir", "-o", default="reports", show_default=True)
@click.option("--no-sbom", is_flag=True, default=False, help="Skip SBOM generation.")
@click.option("--fail-on-severity", default=None, help="Override FAIL_ON_SEVERITY env var.")
@click.pass_context
def scan_image_cmd(
    ctx: click.Context,
    image_ref: str,
    dockerfile: Optional[str],
    scan_path: Optional[str],
    output_dir: str,
    no_sbom: bool,
    fail_on_severity: Optional[str],
) -> None:
    """Scan a Docker image for vulnerabilities, misconfigurations, and secrets.

    IMAGE_REF: Docker image reference (e.g. nginx:1.25, python:3.11-slim)

    \b
    Examples:
        docker-scan image nginx:1.25
        docker-scan image myapp:latest --dockerfile ./Dockerfile --output-dir ./reports
    """
    config: ScannerConfig = ctx.obj["config"]

    # `is not None` rather than truthiness: an explicitly empty
    # --fail-on-severity "" is a deliberate request to disable the CVE
    # thresholds (useful for SBOM-only runs), not an absent flag.
    if fail_on_severity is not None:
        config = config.model_copy(
            update={
                "fail_on_severity": [
                    s.strip().upper() for s in fail_on_severity.split(",") if s.strip()
                ]
            }
        )

    try:
        scanner = SecurityScanner(config)
        result = scanner.scan_image(
            image=image_ref,
            dockerfile_path=dockerfile,
            scan_path=scan_path,
            output_dir=output_dir,
            generate_sbom=not no_sbom,
        )
    except ScannerError as exc:
        console.print(f"[bold red]Scanner error:[/bold red] {exc}")
        raise SystemExit(EXIT_SCANNER_ERROR) from exc

    sys.exit(EXIT_OK if result.passed else EXIT_POLICY_VIOLATION)


@cli.command("dockerfile")
@click.argument("dockerfile_path")
@click.pass_context
def scan_dockerfile_cmd(ctx: click.Context, dockerfile_path: str) -> None:
    """Lint a Dockerfile with Hadolint.

    DOCKERFILE_PATH: Path to the Dockerfile.
    """
    config: ScannerConfig = ctx.obj["config"]
    setup_logging(config.log_level, config.log_file)
    try:
        scanner = HadolintScanner(config)
        result = scanner.scan(dockerfile_path)
    except ScannerError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(EXIT_SCANNER_ERROR) from exc

    console.print(result.summary())
    for issue in result.issues:
        color = SEVERITY_COLORS.get(issue.severity, "white")
        console.print(
            f"  [{color}]{issue.level.upper()}[/{color}] "
            f"Line {issue.line}: [{issue.code}] {issue.message}"
        )

    if not result.ran:
        console.print(f"[bold red]Hadolint did not run:[/bold red] {result.error}")
        sys.exit(EXIT_SCANNER_ERROR)
    sys.exit(EXIT_OK if result.passed else EXIT_POLICY_VIOLATION)


if __name__ == "__main__":
    cli()
