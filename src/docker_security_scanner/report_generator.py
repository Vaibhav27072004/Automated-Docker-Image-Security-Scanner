"""
report_generator.py — Multi-format security report generation.

Generates HTML dashboards, JSON structured reports, and Markdown summaries
from aggregated scanner results. Designed to integrate with GitHub Actions
PR comments and artifact uploads.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .utils import ScannerConfig, ensure_dir, write_json

if TYPE_CHECKING:
    from .scanner import AggregatedResult

logger = logging.getLogger("docker_security_scanner.report")

# Rows rendered in the detail tables. The JSON report carries the full data set
# (subject to ScannerConfig.max_json_vulnerabilities); these caps only keep the
# human-facing documents readable.
_HTML_VULN_LIMIT = 50
_MD_CRITICAL_LIMIT = 5
_MD_SECRET_LIMIT = 10


def md_cell(value: object, max_len: int = 160) -> str:
    """Escape a value for safe inclusion in a Markdown table cell.

    Scanner output is untrusted text: a package name, filename or CVE title
    containing a pipe or a newline would otherwise break the table apart, and
    the Markdown report is posted verbatim into pull request comments.

    Args:
        value: Any value to render in a table cell.
        max_len: Maximum rendered length before truncation.

    Returns:
        A single-line, pipe-safe string.

    Example:
        >>> md_cell("a|b")
        'a\\\\|b'
        >>> md_cell("line1\\nline2")
        'line1 line2'
    """
    text = str(value)
    # Collapse any newline so a cell can never terminate the table row.
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    # Escape Markdown structural characters.
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


TEMPLATE_DIR = Path(__file__).parent / "templates"
HTML_TEMPLATE_NAME = "security_report.html.j2"


class ReportGenerator:
    """Generate security scan reports in multiple formats.

    Args:
        config: ScannerConfig instance.

    Example::

        generator = ReportGenerator(config)
        paths = generator.generate_all(result, output_dir="reports")
        print(paths)
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def generate_all(
        self, result: "AggregatedResult", output_dir: str = "reports"
    ) -> dict[str, str]:
        """Generate all configured report formats.

        Args:
            result: Aggregated scan result. Its policy decision must already be
                evaluated, so every format reports the same verdict.
            output_dir: Directory to write reports.

        Returns:
            Dictionary mapping format -> file path.

        Raises:
            ValueError: If an unknown format is configured.
        """
        out = ensure_dir(output_dir)
        paths: dict[str, str] = {}
        writers = {
            "html": self._generate_html,
            "json": self._generate_json,
            "markdown": self._generate_markdown,
        }

        for fmt in self.config.report_formats:
            writer = writers.get(fmt)
            if writer is None:
                raise ValueError(f"Unknown report format {fmt!r}. Supported: {sorted(writers)}")
            paths[fmt] = writer(result, out)

        logger.info("Reports written to %s: %s", out, list(paths.keys()))
        return paths

    def _generate_html(self, result: "AggregatedResult", out: Path) -> str:
        """Render the HTML dashboard report.

        Autoescaping is enabled for the template, so every interpolated scanner
        value (image name, package name, CVE title, lint message) is escaped and
        cannot inject markup into the report.
        """
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(
                enabled_extensions=("html", "j2"), default_for_string=True
            ),
        )
        template = env.get_template(HTML_TEMPLATE_NAME)
        html_content = template.render(result=result, vuln_limit=_HTML_VULN_LIMIT)
        output_path = out / "security_report.html"
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report: %s", output_path)
        return str(output_path)

    def _generate_json(self, result: "AggregatedResult", out: Path) -> str:
        """Write the JSON structured report."""
        output_path = out / "security_report.json"
        write_json(result.to_dict(self.config.max_json_vulnerabilities), output_path)
        logger.info("JSON report: %s", output_path)
        return str(output_path)

    def _generate_markdown(self, result: "AggregatedResult", out: Path) -> str:
        """Write a Markdown summary for GitHub PR comments."""
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        trivy, hadolint, gitleaks = result.trivy, result.hadolint, result.gitleaks

        lines = [
            f"## 🔒 Docker Security Scan — {status}",
            "",
            f"**Image:** `{md_cell(result.image)}`  ",
            f"**Scanned:** {result.scan_timestamp}",
            "",
            "### 📊 Summary",
            "",
            "| Check | Status | Findings |",
            "|-------|--------|----------|",
            f"| CVE Scan (Trivy) | {self._status_icon(trivy)} | "
            f"CRITICAL: {trivy.critical_count}, HIGH: {trivy.high_count}, "
            f"MEDIUM: {trivy.medium_count}, LOW: {trivy.low_count} |",
            f"| Dockerfile Lint (Hadolint) | {self._status_icon(hadolint)} | "
            f"{hadolint.total_count} issues ({len(hadolint.errors)} error-level) |",
            f"| Secret Detection (Gitleaks) | {self._status_icon(gitleaks)} | "
            f"{gitleaks.total_count} secrets found |",
        ]

        if result.policy.violations:
            lines += ["", "### ❌ Policy Violations", ""]
            lines += [f"- {md_cell(v)}" for v in result.policy.violations]

        if result.policy.scanner_errors:
            lines += [
                "",
                "### ⚠️ Scanners That Did Not Run",
                "",
                "Zero findings from a failed scanner is not evidence of a clean image.",
                "",
            ]
            lines += [f"- {md_cell(e)}" for e in result.policy.scanner_errors]

        if trivy.critical_count > 0:
            lines += ["", f"### 🚨 Critical Vulnerabilities (Top {_MD_CRITICAL_LIMIT})", ""]
            lines.append("| CVE ID | Package | Installed | Fixed | CVSS |")
            lines.append("|--------|---------|-----------|-------|------|")
            for v in trivy.by_severity("CRITICAL")[:_MD_CRITICAL_LIMIT]:
                lines.append(
                    f"| [{md_cell(v.id)}]({v.nvd_url}) | {md_cell(v.package_name)} | "
                    f"{md_cell(v.installed_version)} | {md_cell(v.fixed_version)} | "
                    f"{v.cvss_score} |"
                )

        if hadolint.errors:
            lines += ["", "### 📋 Dockerfile Errors", ""]
            lines.append("| Code | Line | Message |")
            lines.append("|------|------|---------|")
            for i in hadolint.errors:
                lines.append(f"| {md_cell(i.code)} | {i.line} | {md_cell(i.message)} |")

        if gitleaks.findings:
            lines += ["", "### 🔑 Secrets Detected", ""]
            lines.append("| Rule | File | Line | Severity |")
            lines.append("|------|------|------|----------|")
            for f in gitleaks.findings[:_MD_SECRET_LIMIT]:
                lines.append(
                    f"| {md_cell(f.rule_id)} | `{md_cell(f.file)}` | "
                    f"{f.line_number} | {f.severity} |"
                )
            if gitleaks.total_count > _MD_SECRET_LIMIT:
                lines.append("")
                lines.append(f"_Showing {_MD_SECRET_LIMIT} of {gitleaks.total_count} findings._")

        output_path = out / "security_report.md"
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Markdown report: %s", output_path)
        return str(output_path)

    @staticmethod
    def _status_icon(scan_result: object) -> str:
        """Return a status glyph that distinguishes 'clean' from 'did not run'."""
        if not getattr(scan_result, "ran", True):
            return "⚠️ did not run"
        if getattr(scan_result, "skipped", False):
            return "➖ skipped"
        return "✅" if getattr(scan_result, "passed", False) else "❌"
