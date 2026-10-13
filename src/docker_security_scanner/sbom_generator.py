"""
sbom_generator.py — Software Bill of Materials (SBOM) generation.

Uses Trivy's built-in SBOM generation capability to produce CycloneDX and
SPDX format SBOMs from Docker images, enabling compliance reporting for
government contracts, enterprise security standards, and supply-chain audits.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .utils import (
    ScanExecutionError,
    ScannerConfig,
    ToolNotFoundError,
    clean_tool_error,
    ensure_dir,
    utc_now_iso,
)

logger = logging.getLogger("docker_security_scanner.sbom")


@dataclass
class SBOMComponent:
    """A single software component in the SBOM.

    Attributes:
        name: Package name.
        version: Installed version.
        purl: Package URL (PURL) string.
        licenses: List of SPDX license identifiers.
        package_type: Package ecosystem (e.g. pypi, npm, deb, rpm).
        supplier: Upstream supplier / maintainer.
    """

    name: str
    version: str
    purl: str
    licenses: list[str] = field(default_factory=list)
    package_type: str = "unknown"
    supplier: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "licenses": self.licenses,
            "package_type": self.package_type,
            "supplier": self.supplier,
        }


@dataclass
class SBOMResult:
    """Result of SBOM generation for a Docker image.

    Attributes:
        image: Scanned image reference.
        format: SBOM format (cyclonedx | spdx).
        scan_timestamp: ISO-8601 timestamp.
        components: All detected software components.
        output_path: File path of the generated SBOM.
        error: Non-empty if generation encountered an error.
    """

    image: str
    format: str
    scan_timestamp: str = field(default_factory=utc_now_iso)
    components: list[SBOMComponent] = field(default_factory=list)
    output_path: str = ""
    error: str = ""

    @property
    def total_components(self) -> int:
        return len(self.components)

    @property
    def passed(self) -> bool:
        return not self.error

    def unique_licenses(self) -> list[str]:
        """Return a deduplicated list of all licenses found."""
        seen: set[str] = set()
        for comp in self.components:
            seen.update(comp.licenses)
        return sorted(seen)

    def components_by_type(self) -> dict[str, list[SBOMComponent]]:
        """Group components by package type."""
        result: dict[str, list[SBOMComponent]] = {}
        for comp in self.components:
            result.setdefault(comp.package_type, []).append(comp)
        return result

    def summary(self) -> str:
        return (
            f"SBOM ({self.format}) for {self.image} — "
            f"{self.total_components} components, "
            f"{len(self.unique_licenses())} unique licenses"
        )

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "format": self.format,
            "scan_timestamp": self.scan_timestamp,
            "output_path": self.output_path,
            "summary": {
                "total_components": self.total_components,
                "unique_licenses": self.unique_licenses(),
                "components_by_type": {k: len(v) for k, v in self.components_by_type().items()},
            },
            "passed": self.passed,
            "error": self.error,
            "components": [c.to_dict() for c in self.components],
        }


class SBOMGenerator:
    """Generate SBOMs for Docker images using Trivy.

    Args:
        config: ScannerConfig instance.

    Example::

        generator = SBOMGenerator(config)
        result = generator.generate("nginx:1.25", "cyclonedx", output_dir="reports")
        print(result.summary())
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self._check_tool_available()

    def _check_tool_available(self) -> None:
        try:
            subprocess.run(
                [self.config.trivy_path, "--version"],
                capture_output=True,
                check=True,
            )
        except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
            raise ToolNotFoundError("trivy") from exc

    def generate(
        self,
        image: str,
        sbom_format: str = "cyclonedx",
        output_dir: str = "reports",
    ) -> SBOMResult:
        """Generate an SBOM for a Docker image.

        Args:
            image: Docker image reference to analyse.
            sbom_format: 'cyclonedx' or 'spdx'.
            output_dir: Directory to write the SBOM file to.

        Returns:
            SBOMResult with component inventory.

        Raises:
            ScanExecutionError: If Trivy fails.
            ValueError: If sbom_format is not supported.
        """
        sbom_format = sbom_format.lower()
        if sbom_format not in ("cyclonedx", "spdx"):
            raise ValueError(f"Unsupported SBOM format: {sbom_format}")

        logger.info("Generating %s SBOM for image: %s", sbom_format.upper(), image)

        out_dir = ensure_dir(output_dir)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", image)
        output_file = out_dir / f"sbom_{safe_name}_{sbom_format}.json"

        trivy_format = "cyclonedx" if sbom_format == "cyclonedx" else "spdx-json"

        cmd = [
            self.config.trivy_path,
            "image",
            "--format",
            trivy_format,
            "--output",
            str(output_file),
            "--cache-dir",
            self.config.trivy_cache_dir,
        ]
        if self.config.trivy_skip_update:
            cmd.append("--skip-db-update")
        cmd.append(image)

        result = SBOMResult(image=image, format=sbom_format)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(f"SBOM generation timed out for {image}") from exc
        except FileNotFoundError as exc:
            raise ToolNotFoundError("trivy") from exc

        if proc.returncode != 0 or not output_file.exists():
            result.error = clean_tool_error(proc.stderr or "") or (
                f"Trivy exited with code {proc.returncode} and wrote no SBOM."
            )
            logger.error("SBOM generation failed: %s", result.error)
            return result

        result.output_path = str(output_file)

        # Parse the output file to extract component list
        if output_file.exists():
            try:
                result.components = self._parse_components(output_file, sbom_format)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not parse SBOM components: %s", exc)

        logger.info(
            "SBOM generated: %d components → %s",
            result.total_components,
            output_file,
        )
        return result

    def generate_all(self, image: str, output_dir: str = "reports") -> list[SBOMResult]:
        """Generate all configured SBOM formats.

        Args:
            image: Docker image reference.
            output_dir: Output directory.

        Returns:
            List of SBOMResult, one per format.
        """
        results: list[SBOMResult] = []
        for fmt in self.config.sbom_formats:
            results.append(self.generate(image, fmt, output_dir))
        return results

    @staticmethod
    def _parse_components(sbom_file: Path, sbom_format: str) -> list[SBOMComponent]:
        """Parse components from a generated SBOM file.

        Args:
            sbom_file: Path to the SBOM file.
            sbom_format: Format ('cyclonedx' or 'spdx').

        Returns:
            List of SBOMComponent objects.
        """
        with open(sbom_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        components: list[SBOMComponent] = []

        if sbom_format == "cyclonedx":
            for comp in data.get("components", []):
                licenses = [
                    lic.get("license", {}).get("id", "")
                    for lic in comp.get("licenses", [])
                    if lic.get("license", {}).get("id")
                ]
                components.append(
                    SBOMComponent(
                        name=comp.get("name", ""),
                        version=comp.get("version", ""),
                        purl=comp.get("purl", ""),
                        licenses=licenses,
                        package_type=comp.get("type", "library"),
                        supplier=(
                            comp.get("supplier", {}).get("name", "")
                            if isinstance(comp.get("supplier"), dict)
                            else ""
                        ),
                    )
                )
        else:
            # SPDX format
            for pkg in data.get("packages", []):
                purl = next(
                    (
                        ref.get("referenceLocator", "")
                        for ref in pkg.get("externalRefs", [])
                        if ref.get("referenceType") == "purl"
                    ),
                    "",
                )
                declared_lic = pkg.get("licenseDeclared", "NOASSERTION")
                licenses = [] if declared_lic in ("NOASSERTION", "NONE", "") else [declared_lic]
                components.append(
                    SBOMComponent(
                        name=pkg.get("name", ""),
                        version=pkg.get("versionInfo", ""),
                        purl=purl,
                        licenses=licenses,
                        package_type="library",
                        supplier=pkg.get("supplier", ""),
                    )
                )

        return components
