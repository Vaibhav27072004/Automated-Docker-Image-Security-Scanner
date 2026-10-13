"""
test_sbom.py — Unit tests for SBOM generation.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from docker_security_scanner.sbom_generator import (
    SBOMComponent,
    SBOMGenerator,
    SBOMResult,
)
from docker_security_scanner.utils import (
    ScanExecutionError,
    ScannerConfig,
    ToolNotFoundError,
)

CYCLONEDX_DOC = {
    "bomFormat": "CycloneDX",
    "components": [
        {
            "name": "openssl",
            "version": "3.0.11",
            "purl": "pkg:deb/debian/openssl@3.0.11",
            "type": "library",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "supplier": {"name": "Debian"},
        },
        {
            "name": "zlib",
            "version": "1.2.13",
            "purl": "pkg:deb/debian/zlib@1.2.13",
            "type": "library",
            "licenses": [{"license": {"id": "Zlib"}}],
        },
        {"name": "nolicense", "version": "1.0", "licenses": [{"expression": "MIT"}]},
    ],
}

SPDX_DOC = {
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {
            "name": "openssl",
            "versionInfo": "3.0.11",
            "licenseDeclared": "Apache-2.0",
            "supplier": "Organization: Debian",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0.11"}
            ],
        },
        {"name": "zlib", "versionInfo": "1.2.13", "licenseDeclared": "NOASSERTION"},
    ],
}


def _sbom_writer(payload: str | None, returncode: int = 0, stderr: str = ""):
    """Return a subprocess.run side effect that writes Trivy's SBOM output."""

    def _run(cmd, *args, **kwargs):
        if payload is not None:
            Path(cmd[cmd.index("--output") + 1]).write_text(payload, encoding="utf-8")
        return MagicMock(returncode=returncode, stdout="", stderr=stderr)

    return _run


class TestSBOMGenerator:
    @patch("subprocess.run")
    def test_tool_not_found_raises(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        mock_run.side_effect = FileNotFoundError
        with pytest.raises(ToolNotFoundError, match="trivy"):
            SBOMGenerator(config)

    @patch("subprocess.run")
    def test_unsupported_format_rejected(self, mock_run: MagicMock, config: ScannerConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        with pytest.raises(ValueError, match="Unsupported SBOM format"):
            generator.generate("alpine:3.19", "swid")

    @patch("subprocess.run")
    def test_generates_cyclonedx(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(json.dumps(CYCLONEDX_DOC))

        result = generator.generate("alpine:3.19", "cyclonedx", str(tmp_path))

        assert result.error == ""
        assert result.total_components == 3
        assert result.components[0].name == "openssl"
        assert result.components[0].supplier == "Debian"

    @patch("subprocess.run")
    def test_generates_spdx(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(json.dumps(SPDX_DOC))

        result = generator.generate("alpine:3.19", "spdx", str(tmp_path))

        assert result.total_components == 2
        assert result.components[0].purl == "pkg:deb/debian/openssl@3.0.11"
        # NOASSERTION must not be recorded as a real license.
        assert result.components[1].licenses == []

    @patch("subprocess.run")
    def test_output_filename_has_no_doubled_extension(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        """Regression: the SPDX file was named '..._spdx.spdx.json'."""
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(json.dumps(SPDX_DOC))

        result = generator.generate("alpine:3.19", "spdx", str(tmp_path))

        assert Path(result.output_path).name == "sbom_alpine_3.19_spdx.json"

    @patch("subprocess.run")
    def test_registry_qualified_image_produces_a_safe_filename(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(json.dumps(CYCLONEDX_DOC))

        result = generator.generate("ghcr.io/org/app:v1", "cyclonedx", str(tmp_path))

        name = Path(result.output_path).name
        assert "/" not in name and ":" not in name
        assert Path(result.output_path).is_file()

    @patch("subprocess.run")
    def test_trivy_failure_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(None, returncode=1, stderr="db error")

        result = generator.generate("alpine:3.19", "cyclonedx", str(tmp_path))

        assert result.passed is False
        assert "db error" in result.error

    @patch("subprocess.run")
    def test_missing_output_file_sets_error(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(None, returncode=0, stderr="")

        result = generator.generate("alpine:3.19", "cyclonedx", str(tmp_path))
        assert result.passed is False

    @patch("subprocess.run")
    def test_timeout_raises(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)
        with pytest.raises(ScanExecutionError, match="timed out"):
            generator.generate("slow:image", "cyclonedx", str(tmp_path))

    @patch("subprocess.run")
    def test_unparseable_sbom_is_tolerated(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        """A malformed SBOM still counts as generated; components stay empty."""
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer("{not json")

        result = generator.generate("alpine:3.19", "cyclonedx", str(tmp_path))

        assert result.error == ""
        assert result.total_components == 0

    @patch("subprocess.run")
    def test_generate_all_covers_every_configured_format(
        self, mock_run: MagicMock, config: ScannerConfig, tmp_path: Path
    ) -> None:
        config.sbom_formats = ["cyclonedx", "spdx"]
        mock_run.return_value = MagicMock(returncode=0)
        generator = SBOMGenerator(config)
        mock_run.side_effect = _sbom_writer(json.dumps(CYCLONEDX_DOC))

        results = generator.generate_all("alpine:3.19", str(tmp_path))

        assert [r.format for r in results] == ["cyclonedx", "spdx"]


class TestSBOMResult:
    @staticmethod
    def _result() -> SBOMResult:
        r = SBOMResult(image="alpine:3.19", format="cyclonedx")
        r.components = [
            SBOMComponent("openssl", "3.0", "purl1", ["Apache-2.0"], "library"),
            SBOMComponent("zlib", "1.2", "purl2", ["Zlib"], "library"),
            SBOMComponent("app", "1.0", "purl3", ["Apache-2.0"], "application"),
        ]
        return r

    def test_total_components(self) -> None:
        assert self._result().total_components == 3

    def test_unique_licenses_are_sorted_and_deduped(self) -> None:
        assert self._result().unique_licenses() == ["Apache-2.0", "Zlib"]

    def test_components_by_type(self) -> None:
        grouped = self._result().components_by_type()
        assert set(grouped) == {"library", "application"}
        assert len(grouped["library"]) == 2

    def test_passed_is_false_on_error(self) -> None:
        assert SBOMResult(image="x", format="spdx", error="boom").passed is False

    def test_summary_mentions_counts(self) -> None:
        assert "3 components" in self._result().summary()

    def test_to_dict_shape(self) -> None:
        d = self._result().to_dict()
        for key in ("image", "format", "summary", "passed", "error", "components"):
            assert key in d
        assert d["summary"]["components_by_type"] == {"library": 2, "application": 1}

    def test_component_to_dict(self) -> None:
        d = SBOMComponent("openssl", "3.0", "purl", ["MIT"], "library", "Debian").to_dict()
        assert d["name"] == "openssl"
        assert d["licenses"] == ["MIT"]
        assert d["supplier"] == "Debian"
