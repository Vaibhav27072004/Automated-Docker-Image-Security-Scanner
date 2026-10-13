"""
test_utils.py — Unit tests for shared helpers.

TestParseImageRef is a regression suite for the image-reference parser, which
used a lazy-optional registry group (``??``) and therefore mis-attributed the
registry of every reference that did not carry an explicit port.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import pytest

from docker_security_scanner.utils import (
    DEFAULT_REGISTRY,
    ImageRef,
    ScannerConfig,
    ScannerError,
    clean_tool_error,
    ensure_dir,
    mask_secret,
    max_severity,
    parse_image_ref,
    read_json,
    setup_logging,
    severity_rank,
    truncate_string,
    utc_now_iso,
    write_json,
)


class TestParseImageRef:
    """A registry must be detected without needing an explicit port."""

    @pytest.mark.parametrize(
        ("ref", "registry", "repository", "tag"),
        [
            ("nginx:1.25", DEFAULT_REGISTRY, "library/nginx", "1.25"),
            ("nginx", DEFAULT_REGISTRY, "library/nginx", "latest"),
            ("python:3.11-slim", DEFAULT_REGISTRY, "library/python", "3.11-slim"),
            ("org/myapp:v1", DEFAULT_REGISTRY, "org/myapp", "v1"),
            ("ghcr.io/org/myapp:v1.2.3", "ghcr.io", "org/myapp", "v1.2.3"),
            ("quay.io/prometheus/node:v1.8", "quay.io", "prometheus/node", "v1.8"),
            ("docker.io/library/nginx:1.25", "docker.io", "library/nginx", "1.25"),
            ("mcr.microsoft.com/dotnet/runtime:8.0", "mcr.microsoft.com", "dotnet/runtime", "8.0"),
            ("localhost:5000/app:v1", "localhost:5000", "app", "v1"),
            ("localhost/app", "localhost", "app", "latest"),
            (
                "registry.example.com:5000/team/app:1.0",
                "registry.example.com:5000",
                "team/app",
                "1.0",
            ),
        ],
    )
    def test_parses_registry_repository_and_tag(
        self, ref: str, registry: str, repository: str, tag: str
    ) -> None:
        parsed = parse_image_ref(ref)
        assert (parsed.registry, parsed.repository, parsed.tag) == (registry, repository, tag)

    def test_registry_qualified_reference_is_not_swallowed_into_repository(self) -> None:
        """Regression: this returned registry='docker.io', repo='ghcr.io/org/myapp'."""
        parsed = parse_image_ref("ghcr.io/org/myapp:v1.2.3")
        assert parsed.registry == "ghcr.io"
        assert "ghcr.io" not in parsed.repository

    def test_latest_tag_detection(self) -> None:
        assert parse_image_ref("ubuntu:latest").is_latest is True
        assert parse_image_ref("ubuntu:24.04").is_latest is False

    def test_digest_is_parsed_and_marks_pinned(self) -> None:
        digest = "sha256:" + "a" * 64
        parsed = parse_image_ref(f"ghcr.io/org/app@{digest}")
        assert parsed.digest == digest
        assert parsed.is_pinned is True
        assert parsed.registry == "ghcr.io"

    def test_tag_and_digest_together(self) -> None:
        digest = "sha256:" + "b" * 64
        parsed = parse_image_ref(f"nginx:1.25@{digest}")
        assert parsed.tag == "1.25"
        assert parsed.is_pinned is True

    def test_no_digest_is_not_pinned(self) -> None:
        assert parse_image_ref("nginx:1.25").is_pinned is False

    def test_full_name_round_trip(self) -> None:
        assert parse_image_ref("nginx:1.25").full_name == "docker.io/library/nginx:1.25"

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        assert parse_image_ref("  nginx:1.25  ").repository == "library/nginx"

    def test_raw_preserves_the_original_input(self) -> None:
        assert parse_image_ref("  nginx:1.25 ").raw == "  nginx:1.25 "

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "!!!bad!!!", ":", "nginx:", "/nginx", "a//b", "@sha256:xx", "UP/Bad:x!"],
    )
    def test_rejects_malformed_references(self, bad: str) -> None:
        """Regression: an empty string silently became 'library/unknown:latest'."""
        with pytest.raises(ValueError):
            parse_image_ref(bad)

    def test_repr_and_equality(self) -> None:
        a = parse_image_ref("nginx:1.25")
        b = parse_image_ref("nginx:1.25")
        assert a == b
        assert "library/nginx" in repr(a)
        assert a != "nginx:1.25"
        assert a != parse_image_ref("nginx:1.26")

    def test_eq_with_other_type_returns_not_implemented(self) -> None:
        assert ImageRef("r", "p", "t", None, "raw").__eq__(42) is NotImplemented


class TestSeverityHelpers:
    def test_rank_ordering(self) -> None:
        assert severity_rank("CRITICAL") > severity_rank("HIGH")
        assert severity_rank("HIGH") > severity_rank("MEDIUM")
        assert severity_rank("MEDIUM") > severity_rank("LOW")
        assert severity_rank("LOW") > severity_rank("UNKNOWN")

    def test_rank_is_case_insensitive(self) -> None:
        assert severity_rank("critical") == severity_rank("CRITICAL")

    def test_rank_of_garbage_is_zero(self) -> None:
        assert severity_rank("nonsense") == 0

    def test_max_severity_returns_highest(self) -> None:
        assert max_severity(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"

    def test_max_severity_empty_list(self) -> None:
        assert max_severity([]) == "NONE"


class TestMaskSecret:
    """A redacted secret must not be reconstructible from the report."""

    def test_short_secret_is_not_leaked(self) -> None:
        """Regression: mask_secret('abc') used to render as 'abc[REDACTED]'."""
        masked = mask_secret("abc")
        assert "abc" not in masked
        assert "REDACTED" in masked

    def test_two_char_secret_is_not_leaked(self) -> None:
        assert "ab" not in mask_secret("ab")

    def test_mask_width_does_not_reveal_length(self) -> None:
        assert mask_secret("a" * 8) == mask_secret("b" * 40)

    def test_empty_secret_is_handled(self) -> None:
        assert mask_secret("") == "************ [REDACTED]"

    def test_keep_prefix_only_for_long_secrets(self) -> None:
        assert mask_secret("AKIAIOSFODNN7EXAMPLE", keep=4).startswith("AKIA")

    def test_keep_prefix_ignored_for_short_secrets(self) -> None:
        assert mask_secret("abcd", keep=4).startswith("*")


class TestTruncateString:
    def test_short_string_unchanged(self) -> None:
        assert truncate_string("hello", 10) == "hello"

    def test_long_string_truncated_with_ellipsis(self) -> None:
        out = truncate_string("x" * 50, 10)
        assert len(out) == 10
        assert out.endswith("...")

    def test_exact_length_unchanged(self) -> None:
        assert truncate_string("abcde", 5) == "abcde"


class TestUtcNowIso:
    def test_is_timezone_aware_utc(self) -> None:
        """Regression: datetime.utcnow() produced a naive, offset-less string."""
        stamp = utc_now_iso()
        parsed = datetime.fromisoformat(stamp)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0

    def test_carries_an_explicit_offset(self) -> None:
        assert utc_now_iso().endswith("+00:00")


class TestFileHelpers:
    def test_ensure_dir_creates_nested_path(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c"
        assert ensure_dir(target).is_dir()

    def test_ensure_dir_is_idempotent(self, tmp_path: Path) -> None:
        ensure_dir(tmp_path / "x")
        assert ensure_dir(tmp_path / "x").is_dir()

    def test_write_then_read_json_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "data.json"
        write_json({"a": [1, 2], "b": "x"}, path)
        assert read_json(path) == {"a": [1, 2], "b": "x"}

    def test_write_json_serialises_unknown_types_via_str(self, tmp_path: Path) -> None:
        path = tmp_path / "d.json"
        write_json({"when": datetime(2024, 1, 1)}, path)
        assert "2024-01-01" in json.loads(path.read_text(encoding="utf-8"))["when"]

    def test_read_json_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            read_json(tmp_path / "nope.json")


class TestSetupLogging:
    def test_returns_named_logger(self) -> None:
        assert setup_logging("WARNING").name == "docker_security_scanner"

    def test_unknown_level_falls_back_to_info(self) -> None:
        setup_logging("NOT_A_LEVEL")
        assert logging.getLogger().level == logging.INFO

    def test_log_file_is_created(self, tmp_path: Path) -> None:
        log_file = tmp_path / "logs" / "scan.log"
        logger = setup_logging("INFO", str(log_file))
        logger.warning("hello")
        logging.shutdown()
        assert log_file.exists()


class TestScannerConfig:
    def test_defaults_are_fail_closed(self) -> None:
        config = ScannerConfig()
        assert config.fail_on_scanner_error is True
        assert config.fail_on_dockerfile_errors is True

    def test_comma_string_parsed_into_severity_list(self) -> None:
        config = ScannerConfig(fail_on_severity="critical, high")
        assert config.fail_on_severity == ["CRITICAL", "HIGH"]

    def test_severity_list_is_uppercased(self) -> None:
        assert ScannerConfig(fail_on_severity=["critical"]).fail_on_severity == ["CRITICAL"]

    def test_comma_string_parsed_into_format_list(self) -> None:
        assert ScannerConfig(report_formats="HTML, Json").report_formats == ["html", "json"]

    def test_negative_threshold_rejected(self) -> None:
        with pytest.raises(ValueError):
            ScannerConfig(critical_threshold=-1)

    def test_from_env_uses_defaults_when_unset(self) -> None:
        config = ScannerConfig.from_env()
        assert config.fail_on_severity == ["CRITICAL", "HIGH"]
        assert config.critical_threshold == 0
        assert config.high_threshold == 10
        assert config.trivy_path == "trivy"

    def test_from_env_reads_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FAIL_ON_SEVERITY", "critical")
        monkeypatch.setenv("CRITICAL_THRESHOLD", "3")
        monkeypatch.setenv("TRIVY_SKIP_UPDATE", "true")
        monkeypatch.setenv("REPORT_FORMATS", "json")
        monkeypatch.setenv("MAX_JSON_VULNERABILITIES", "7")

        config = ScannerConfig.from_env()

        assert config.fail_on_severity == ["CRITICAL"]
        assert config.critical_threshold == 3
        assert config.trivy_skip_update is True
        assert config.report_formats == ["json"]
        assert config.max_json_vulnerabilities == 7

    def test_from_env_blank_optional_becomes_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HADOLINT_CONFIG", "")
        monkeypatch.setenv("GITLEAKS_CONFIG", "")
        config = ScannerConfig.from_env()
        assert config.hadolint_config is None
        assert config.gitleaks_config is None

    def test_from_env_rejects_non_numeric_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A typo in CI config must fail loudly, not silently use the default."""
        monkeypatch.setenv("CRITICAL_THRESHOLD", "lots")
        with pytest.raises(ScannerError, match="not an integer"):
            ScannerConfig.from_env()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("true", True),
            ("TRUE", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("", False),
        ],
    )
    def test_bool_env_parsing(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
    ) -> None:
        monkeypatch.setenv("TRIVY_SKIP_UPDATE", raw)
        assert ScannerConfig.from_env().trivy_skip_update is expected


class TestCleanToolError:
    """Tool stderr goes into reports and PR comments; it must stay readable."""

    def test_strips_ansi_colour_codes(self) -> None:
        assert clean_tool_error("\x1b[31mFTL\x1b[0m boom") == "FTL boom"

    def test_drops_ascii_art_banner_lines(self) -> None:
        raw = "    ○\n    │╲\n    │ ○\n    ○ ░\n    ░    gitleaks\n\nFTL unable to load config"
        cleaned = clean_tool_error(raw)
        assert "unable to load config" in cleaned
        # All banner artwork is gone; only real words survive.
        for glyph in "╲│○░":
            assert glyph not in cleaned

    def test_collapses_to_a_single_line(self) -> None:
        assert "\n" not in clean_tool_error("line one\nline two\nline three")

    def test_truncates(self) -> None:
        assert len(clean_tool_error("x " * 500)) <= 300

    def test_empty_input(self) -> None:
        assert clean_tool_error("") == ""

    def test_whitespace_only_input(self) -> None:
        assert clean_tool_error("   \n\n  ") == ""
