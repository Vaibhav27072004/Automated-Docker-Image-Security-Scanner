"""
utils.py — Shared helper utilities for Docker Security Scanner.

Provides:
  - Logging configuration
  - Docker image tag parsing
  - Severity scoring & ordering
  - File I/O helpers
  - Custom exception hierarchy
  - Configuration management via Pydantic + python-dotenv
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator
from rich.console import Console
from rich.logging import RichHandler

# ─── Load .env ───────────────────────────────────────────────────────────────
load_dotenv()


def _make_console() -> Console:
    """Build the shared rich console so it cannot crash on a Windows terminal.

    On Windows the interpreter's stdout defaults to the ANSI code page (cp1252),
    and writing any character outside it raises ``UnicodeEncodeError`` — which
    previously aborted a scan on the very first banner line. Re-encoding the
    streams as UTF-8 with ``errors="replace"`` makes output lossy at worst
    instead of fatal, and ``legacy_windows=False`` keeps rich on ANSI/VT
    sequences rather than the legacy Win32 console API.

    Returns:
        A configured :class:`rich.console.Console`.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - stream not reconfigurable
            pass
    return Console(legacy_windows=False, soft_wrap=False)


# ─── Rich console (shared) ───────────────────────────────────────────────────
console = _make_console()

# ─── Severity constants & ordering ───────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1,
    "NONE": 0,
}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
    "NONE": "green",
}


def utc_now_iso() -> str:
    """Return the current UTC time as a timezone-aware ISO-8601 string.

    ``datetime.utcnow()`` is deprecated from Python 3.12 and returns a *naive*
    datetime, so its ISO form carries no offset and reports render as if the
    timestamp were local time. This always emits an explicit ``+00:00``.

    Returns:
        ISO-8601 timestamp with a UTC offset, e.g. ``2024-05-01T12:00:00+00:00``.
    """
    return datetime.now(timezone.utc).isoformat()


# ─── Custom Exceptions ────────────────────────────────────────────────────────
class ScannerError(Exception):
    """Base exception for all scanner errors."""


class ToolNotFoundError(ScannerError):
    """Raised when a required external tool is not installed or not on PATH."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            f"Required tool '{tool_name}' not found. "
            f"Please install it and ensure it is on your PATH."
        )
        self.tool_name = tool_name


class DockerfileNotFoundError(ScannerError):
    """Raised when the specified Dockerfile does not exist."""


class ScanPathNotFoundError(ScannerError):
    """Raised when the path requested for a secret scan does not exist."""


class ImageBuildError(ScannerError):
    """Raised when the Docker image build fails."""


class ScanExecutionError(ScannerError):
    """Raised when a scanner subprocess fails unexpectedly."""


class PolicyViolationError(ScannerError):
    """Raised when the scan result violates security policy (e.g. critical CVEs)."""

    def __init__(self, message: str, severity: str = "CRITICAL") -> None:
        super().__init__(message)
        self.severity = severity


# ─── Configuration Model ─────────────────────────────────────────────────────
class ScannerConfig(BaseModel):
    """Pydantic model for scanner configuration loaded from env / config file."""

    # Severity policy
    fail_on_severity: list[str] = Field(
        default_factory=lambda: ["CRITICAL", "HIGH"],
        description="Severity levels that trigger a pipeline failure.",
    )
    critical_threshold: int = Field(
        default=0, ge=0, description="Max CRITICAL CVEs before hard-fail (0 = any)."
    )
    high_threshold: int = Field(
        default=10, ge=0, description="Max HIGH CVEs before hard-fail (0 = disabled)."
    )
    fail_on_dockerfile_errors: bool = Field(
        default=True,
        description="Treat Hadolint error-level findings as a policy violation.",
    )
    fail_on_scanner_error: bool = Field(
        default=True,
        description=(
            "Fail closed when a scanner could not run. Disabling this allows a "
            "scan to report PASSED on the strength of zero evidence."
        ),
    )

    # Tool paths
    trivy_path: str = Field(default="trivy")
    hadolint_path: str = Field(default="hadolint")
    gitleaks_path: str = Field(default="gitleaks")

    # Trivy options
    trivy_cache_dir: str = Field(default=".trivy-cache")
    trivy_skip_update: bool = Field(default=False)

    # Hadolint options
    hadolint_config: Optional[str] = Field(default=None)
    hadolint_ignore: list[str] = Field(default_factory=list)

    # Gitleaks options
    gitleaks_config: Optional[str] = Field(default=None)

    # Reporting
    report_output_dir: str = Field(default="reports")
    report_formats: list[str] = Field(default_factory=lambda: ["html", "json", "markdown"])
    sbom_formats: list[str] = Field(default_factory=lambda: ["cyclonedx", "spdx"])
    max_json_vulnerabilities: int = Field(
        default=1000,
        ge=0,
        description=(
            "Cap on individual CVE records written to the JSON report "
            "(0 = unlimited). Summary counts are always complete."
        ),
    )

    # Logging
    log_level: str = Field(default="INFO")
    log_file: Optional[str] = Field(default=None)

    @field_validator("fail_on_severity", mode="before")
    @classmethod
    def _parse_severity_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [s.strip().upper() for s in v.split(",") if s.strip()]
        return [s.upper() for s in v]

    @field_validator("report_formats", "sbom_formats", "hadolint_ignore", mode="before")
    @classmethod
    def _parse_comma_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [s.strip().lower() for s in v.split(",") if s.strip()]
        return list(v)

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Create a ScannerConfig instance from environment variables.

        Values arrive as strings and are coerced by the field validators above,
        so the comma-separated list variables are passed through verbatim.
        """
        return cls(
            fail_on_severity=_env_str("FAIL_ON_SEVERITY", "CRITICAL,HIGH"),
            critical_threshold=_env_int("CRITICAL_THRESHOLD", 0),
            high_threshold=_env_int("HIGH_THRESHOLD", 10),
            fail_on_dockerfile_errors=_env_bool("FAIL_ON_DOCKERFILE_ERRORS", True),
            fail_on_scanner_error=_env_bool("FAIL_ON_SCANNER_ERROR", True),
            trivy_path=_env_str("TRIVY_PATH", "trivy"),
            hadolint_path=_env_str("HADOLINT_PATH", "hadolint"),
            gitleaks_path=_env_str("GITLEAKS_PATH", "gitleaks"),
            trivy_cache_dir=_env_str("TRIVY_CACHE_DIR", ".trivy-cache"),
            trivy_skip_update=_env_bool("TRIVY_SKIP_UPDATE", False),
            hadolint_config=os.getenv("HADOLINT_CONFIG") or None,
            hadolint_ignore=_env_str("HADOLINT_IGNORE", ""),
            gitleaks_config=os.getenv("GITLEAKS_CONFIG") or None,
            report_output_dir=_env_str("REPORT_OUTPUT_DIR", "reports"),
            report_formats=_env_str("REPORT_FORMATS", "html,json,markdown"),
            sbom_formats=_env_str("SBOM_FORMATS", "cyclonedx,spdx"),
            max_json_vulnerabilities=_env_int("MAX_JSON_VULNERABILITIES", 1000),
            log_level=_env_str("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE") or None,
        )


# ─── Environment helpers ──────────────────────────────────────────────────────
def _env_str(name: str, default: str) -> str:
    """Read a string environment variable, falling back to ``default``."""
    value = os.getenv(name)
    return default if value is None else value


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable.

    Raises:
        ScannerError: If the variable is set but is not a valid integer.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ScannerError(f"Environment variable {name}={raw!r} is not an integer.") from exc


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable (``true/1/yes/on`` are true)."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# ─── Logging setup ───────────────────────────────────────────────────────────
def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure rich-based logging for the scanner.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional file path to also write logs to.

    Returns:
        Configured root logger.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [
        RichHandler(console=console, rich_tracebacks=True, markup=True)
    ]

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    return logging.getLogger("docker_security_scanner")


# ─── Docker image parsing ─────────────────────────────────────────────────────
class ImageRef:
    """Parsed Docker image reference.

    Attributes:
        registry: Registry hostname (e.g. docker.io, ghcr.io).
        repository: Image repository path.
        tag: Image tag (default: latest).
        digest: Optional SHA256 digest.
        raw: Original unparsed string.
    """

    __slots__ = ("registry", "repository", "tag", "digest", "raw")

    def __init__(
        self,
        registry: str,
        repository: str,
        tag: str,
        digest: Optional[str],
        raw: str,
    ) -> None:
        self.registry = registry
        self.repository = repository
        self.tag = tag
        self.digest = digest
        self.raw = raw

    @property
    def full_name(self) -> str:
        """Fully-qualified image name without digest."""
        return f"{self.registry}/{self.repository}:{self.tag}"

    @property
    def is_latest(self) -> bool:
        """Return True if the image uses the :latest tag."""
        return self.tag == "latest"

    @property
    def is_pinned(self) -> bool:
        """Return True if the image is pinned to a specific digest."""
        return self.digest is not None

    def __repr__(self) -> str:
        return (
            f"ImageRef(registry={self.registry!r}, repository={self.repository!r}, "
            f"tag={self.tag!r}, digest={self.digest!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ImageRef):
            return NotImplemented
        return (
            self.registry == other.registry
            and self.repository == other.repository
            and self.tag == other.tag
            and self.digest == other.digest
        )


# A reference is "<name>[:<tag>][@<digest>]" where <name> is
# "[<registry>/]<repository>". The registry is only the first path segment when
# that segment actually looks like a host: it contains a dot, carries an
# explicit port, or is exactly "localhost". Anything else is part of the
# repository path (e.g. "org/myapp" on Docker Hub).
_DIGEST_RE = re.compile(r"^(?P<name>.*?)@(?P<digest>[a-zA-Z0-9][a-zA-Z0-9._-]*:[a-fA-F0-9]{32,})$")
_TAG_RE = re.compile(r"^(?P<name>.*):(?P<tag>[a-zA-Z0-9_][a-zA-Z0-9._-]*)$")
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/]*$")
_REGISTRY_RE = re.compile(r"^(?:localhost|[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z0-9._-]+)(?::\d+)?$")
_PORTED_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*:\d+$")

DEFAULT_REGISTRY = "docker.io"


def _looks_like_registry(segment: str) -> bool:
    """Return True if a leading path segment should be treated as a registry host."""
    return bool(_REGISTRY_RE.match(segment) or _PORTED_HOST_RE.match(segment))


def parse_image_ref(image: str) -> ImageRef:
    """Parse a Docker image reference string into an :class:`ImageRef`.

    Args:
        image: Docker image reference (e.g. ``nginx:1.25``, ``ghcr.io/org/img:v1``).

    Returns:
        Parsed :class:`ImageRef`.

    Raises:
        ValueError: If the image reference is empty or cannot be parsed.

    Example:
        >>> ref = parse_image_ref("python:3.11-slim")
        >>> ref.repository
        'library/python'
        >>> ref.tag
        '3.11-slim'
        >>> parse_image_ref("ghcr.io/org/myapp:v1").registry
        'ghcr.io'
    """
    raw = image
    image = image.strip()
    if not image:
        raise ValueError("Image reference is empty.")

    # 1. Split off an optional @digest suffix.
    digest: Optional[str] = None
    digest_match = _DIGEST_RE.match(image)
    if digest_match:
        image = digest_match.group("name")
        digest = digest_match.group("digest")
        if not image:
            raise ValueError(f"Cannot parse image reference: {raw!r}")

    # 2. Split off an optional :tag suffix. A colon in the *first* segment is a
    #    registry port, not a tag (e.g. "localhost:5000/app"), so only treat the
    #    colon as a tag separator when it appears after the last '/'.
    tag: Optional[str] = None
    last_slash = image.rfind("/")
    tail = image[last_slash + 1 :]
    if ":" in tail:
        tag_match = _TAG_RE.match(image)
        if not tag_match:
            raise ValueError(f"Cannot parse image reference: {raw!r}")
        image = tag_match.group("name")
        tag = tag_match.group("tag")

    if not image or "//" in image:
        raise ValueError(f"Cannot parse image reference: {raw!r}")

    # 3. Decide whether the leading segment is a registry host. This must happen
    #    before validating the remainder, because a registry may carry a port
    #    (":5000") which is not legal inside a repository path.
    registry = DEFAULT_REGISTRY
    repository = image
    if "/" in image:
        head, rest = image.split("/", 1)
        if rest and _looks_like_registry(head):
            registry = head
            repository = rest

    if not repository or not _NAME_RE.match(repository):
        raise ValueError(f"Cannot parse image reference: {raw!r}")

    # Normalise official Docker Hub images (e.g. "nginx" → "library/nginx").
    if registry == DEFAULT_REGISTRY and "/" not in repository:
        repository = f"library/{repository}"

    return ImageRef(
        registry=registry,
        repository=repository,
        tag=tag or "latest",
        digest=digest,
        raw=raw,
    )


# ─── Severity helpers ─────────────────────────────────────────────────────────
def severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string (higher = worse).

    Args:
        severity: Severity string (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, NONE).

    Returns:
        Integer rank 0-5.
    """
    return SEVERITY_ORDER.get(severity.upper(), 0)


def max_severity(severities: list[str]) -> str:
    """Return the highest severity from a list.

    Args:
        severities: List of severity strings.

    Returns:
        Highest severity string, or 'NONE' if list is empty.
    """
    if not severities:
        return "NONE"
    return max(severities, key=severity_rank)


# ─── File I/O helpers ─────────────────────────────────────────────────────────
def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path.

    Returns:
        Resolved :class:`Path`.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(data: Any, path: str | Path, indent: int = 2) -> None:
    """Write data as pretty-printed JSON.

    Args:
        data: JSON-serialisable object.
        path: Destination file path.
        indent: JSON indentation level.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, default=str)


def read_json(path: str | Path) -> Any:
    """Read and parse a JSON file.

    Args:
        path: Source file path.

    Returns:
        Parsed JSON data.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def truncate_string(s: str, max_len: int = 120) -> str:
    """Truncate a string with ellipsis if it exceeds max_len.

    Args:
        s: Source string.
        max_len: Maximum length before truncation.

    Returns:
        Truncated string.
    """
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Box Drawing (2500-257F), Block Elements (2580-259F) and Geometric Shapes
# (25A0-25FF) — the glyphs the scanner CLIs draw their startup banners with.
_BANNER_GLYPH_RE = re.compile(r"[─-╿▀-▟■-◿]+")


def clean_tool_error(text: str, max_len: int = 300) -> str:
    """Normalise a tool's stderr into one readable line for reports.

    Tools print colour codes and ASCII-art banners to stderr. Embedding that
    raw in an HTML report, a JSON artifact or a pull request comment makes the
    actual error unreadable, so escape sequences and blank-ish banner lines are
    stripped and the result collapsed to a single line.

    Args:
        text: Raw stderr captured from a scanner.
        max_len: Maximum length of the returned message.

    Returns:
        A single-line, ANSI-free error message (possibly empty).

    Example:
        >>> clean_tool_error("\\x1b[31mFTL\\x1b[0m  boom")
        'FTL boom'
    """
    text = _ANSI_RE.sub("", text)
    # Strip box-drawing, block and geometric-shape glyphs, which is what the
    # tools' startup banners are made of.
    text = _BANNER_GLYPH_RE.sub(" ", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    message = " ".join(" ".join(lines).split())
    return truncate_string(message, max_len)


def mask_secret(secret: str, keep: int = 0, width: int = 12) -> str:
    """Return a fixed-width mask for a detected secret.

    The mask never reveals the plaintext and never encodes the secret's true
    length, so short or low-entropy secrets cannot be reconstructed from a
    report that is uploaded as a CI artifact or posted to a pull request.

    Args:
        secret: The raw matched secret (may be empty).
        keep: Number of leading characters to retain. Only honoured when the
            secret is comfortably longer than ``keep``; defaults to 0 (reveal
            nothing).
        width: Number of mask characters to emit.

    Returns:
        A redacted representation such as ``"************ [REDACTED]"``.

    Example:
        >>> mask_secret("abc")
        '************ [REDACTED]'
        >>> mask_secret("AKIAIOSFODNN7EXAMPLE", keep=4)
        'AKIA************ [REDACTED]'
    """
    mask = "*" * width
    if not secret:
        return f"{mask} [REDACTED]"
    # Only show a prefix when doing so leaves the bulk of the secret hidden.
    if keep > 0 and len(secret) >= keep * 3:
        return f"{secret[:keep]}{mask} [REDACTED]"
    return f"{mask} [REDACTED]"
