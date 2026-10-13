"""
docker_security_scanner — automated Docker image security scanning.

Wraps Trivy (CVEs), Hadolint (Dockerfile lint) and Gitleaks (secrets) behind a
single policy gate that fails closed.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("docker-security-scanner")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "1.0.0-dev"

__all__ = ["__version__"]
