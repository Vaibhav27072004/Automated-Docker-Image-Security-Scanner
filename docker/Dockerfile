# ─────────────────────────────────────────────────────────────────────────────
# Docker Security Scanner — Scanner Container Image
# Packages all three tools (Trivy, Hadolint, Gitleaks) with the Python scanner
# into a self-contained, portable container.
#
# Build from the repository root (the build context must include src/):
#   docker build -t security-scanner -f docker/Dockerfile .
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.14.8-slim AS base

# ── Tool versions ─────────────────────────────────────────────────────────────
# All three are pinned and all three are actually used. TRIVY_VERSION used to be
# declared and then ignored, because Trivy was installed from the apt repo,
# which silently shipped whatever was newest — so the "pinned" version was a
# fiction and builds were not reproducible.
ARG TRIVY_VERSION=0.75.0
ARG HADOLINT_VERSION=2.12.0
ARG GITLEAKS_VERSION=8.18.4

# ── System dependencies ───────────────────────────────────────────────────────
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tar \
    && rm -rf /var/lib/apt/lists/*

# ── Install Trivy (pinned release tarball, not the rolling apt repo) ─────────
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) trivy_arch="Linux-64bit" ;; \
      arm64) trivy_arch="Linux-ARM64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tar.gz; \
    trivy --version

# ── Install Hadolint ──────────────────────────────────────────────────────────
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) hadolint_arch="x86_64" ;; \
      arm64) hadolint_arch="arm64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/hadolint \
      "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${hadolint_arch}"; \
    chmod +x /usr/local/bin/hadolint; \
    hadolint --version

# ── Install Gitleaks ─────────────────────────────────────────────────────────
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gitleaks_arch="x64" ;; \
      arm64) gitleaks_arch="arm64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tar.gz; \
    gitleaks version

# ── Python scanner ───────────────────────────────────────────────────────────
WORKDIR /scanner

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY setup.py .
COPY README.md .
RUN pip install --no-cache-dir .

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home scanner

# ── Writable directories ─────────────────────────────────────────────────────
# The scanner runs as uid 10001 but WORKDIR /scanner is root-owned, so a
# relative TRIVY_CACHE_DIR resolved to a path the user could not create and
# every scan died with "mkdir .trivy-cache: permission denied". Both the cache
# and the report directory are now explicit, absolute and owned by the user.
ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy \
    REPORT_OUTPUT_DIR=/reports \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN mkdir -p /reports /home/scanner/.cache/trivy \
    && chown -R scanner:scanner /reports /home/scanner

USER scanner

VOLUME ["/scan-target", "/reports"]

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["docker-scan"]
CMD ["--help"]

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="Docker Security Scanner" \
      org.opencontainers.image.description="Automated Docker image security scanner with Trivy, Hadolint, and Gitleaks" \
      org.opencontainers.image.source="https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner" \
      org.opencontainers.image.licenses="MIT"
