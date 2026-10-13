# Configuration Guide

Complete reference for all scanner configuration options.

---

## Configuration Sources (Priority Order)

1. **CLI flags** — highest priority
2. **Environment variables** (`.env` file via python-dotenv)
3. **Built-in defaults** — lowest priority

---

## Environment Variables Reference

### Severity Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `FAIL_ON_SEVERITY` | `CRITICAL,HIGH` | Comma-separated severities that trigger pipeline failure |
| `CRITICAL_THRESHOLD` | `0` | Max CRITICAL CVEs allowed (0 = any triggers failure) |
| `HIGH_THRESHOLD` | `10` | Max HIGH CVEs allowed (0 = disables the HIGH check) |
| `FAIL_ON_DOCKERFILE_ERRORS` | `true` | Treat Hadolint error-level findings as a violation |
| `FAIL_ON_SCANNER_ERROR` | `true` | Fail when a scanner could not run (**fail closed**) |

### The policy decides the exit code

`FAIL_ON_SEVERITY` and the thresholds are the *only* thing that determines the
verdict. A LOW-severity CVE in a base image does not fail the build unless you
ask it to, and the console verdict, all three report formats and the process
exit code are read from one `PolicyDecision` — they cannot disagree.

### Fail closed

Leave `FAIL_ON_SCANNER_ERROR=true`. A scanner that cannot run reports zero
findings, and zero findings must never be mistaken for a clean image. With this
enabled, a missing Trivy binary or an unreadable config file is a *violation*
that names the tool that failed. Setting it to `false` lets such a scan be
reported as a pass; the errors are still listed in the report, but they no
longer gate.

**Example — strict policy (zero tolerance):**
```bash
FAIL_ON_SEVERITY=CRITICAL,HIGH,MEDIUM
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=0
```

**Example — relaxed policy (only block on critical):**
```bash
FAIL_ON_SEVERITY=CRITICAL
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=0
```

---

### Tool Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_PATH` | `trivy` | Path to Trivy binary |
| `HADOLINT_PATH` | `hadolint` | Path to Hadolint binary |
| `GITLEAKS_PATH` | `gitleaks` | Path to Gitleaks binary |

Useful for non-standard install locations:
```bash
TRIVY_PATH=/opt/security-tools/trivy
```

---

### Trivy Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_CACHE_DIR` | `.trivy-cache` | Trivy vulnerability DB cache directory |
| `TRIVY_SKIP_UPDATE` | `false` | Skip DB update (air-gapped environments) |

**Air-gapped environment setup:**
```bash
# On internet-connected machine:
trivy image --download-db-only --cache-dir /shared/trivy-cache

# On air-gapped machine:
TRIVY_CACHE_DIR=/shared/trivy-cache
TRIVY_SKIP_UPDATE=true
```

---

### Hadolint Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HADOLINT_CONFIG` | _(none)_ | Path to a `.hadolint.yaml` config. **Leave blank unless the file exists** |
| `HADOLINT_IGNORE` | _(none)_ | Comma-separated rule IDs to ignore |

> **Pointing these at a file that does not exist makes the tool abort.**
> Hadolint exits with an error and Gitleaks exits fatally, so the scanner gets
> no findings back. The gate catches that (see *Fail closed* above) and fails
> rather than reporting a clean image, but you still get no scan — so only set
> these once you have actually created the file.

**Example `.hadolint.yaml`:**
```yaml
ignore:
  - DL3008  # Allow unpinned apt packages in dev environments
  - DL3009
trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
```

---

### Gitleaks Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `GITLEAKS_CONFIG` | _(none)_ | Path to a `.gitleaks.toml` config. **Leave blank unless the file exists** |

**Example `.gitleaks.toml` (allowlist):**
```toml
[allowlist]
  description = "Allowlist for test fixtures"
  paths = [
    "tests/fixtures/.*",
    "examples/vulnerable-app/.*"   # Demo secrets are intentional
  ]
```

---

### Reporting

| Variable | Default | Description |
|----------|---------|-------------|
| `REPORT_OUTPUT_DIR` | `reports` | Output directory for all reports |
| `REPORT_FORMATS` | `html,json,markdown` | Comma-separated list of formats |
| `SBOM_FORMATS` | `cyclonedx,spdx` | Comma-separated SBOM formats |
| `MAX_JSON_VULNERABILITIES` | `1000` | Cap on CVE records in the JSON report (0 = unlimited) |

`MAX_JSON_VULNERABILITIES` trims only the detail list; the summary counts always
describe every finding. An image with 6,000 CVEs would otherwise produce a
multi-megabyte JSON artifact on every CI run.

---

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log verbosity: DEBUG, INFO, WARNING, ERROR |
| `LOG_FILE` | _(none)_ | Write logs to file (in addition to stdout) |

---

## CLI Override Flags

The `docker-scan image` command accepts flags that override env vars:

```
Usage: docker-scan [OPTIONS] COMMAND [ARGS]...

Options:
  --log-level TEXT  Logging verbosity  [default: INFO]
  --version         Show the version and exit
  -h, --help        Show this message and exit

Commands:
  dockerfile  Lint a Dockerfile with Hadolint
  image       Scan a Docker image for vulnerabilities, misconfigurations,
              and secrets
```

```
Usage: docker-scan image [OPTIONS] IMAGE_REF

Options:
  -d, --dockerfile TEXT    Path to Dockerfile for linting
  -s, --scan-path TEXT     Directory to scan for secrets
  -o, --output-dir TEXT    Output directory for reports  [default: reports]
  --no-sbom                Skip SBOM generation
  --fail-on-severity TEXT  Override FAIL_ON_SEVERITY
  -h, --help               Show this message and exit
```

`--log-level` is a flag on `docker-scan` itself, so it goes **before** the
subcommand: `docker-scan --log-level DEBUG image nginx:1.25`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Policy passed |
| `1` | Policy violated (findings over threshold, secrets, Dockerfile errors, or a scanner that did not run) |
| `2` | Scanner or configuration error |

**Examples:**

```bash
# Scan with custom severity threshold
docker-scan image myapp:latest --fail-on-severity CRITICAL

# Scan with Dockerfile lint, custom output dir
docker-scan image myapp:latest \
  --dockerfile ./Dockerfile \
  --output-dir /tmp/scan-reports

# Quick scan (no SBOM, no secrets)
docker-scan image myapp:latest --no-sbom
```
