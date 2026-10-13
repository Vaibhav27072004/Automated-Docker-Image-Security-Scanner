# Troubleshooting Guide

Common issues and their solutions.

---

## Tool Not Found Errors

### `ToolNotFoundError: Required tool 'trivy' not found`

**Cause:** Trivy is not installed or not on your `PATH`.

**Fix:**
```bash
# Linux/macOS (via apt)
sudo apt-get install trivy

# macOS (via Homebrew)
brew install trivy

# Windows (via Scoop)
scoop install trivy

# Verify
trivy --version
```

If installed to a non-standard path, set the env var:
```bash
TRIVY_PATH=/path/to/trivy docker-scan image nginx:latest
```

---

### `ToolNotFoundError: Required tool 'hadolint' not found`

```bash
# Linux/macOS
curl -sSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
  -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# macOS (via Homebrew)
brew install hadolint

# Windows (via Scoop)
scoop install hadolint
```

---

### `ToolNotFoundError: Required tool 'gitleaks' not found`

```bash
# Linux/macOS
GITLEAKS_VER="8.18.4"
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" \
  | tar xz gitleaks && sudo mv gitleaks /usr/local/bin/

# macOS (via Homebrew)
brew install gitleaks

# Windows (via Chocolatey)
choco install gitleaks
```

---

## Trivy Issues

### `Trivy produced no output` / Docker image not found

```bash
# Pull the image first
docker pull nginx:1.25

# Or build it
docker build -t myapp:latest .
```

### Trivy DB update fails (proxy/air-gapped)

```bash
# Download the DB on an internet-connected machine
trivy image --download-db-only --cache-dir /shared/cache

# Transfer /shared/cache to air-gapped machine then:
TRIVY_CACHE_DIR=/shared/cache
TRIVY_SKIP_UPDATE=true
```

---

## Scan Timeout

If Trivy times out on large images, the default timeout is 300 seconds.
To increase it, run Trivy directly and pass the output to the scanner:

```bash
trivy image --format json --output /tmp/trivy.json nginx:latest
```

---

## Permission Errors

### Docker socket not accessible

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
```

---

## Report Generation Issues

### HTML report has no charts

The HTML template uses inline CSS/JS only and requires no internet connection.
If you see a blank page, check that the report file was fully written:

```bash
ls -lh reports/security_report.html
```

### JSON report is empty / malformed

Check for scan errors in the terminal output. If a scanner failed, the
corresponding section in the JSON report will contain an `error` field.

```bash
jq '.trivy.error, .hadolint.error, .gitleaks.error' reports/security_report.json
```

---

## GitHub Actions Issues

### PR comments not appearing

Ensure the workflow has `pull-requests: write` permission:
```yaml
permissions:
  pull-requests: write
```

And that `GITHUB_TOKEN` is available (it is automatically injected by GitHub Actions).

### Workflow failing on `examples/vulnerable-app` (expected)

The vulnerable app is intentionally insecure. The workflow is configured to
`continue-on-error: true` for that target and only fails the gate for `examples/secure-app`.

---

## Getting Help

## The scan says a tool "did not run"

```
❌ Security policy: FAILED
  • scanner did not run (Trivy CVE scan: Required tool 'trivy' not found...)
```

This is the gate working as designed. A scanner that could not run reports zero
findings, and zero findings from a tool that never started is not evidence of a
clean image, so it is treated as a policy violation rather than a pass.

Common causes:

| Message | Cause | Fix |
|---------|-------|-----|
| `Required tool 'X' not found` | binary not on `PATH` | install it, or set `TRIVY_PATH` / `HADOLINT_PATH` / `GITLEAKS_PATH` |
| `unable to load gitleaks config` | `GITLEAKS_CONFIG` points at a missing file | leave it blank, or create the file |
| `.hadolint.yaml: does not exist` | `HADOLINT_CONFIG` points at a missing file | leave it blank, or create the file |
| `mkdir .trivy-cache: permission denied` | `TRIVY_CACHE_DIR` is not writable | set it to an absolute writable path |

---

## `permission denied while trying to connect to the Docker API`

The scanner container runs as a non-root user (uid 10001), so it is not in the
group that owns `/var/run/docker.sock`. Trivy therefore cannot inspect an image
that exists only in your local daemon.

```bash
docker run --rm --group-add "$(stat -c '%g' /var/run/docker.sock)" -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)/reports:/reports" security-scanner image myapp:latest
```

Images pulled from a registry need no socket access at all, so pushing the image
and scanning it by reference avoids the problem entirely.

---

## The scan exits 1 but the policy passed

It no longer can. The console verdict, all three report formats and the exit
code are read from the same `PolicyDecision`. If you see them disagree, that is
a bug worth reporting.

---

- 📋 [Open an Issue](https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner/issues)
- 📖 [Architecture Docs](../ARCHITECTURE.md)
- 💬 [Discussions](https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner/discussions)
