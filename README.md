<div align="center">
  <h1>🔒 Docker Image Security Scanner</h1>
  <p><strong>A build-time security gate for container images: CVEs, hardcoded secrets,<br>Dockerfile misconfigurations and SBOMs, behind one policy that fails closed.</strong></p>

  [![Build Status](https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner/actions/workflows/security-scan.yml)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Coverage](https://img.shields.io/badge/coverage%20gate-85%25-brightgreen)](tests/)
  [![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
  [![Trivy](https://img.shields.io/badge/Powered%20by-Trivy-blue)](https://trivy.dev)
  [![Hadolint](https://img.shields.io/badge/Linted%20by-Hadolint-orange)](https://github.com/hadolint/hadolint)
  [![Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks-red)](https://gitleaks.io)

</div>

---

## 🎯 Executive Summary

### The problem

Container images routinely ship with known CVEs and hardcoded credentials, and
the fix is well understood: scan at build time and block the bad build. Most
teams add a scanner to CI and move on.

The failure mode nobody tests is what the gate reports **when the scanner
itself cannot run.** A scanner that fails to start finds nothing — and "found
nothing" is the same zero as "found no problems." A gate that reads only that
number cannot tell a broken scanner from a clean image, so it shows a green
check mark for both.

That is the problem this project solves, and it is not theoretical: **this
scanner had that bug, and we caught it reporting `✅ PASSED` on an image
carrying 22 CRITICAL CVEs and 5 hardcoded credentials** — with zero scans
having run. Three ordinary mistakes reached that path, including following this
project's own setup documentation. See
[**The Real-World Problem This Solves**](#-the-real-world-problem-this-solves)
for the full case study, the root cause, and the fix.

### What this scanner does

Four checks over an image and its build context, in one pass:

✓ **Trivy CVE scanning** → OS and language-package CVEs with CVSS scores
✓ **Hadolint analysis** → Dockerfile misconfiguration and anti-pattern linting
✓ **Gitleaks detection** → hardcoded secrets in the build context
✓ **SBOM generation** → CycloneDX and SPDX component inventories

### What makes it a gate you can trust

**One verdict, computed once.** A single `PolicyDecision` is produced *before*
any report is written, and the console output, all three report formats and the
process exit code read that same object. They cannot disagree — which they
previously did, three different ways, in a single run.

**It fails closed.** A scanner that could not run is a policy violation that
names the tool and the reason, never a quiet zero:

```console
❌ Security policy: FAILED
  • scanner did not run (Trivy CVE scan: Required tool 'trivy' not found...)

Note: zero findings from a scanner that failed to run is not evidence of a
clean image.
```

**The policy decides, not the raw counts.** A LOW CVE in a base image does not
fail your build unless you say so. `FAIL_ON_SEVERITY` and the thresholds are
the only thing that sets the verdict, and a separate `is_clean` flag carries the
stricter "nothing at all was found" fact so the two never get confused.

### What the demo images actually produce

Run against the two bundled examples (counts move as upstream advisories land,
so treat them as a snapshot, not a promise):

| | `examples/vulnerable-app` | `examples/secure-app` |
|---|---|---|
| CRITICAL CVEs | 22 | 0 |
| HIGH CVEs | 379 | 44 |
| Hardcoded secrets | 5 | 0 |
| Dockerfile findings | 5 (0 error-level) | 0 |
| Verdict | ❌ FAILED | base-image CVEs only |

The secure example demonstrates Dockerfile hygiene — digest-pinned base image,
non-root user, multi-stage build, no secrets. Its remaining HIGH CVEs come from
the Debian base image, not from the Dockerfile, which is exactly the triage
split the scanner exists to make visible.

---

## ⚡ Start Here — 3 Minutes to First Scan

**What you'll have after 3 minutes:**
- ✅ A working security scanner running locally
- ✅ A real vulnerability report for the bundled demo image
- ✅ An HTML dashboard, a JSON report and a Markdown PR summary
- ✅ An exit code your CI can gate on

**Requirements:** Docker + Python 3.10+ (3.9 is end-of-life and unsupported)

### 1. Installation

```bash
git clone https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner.git && \
  cd Automated-Docker-Image-Security-Scanner && \
  pip install -r requirements.txt && \
  pip install -e .
```

*(Ensure you have `trivy`, `hadolint`, and `gitleaks` installed. See [Installation](#-installation) for details or Docker alternative).*

### 2. Three Progressive Examples

Scan a public image:

```bash
docker-scan image nginx:1.25
```

Full scan of an image plus its Dockerfile and source:

```bash
docker build -t vuln-app:latest examples/vulnerable-app/ && docker-scan image vuln-app:latest --dockerfile examples/vulnerable-app/Dockerfile --scan-path examples/vulnerable-app/
```

Tighten the policy so any MEDIUM CVE also fails the build:

```bash
docker-scan image vuln-app:latest --fail-on-severity CRITICAL,HIGH,MEDIUM
```

### 3. Expected Output

Scanning `alpine:3.19` with the default policy (fail on CRITICAL, allow up to
10 HIGH):

```
──────────────────── 🔒 Docker Security Scanner ────────────────────
Scanning image: alpine:3.19

Step 1/4: Running Trivy CVE scan...
    CVE Summary
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     0 │
│ HIGH     │     2 │
│ MEDIUM   │     5 │
│ LOW      │     3 │
╰──────────┴───────╯

Step 2/4: Skipping Hadolint (no Dockerfile specified).

Step 3/4: Running Gitleaks secret scan on .
  Gitleaks: ✓ PASSED - Secrets: 0

Step 4/4: Generating SBOM...
  ✓ CYCLONEDX SBOM: reports/sbom_alpine_3.19_cyclonedx.json
  ✓ SPDX SBOM: reports/sbom_alpine_3.19_spdx.json

Generating reports...
  ✓ HTML report: reports/security_report.html
  ✓ JSON report: reports/security_report.json
  ✓ MARKDOWN report: reports/security_report.md

✅ Security policy: PASSED
```

Ten CVEs were found and the scan still passes, because the configured policy
allows them. When it fails, it says exactly why:

```
❌ Security policy: FAILED
  • 22 CRITICAL CVEs (threshold: 0)
  • 379 HIGH CVEs (threshold: 10)
  • 5 hardcoded secrets detected
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Policy passed |
| `1` | Policy violated — findings over threshold, secrets, Dockerfile errors, **or a scanner that did not run** |
| `2` | Scanner or configuration error |

---

## 🛡️ Security Checks

### CVE Scanning — Trivy Integration

Scans both OS-level and application dependencies for known vulnerabilities:

- **Trivy's vulnerability database** — advisories from NVD, Red Hat, Debian,
  Ubuntu, Alpine and language ecosystems
- **CVSS v3 scoring** with severity classification (CRITICAL → LOW), read from
  the NVD, Red Hat or GHSA entry, whichever Trivy supplies first
- **Fix availability** — each finding records whether a fixed version exists,
  surfaced as a `fixable` count so you can tell actionable from unactionable
- **Target attribution** — each CVE records the Trivy target (OS package set or
  language manifest) it was found in
- **Findings sorted by severity, then CVSS**, so the worst items are first in
  every report

**Real example** — `examples/vulnerable-app`, which is built `FROM ubuntu:latest`:

```text
CRITICAL  CVE-2026-43037  linux-libc-dev  6.8.0-111.111 -> 6.8.0-134.134  CVSS 8.8
CRITICAL  CVE-2026-23216  linux-libc-dev  6.8.0-111.111 -> 6.8.0-117.117  CVSS 7.8
CRITICAL  CVE-2026-64564  linux-libc-dev  6.8.0-111.111 -> (no fix)       CVSS 7.8
```

Counts change as upstream advisories land; run the scan to get current numbers.

### Dockerfile Linting — Hadolint Integration

Applies Hadolint's Dockerfile rule set, which overlaps with — but is not an
implementation of — the CIS Docker Benchmark:

- **Hadolint `DL*` rules plus ShellCheck `SC*` rules** for `RUN` script bodies
- **Levels mapped to severities** — `error` → HIGH, `warning` → MEDIUM,
  `info`/`style` → LOW
- **Only error-level findings gate the build** by default
  (`FAIL_ON_DOCKERFILE_ERRORS`); warnings are reported, not blocking
- **Rules categorised** by prefix (Base Image, Package Management, Permissions,
  Shell Script, …) and linked to the Hadolint wiki
- **A rule set of interest flagged** as security-critical: `DL3002`, `DL3007`,
  `DL4006`, `SC2035`

**Examples caught** in `examples/vulnerable-app`:
```text
DL3007   warning  line 10  Using latest is prone to errors; pin the version
DL3008   warning  line 14  Pin versions in apt-get install
DL3042   warning  line 33  Avoid use of cache directory with pip
DL3025   warning  line 40  Use arguments JSON notation for CMD and ENTRYPOINT
DL3015   info     line 14  Avoid additional packages by specifying --no-install-recommends
```

> **Scope note.** Hadolint reads the Dockerfile as text. It does not detect
> secrets hardcoded in `ENV` instructions — that is what the Gitleaks step is
> for, and it does flag them.

### Secret Detection — Gitleaks Integration

Prevents hardcoded credentials in image layers:

- **Gitleaks' built-in rule set** — cloud keys, private keys, provider tokens
- **Shannon entropy** recorded per finding, and used to rank an unrecognised
  high-entropy match as HIGH rather than MEDIUM
- **Severity by rule family** — a match on an AWS/GCP/Azure/private-key/
  provider-token rule is treated as CRITICAL
- **Filesystem scanning** (`--no-git`), so it works on a build context with no
  git history
- **Secret values are never written to a report** — every finding is emitted
  through a fixed-width mask that reveals neither the plaintext nor its length

**Detects**:
- AWS Access Keys, Azure Storage Keys, GCP Service Accounts
- GitHub, Slack, Discord, PagerDuty, Datadog tokens
- SSH/PEM private keys, GPG keys
- Database connection strings, API endpoints
- High-entropy strings (tokens, hashed secrets)

> **Detection is rule-based, not exhaustive.** On the bundled vulnerable app
> Gitleaks finds the AWS keys and the GitHub token but not the plain
> `DB_PASSWORD` string or the example Slack webhook. Treat it as a strong net,
> not a guarantee — and keep using a secrets manager.

### SBOM Generation

Generates a machine-readable component inventory in the two formats most
commonly requested for supply-chain review:

- **CycloneDX JSON** and **SPDX JSON**, both produced by Trivy
- **License extraction** — declared licenses per component, plus a deduplicated
  list across the image (`NOASSERTION` is correctly recorded as *no* license)
- **Component versions and PURLs** — every package with its exact version and
  package URL
- **Component type grouping** — library/application/OS counts in the summary

An SBOM in these formats is a prerequisite for most supply-chain policies
(including the inventory requirements referenced by U.S. Executive Order 14028),
but generating one is not by itself a compliance attestation.

**Example Output**:
```json
{
  "bomFormat": "CycloneDX",
  "components": 487,
  "licenses": {
    "MIT": 156,
    "Apache-2.0": 89,
    "GPL-3.0": 12,
    "Proprietary": 3
  }
}
```

---

## 🏗️ Architecture & Workflow

### Pipeline Stages

**Stage 1: Image Preparation**
```text
Input: Docker Image + Dockerfile + Source Code
              ↓
      1. Image metadata extraction
      2. Dockerfile parsing and validation
      3. Layer history analysis
              ↓
      Ready for scanning
```

**Stage 2: Security Scanning (Parallelized Design)**
```text
Trivy CVE Scan ────┐
                   ├──→ Results Aggregation
Hadolint Lint ─────┤
                   │
Gitleaks Secret ───┘
```

**Stage 3: Analysis & Decision**
```text
Aggregated Results
        ↓
  Severity Scoring
        ↓
  Policy Check (CRITICAL ≤ 0?)
        ├─→ PASS: Proceed to production ✅
        └─→ FAIL: Block deployment ❌
```

**Stage 4: Report Generation**
```text
HTML Dashboard  ← For security teams to review
JSON Structured ← For CI/CD integration
Markdown Summary ← For GitHub PR comments
SBOM Artifacts ← For compliance & procurement
```

### Key Design Decisions

**Why These Three Tools?**
- **Trivy** — Only tool recommended by CISA, Docker Official, Kubernetes, AWS.
- **Hadolint** — The de facto Dockerfile linter; its rules overlap substantially with the CIS Docker Benchmark.
- **Gitleaks** — Built by Zack Rice, widely adopted in enterprise pipelines.

**Why Orchestrate?**
- Independent results → easier debugging if one tool fails.
- Unified reporting → single pane of glass for security posture.
- Enterprise-grade policy enforcement across all dimensions simultaneously.

**Why SBOM is Mandatory?**
- U.S. Executive Order 14028 drove the SBOM requirements now common in government contracts.
- Increasing enterprise compliance requirement (AWS, Google Cloud, Azure all require).
- SolarWinds/Log4j showed why software inventory matters.

### Scanning Algorithm (Technical Detail)

```python
def scan_image(image_ref: str) -> ScanResult:
    """
    1. Extract image metadata (OS, distro, version)
    2. Analyze target artifacts
    3. For each vulnerability database / rule engine:
        - Load definitions
        - Match installed packages/code against data
        - Calculate CVSS scores and exploitability
    4. Aggregate results with configurable severity thresholds
    5. Apply organization security policy
    6. Generate reports in multiple formats
    
    Time Complexity: O(n * m) where:
        n = number of packages/lines in image
        m = size of rule database (constant)
    """
```

---

## 📦 Installation

### Option 1: Docker (no local tool install)

The image bundles pinned builds of Trivy, Hadolint and Gitleaks and runs as a
non-root user (uid 10001). Build it from the repository root -- the build
context must include `src/`:

```bash
docker build -t security-scanner -f docker/Dockerfile .
```

**Scanning an image from a registry** needs no Docker socket at all:

```bash
docker run --rm -v "$(pwd)/reports:/reports" security-scanner image nginx:1.25
```

**Scanning an image that exists only in your local Docker daemon** needs access
to the socket. Because the container runs as a non-root user, it must also join
the group that owns the socket, or Trivy cannot inspect the image:

```bash
docker run --rm --group-add "$(stat -c '%g' /var/run/docker.sock)" -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)/reports:/reports" security-scanner image myapp:latest
```

Without `--group-add`, Trivy reports `permission denied while trying to connect
to the Docker API`, and the scan **fails** instead of reporting a clean image.
If you would rather not expose the socket, push the image to a registry and
scan it by reference.

To lint a Dockerfile or scan a source tree, mount it read-only:

```bash
docker run --rm -v "$(pwd):/scan-target:ro" -v "$(pwd)/reports:/reports" security-scanner dockerfile /scan-target/Dockerfile
```

### Option 2: Manual Installation (Full Control)

**Step 1: Install system dependencies**
```bash
# macOS
brew install trivy hadolint gitleaks python@3.11

# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y trivy
curl -sSL https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
  -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint
curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
  | tar xz gitleaks && sudo mv gitleaks /usr/local/bin/
```

**Step 2: Install Python package**
```bash
git clone https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner.git
cd Automated-Docker-Image-Security-Scanner
pip install -r requirements.txt
pip install -e .
```

**Step 3: Verify installation**
```bash
docker-scan --help
docker-scan image nginx:1.25 --no-sbom
```

### Environment Configuration

Create a `.env` file to customize behavior:

```bash
# Severity levels that fail the pipeline
FAIL_ON_SEVERITY=CRITICAL,HIGH

# 0 = any critical CVE fails; 10 = up to 10 allowed
CRITICAL_THRESHOLD=0

# Report formats (comma-separated)
REPORT_FORMATS=html,json,markdown

# SBOM standards
SBOM_FORMATS=cyclonedx,spdx

# Output directory
REPORT_OUTPUT_DIR=./reports
```

See [Configuration Guide](docs/configuration.md) for all available options.

---

## 💻 Usage Patterns

### Pattern 1: Local Development — Scan Before Committing

Catch vulnerabilities before they reach your team:

```bash
# Scan the image you just built
docker build -t myapp:dev .
docker-scan image myapp:dev

# If CRITICAL CVEs found:
# ❌ Exit code 1, scan fails
# Fix the Dockerfile, rebuild, rescan
```

**When to use**: Daily development, pre-commit checks

---

### Pattern 2: Production Gates — CI/CD Integration

Every merge to main must pass security gates:

```bash
# In your CI/CD (GitHub Actions, GitLab CI, Jenkins, etc.)
docker build -t myapp:${GITHUB_SHA} .
docker-scan image myapp:${GITHUB_SHA}

# If this fails:
# - Deployment is blocked ✋
# - Developer gets PR comment with security issues
# - CISO gets dashboard update
```

**When to use**: Production pipelines, enterprise deployments

---

### Pattern 3: Compliance Scanning — Generate SBOMs for Procurement

Many enterprises require SBOMs before using third-party software:

```bash
# Generate SBOMs for procurement teams.
# An empty --fail-on-severity disables the CVE thresholds, so no CVE count
# fails the run. Hardcoded secrets and Dockerfile errors still fail, and so
# does a scanner that could not run -- the gate never opens on no evidence.
docker-scan image vendorlib:1.0 \
  --output-dir ./compliance \
  --fail-on-severity ""

# Outputs (one file per configured SBOM format):
# - compliance/sbom_vendorlib_1.0_cyclonedx.json
# - compliance/sbom_vendorlib_1.0_spdx.json
# Each lists every component with its version, PURL and declared license.
# 
# Hand these to procurement → they verify against their blocklist
# ✅ Approved or ❌ Rejected before integration
```

**When to use**: Third-party dependencies, vendor assessment, compliance audits

---

### Pattern 4: Hardening Optimization — Find the "Low Fruit"

Understand which packages are actually vulnerable:

```bash
docker-scan image myapp:latest \
  --output-dir ./reports

# Parse JSON to find fixable criticals
jq '.trivy.vulnerabilities[] | select(.severity=="CRITICAL" and .is_fixable==true)' reports/security_report.json

# Shows you exactly which packages to upgrade first
# Instead of upgrading everything (breaking changes), 
# upgrade only what matters for security
```

**When to use**: Optimization phase, budget-constrained patching

---

### Pattern 5: Automated Reporting — Executive Dashboard

Generate reports for non-technical stakeholders:

```bash
# Scan suite of microservices
for service in api auth db cache; do
  docker-scan image myapp-$service:latest \
    --output-dir reports/$service
done

# All reports → reports/
# Share HTML dashboards, email to CTO/CISO
```

**When to use**: Executive reports, organizational security posture

---

## 🚀 GitHub Actions Integration — Automated Security Gates

Every push and pull request automatically runs through security checks. **No manual review, no bottlenecks.**

### Quick Integration (Copy-Paste)

Add to `.github/workflows/security-scan.yml`:

```yaml
name: 🔒 Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 2 * * 0" # Weekly audit

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
      pull-requests: write
    steps:
      # Pin third-party actions to a commit SHA, not a mutable tag.
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4

      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: "3.11"
          cache: pip

      # Pin every tool version: a scanner whose own inputs drift is not a
      # reproducible gate.
      - name: Install tools
        env:
          TRIVY_VERSION: "0.75.0"
          HADOLINT_VERSION: "2.12.0"
          GITLEAKS_VERSION: "8.18.4"
        run: |
          curl -fsSL -o /tmp/trivy.tar.gz \
            "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
          sudo tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
          sudo curl -fsSL -o /usr/local/bin/hadolint \
            "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64"
          sudo chmod +x /usr/local/bin/hadolint
          curl -fsSL \
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | tar -xz gitleaks
          sudo mv gitleaks /usr/local/bin/

      - name: Run security scan
        id: scan
        # continue-on-error so the reports below still upload on a failure.
        # The gate is re-asserted in the final step.
        continue-on-error: true
        env:
          # Cache the Trivy DB between runs: it dominates the wall clock.
          TRIVY_CACHE_DIR: ${{ runner.temp }}/trivy-cache
        run: |
          pip install -e .
          docker build -t myapp:latest .
          docker-scan image myapp:latest \
            --dockerfile ./Dockerfile \
            --scan-path . \
            --output-dir reports/

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: security-reports
          path: reports/
          if-no-files-found: warn

      # Same-repo PRs only: a pull_request from a fork gets a read-only token
      # regardless of the permissions block, so this would 403 otherwise.
      - name: Comment PR
        if: >-
          github.event_name == 'pull_request' &&
          github.event.pull_request.head.repo.full_name == github.repository
        continue-on-error: true
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        with:
          script: |
            const fs = require('fs');
            if (!fs.existsSync('reports/security_report.md')) return;
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: fs.readFileSync('reports/security_report.md', 'utf8'),
            });

      - name: Enforce policy
        if: steps.scan.outcome != 'success'
        run: |
          echo "::error::Security policy failed - see the uploaded report."
          exit 1
```

The scanner exits `0` on a pass, `1` on a policy violation (including a scanner
that could not run) and `2` on a configuration error, so `steps.scan.outcome`
is all the gate needs.

### GitHub PR Comment Example

When a PR is opened, developers immediately see what to fix:

```markdown
## 🔒 Docker Security Scan — ❌ FAILED

**Image:** `demo-vulnerable:latest`

### 📊 Summary

| Check | Status | Findings |
|-------|--------|----------|
| CVE Scan (Trivy) | ❌ | CRITICAL: 22, HIGH: 379, MEDIUM: 5267, LOW: 518 |
| Dockerfile Lint (Hadolint) | ❌ | 5 issues (0 error-level) |
| Secret Detection (Gitleaks) | ❌ | 5 secrets found |

### ❌ Policy Violations

- 22 CRITICAL CVEs (threshold: 0)
- 379 HIGH CVEs (threshold: 10)
- 5 hardcoded secrets detected

Action Required:
1. Update base image
2. Remove hardcoded credentials
3. Re-push to trigger new scan

[View Full Report]
```

### Advanced: Scheduled Full Repository Scan

Adding the `schedule` trigger to the workflow (as shown above) catches retroactive CVEs. This catches when:
- Operating systems release new security updates.
- OpenSSL has a retroactive CVE (0-day becomes known).
- Rebuilding forces these updates and the weekly scan will fail, alerting the team.

---

## 📈 The Real-World Problem This Solves

### Everyone adds a scanner. Almost nobody checks that it still works.

Adding a vulnerability scanner to CI is a solved problem — one step in a YAML
file. The part nobody checks is the failure mode: **what does the gate report
when the scanner itself cannot run?**

A scanner that fails to start finds nothing. "Found nothing" and "found no
problems" are the same number — zero. If the gate reads only that number, a
broken scanner and a clean image are indistinguishable, and the pipeline shows
a green check mark either way.

That green check mark is worse than having no scanner at all. No scanner leaves
you *aware* that container security is unverified. A scanner that fails open
leaves you confidently wrong, with an artifact trail that says you checked.

### The bug we found in this project

This repository's own scanner had exactly that bug. Finding it, proving it, and
fixing it is the engineering story here.

The original policy check counted findings and nothing else:

```python
# Only ever looked at counts.
if sev == "CRITICAL" and result.trivy.critical_count > self.config.critical_threshold:
    violations.append(...)
```

`result.trivy.error` was never read. So we pointed the scanner at
`demo-vulnerable:latest` — an image we had already confirmed carries **22
CRITICAL CVEs and 5 hardcoded AWS/GitHub credentials** — with the scanning
tools unavailable:

```console
$ docker-scan image demo-vulnerable:latest --scan-path examples/vulnerable-app

Step 1/4: Running Trivy CVE scan...
  ERROR  Trivy scan failed: Required tool 'trivy' not found.
Step 3/4: Running Gitleaks secret scan...
  ERROR  Gitleaks scan failed: Required tool 'gitleaks' not found.

✅ Security policy: PASSED
```

**Zero scans ran. The gate passed.** On an image with 22 critical
vulnerabilities and five live-looking credentials in it.

### Why this was not a hypothetical

Three separate, ordinary mistakes all reached that same fail-open path — none
of them requiring an unlucky edge case:

| Trigger | What a user did | What happened |
|---|---|---|
| **The project's own setup docs** | `cp .env.example .env`, as `docs/getting-started.md` instructed | That `.env` set `GITLEAKS_CONFIG=.gitleaks.toml` and `HADOLINT_CONFIG=.hadolint.yaml` — **neither file exists in the repo**. Gitleaks exits fatally on an unreadable config. Secret scanning silently stopped running. |
| **The project's own Docker quickstart** | Ran the `docker run` command from the README | The container runs as uid 10001 but `WORKDIR` was root-owned, so Trivy could not create its relative cache dir: `mkdir .trivy-cache: permission denied`. CVE scanning never started. |
| **Running on Windows at all** | Installed the tools and ran a scan | Both scanners wrote their JSON to `--output /dev/stdout`, a path that **does not exist on Windows**. Both produced no output on every run. |

Each one produced a confident `✅ PASSED`. The last is the most instructive: the
scanner was non-functional on an entire operating system, and nothing in the
output said so.

### Three more defects in the same decision path

Once we were looking at the verdict logic, the rest followed:

- **The verdict contradicted itself three ways in a single run.** Scanning
  `alpine:3.19` under a CRITICAL-only policy with zero criticals present: the
  console printed `✅ PASSED`, the JSON report recorded `"passed": false`, and
  the process exited `1`. Three different answers, three different consumers.
- **The configured thresholds were decorative.** The exit code came from
  "zero findings of any severity," so three LOW CVEs in a base image failed the
  build regardless of `FAIL_ON_SEVERITY` or `CRITICAL_THRESHOLD`. No real image
  could ever exit `0`, which makes a CI gate permanently red — and a
  permanently red gate gets switched off.
- **Dockerfile findings could never fail anything.** Hadolint's results were
  collected, rendered into all three reports, and then excluded from the policy
  entirely. A Dockerfile with a hard error-level violation passed.

### What we changed

**One verdict, computed once, before anything reads it.** `evaluate_policy()`
returns a single `PolicyDecision`, attached to the result *before* any report is
written. The console, the HTML/JSON/Markdown reports and the exit code all read
that one object, so they cannot disagree. An unevaluated decision is never a
pass, so a crash between scanning and reporting cannot read as success.

**The gate fails closed.** Every per-tool result now carries both an `error`
string and a `ran` flag. Any scanner that did not run is a policy violation that
names the tool and the reason:

```console
❌ Security policy: FAILED
  • scanner did not run (Trivy CVE scan: Required tool 'trivy' not found...)
  • scanner did not run (Gitleaks secret scan: Required tool 'gitleaks' not found...)

Note: zero findings from a scanner that failed to run is not evidence of a
clean image.
```

**The policy decides, not the raw counts.** `passed` reflects only the
configured thresholds, so LOW CVEs in a base image no longer fail a build unless
you ask them to. A separate `is_clean` flag carries the stricter "nothing at all
was found" fact, so the two questions stop being confused for each other.

**And the three triggers are gone at the source:** scanners write to temp files
instead of `/dev/stdout`, the container sets an absolute writable
`TRIVY_CACHE_DIR` owned by the runtime user, and `.env.example` no longer points
at files that do not exist.

### Verify the fix yourself

The regression is pinned by tests that fail if the gate ever opens on no
evidence again — `tests/test_scanner.py::TestFailClosedPolicy` and
`tests/test_cli.py::test_image_missing_tool_exits_one_not_zero`:

```bash
docker build -t security-scanner -f docker/Dockerfile . && docker run --rm -e TRIVY_PATH=/nonexistent security-scanner image alpine:3.19 --no-sbom; echo "exit=$?"
```

Before: `✅ Security policy: PASSED`, exit `1` (for an unrelated reason).
After: `❌ Security policy: FAILED`, exit `1`, naming the tool that did not run.

### Measured outcomes

Every number below is reproducible from a clean clone:

| | Before | After |
|---|---|---|
| Scan with all tools broken | `✅ PASSED` | `❌ FAILED`, names each tool |
| Verdict consistency | console / report / exit code disagreed | one `PolicyDecision`, all three agree |
| Can a real image pass? | **No** — any single LOW CVE failed the build | Yes, per the configured policy |
| Dockerfile errors gate the build | No | Yes |
| Works on Windows | No — `/dev/stdout`, plus a `UnicodeEncodeError` crash | Yes |
| CI quality gates passing | **0 of 5** (pipeline had never been green) | **5 of 5** |
| Tests / coverage | 44 passing, 1 failing, 63% | **272 passing, 96.5%** |
| `examples/secure-app` | **did not build** (missing `requirements.txt`) | builds; 0 CRITICAL, 0 lint issues, 0 secrets |
| JSON report (6,186-CVE image) | 8.7 MB, unbounded | 1.6 MB, capped, summary still complete |
| Docker build context | 237 MB | **380 KB** |
| Runtime dependencies | 24 (incl. pytest, black, mypy, pylint) | **5** |
| Secret redaction | `mask_secret("abc")` → `abc[REDACTED]` | fixed-width mask, no plaintext, length hidden |

### The transferable lesson

> **A security control that fails open is not a weak control. It is a liability,
> because it manufactures evidence that the check was performed.**

This is why the gate now treats "the scanner could not run" as a failure rather
than a quiet zero, why the verdict is computed exactly once, and why
`FAIL_ON_SCANNER_ERROR` defaults to `true` and has to be switched off
deliberately. It is the kind of bug that does not announce itself: everything
is green, the reports render, the artifacts upload, and nothing was ever
checked.

### How this compares to the alternatives

Honest trade-offs, on properties you can verify rather than vendor pricing:

| | This scanner | Hand-rolled CI steps | Hosted scanning platform |
|---|---|---|---|
| **Checks** | CVEs, secrets, Dockerfile lint, SBOM in one pass | whatever you wire up | CVEs + SBOM; secrets vary |
| **Verdict** | one policy, fails closed, exit code `0`/`1`/`2` | per-step exit codes you must combine yourself | platform policy engine |
| **Behaviour when a scan breaks** | **fails closed and names the tool** | typically fails open — the usual bug | platform-dependent |
| **Where findings live** | HTML + JSON + Markdown next to the build | step logs | the vendor's dashboard |
| **Runs offline / air-gapped** | yes (`TRIVY_SKIP_UPDATE=true`) | yes | no |
| **Cost** | free; runs on existing CI | free | licensed |
| **You own the policy** | yes, in `.env` / flags | yes | within what the vendor exposes |

Use a hosted platform if you need fleet-wide dashboards, drift tracking and
someone to call. Use this if you want a build-time gate you can read end to
end, run offline, and reason about — including what it does when it breaks.

## 🖥️ Docker Desktop Demo — Live Test Results

The following results were captured by running the scanner **locally on Docker Desktop (Windows)** against the included `examples/vulnerable-app`. These are real, reproducible findings — not simulated data.

### How to Reproduce

```bash
# Step 1: Build the vulnerable test app
docker build -t vuln-app:latest -f examples/vulnerable-app/Dockerfile examples/vulnerable-app/

# Step 2: Build the scanner image (packages Trivy + Hadolint + Gitleaks)
docker build -t security-scanner:latest -f docker/Dockerfile .

# Step 3: Run the full security scan
docker run --rm \
  --group-add "$(stat -c '%g' /var/run/docker.sock)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)/examples/vulnerable-app:/scan-target:ro" \
  -v "$(pwd)/reports:/reports" \
  security-scanner:latest \
  image vuln-app:latest \
  --dockerfile /scan-target/Dockerfile \
  --scan-path /scan-target \
  --output-dir /reports
```

### Scan Output (Actual Terminal Log)

```text
────────────────────────── 🔒 Docker Security Scanner ──────────────────────────
Scanning image: vuln-app:latest

Step 1/4: Running Trivy CVE scan...
    CVE Summary
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     0 │
│ HIGH     │     1 │
│ MEDIUM   │   831 │
│ LOW      │    45 │
╰──────────┴───────╯

Step 2/4: Running Hadolint Dockerfile lint...
  Hadolint: ✓ PASSED — Errors: 0, Warnings: 4

Step 3/4: Running Gitleaks secret scan on /scan-target...
  Gitleaks: ✗ FAILED — Secrets: 6

Step 4/4: Generating SBOM...
  ✓ CYCLONEDX SBOM: /reports/sbom_vuln-app_latest_cyclonedx.json
  ✓ SPDX SBOM: /reports/sbom_vuln-app_latest_spdx.json

Generating reports...
  ✓ HTML report: /reports/security_report.html
  ✓ JSON report: /reports/security_report.json
  ✓ MARKDOWN report: /reports/security_report.md

❌ Security policy violated: 6 hardcoded secrets detected
```

### Results Summary

| Scanner Module | Status | Findings |
|----------------|--------|----------|
| **Trivy CVE Scan** | ✅ Completed | **877 vulnerabilities** (1 HIGH · 831 MEDIUM · 45 LOW · 4 fixable) |
| **Hadolint Dockerfile Lint** | ✅ Completed | **5 issues** (4 warnings · 1 info) |
| **Gitleaks Secret Detection** | ✅ Completed | **6 secrets** (4 CRITICAL · 2 HIGH) |
| **SBOM Generation** | ✅ Completed | CycloneDX (260 components) + SPDX (261 components) |
| **Policy Enforcement** | ❌ FAILED | Blocked — hardcoded secrets detected |

### Secrets Detected by Gitleaks

| Rule | Severity | File | Description |
|------|----------|------|-------------|
| `aws-access-token` | 🔴 CRITICAL | `.env.example:9` | AWS credentials pattern detected |
| `aws-access-token` | 🔴 CRITICAL | `Dockerfile:28` | AWS key exposed via ENV instruction |
| `aws-access-token` | 🔴 CRITICAL | `app.py:15` | Hardcoded AWS Access Key in source |
| `slack-webhook-url` | 🔴 CRITICAL | `app.py:26` | Slack Webhook URL leaked |
| `generic-api-key` | 🟠 HIGH | `.env.example:11` | GitHub Personal Access Token |
| `generic-api-key` | 🟠 HIGH | `app.py:19` | GitHub PAT hardcoded in application |

### Dockerfile Lint Issues Found by Hadolint

| Code | Level | Line | Issue |
|------|-------|------|-------|
| [DL3007](https://github.com/hadolint/hadolint/wiki/DL3007) | ⚠️ Warning | 10 | Using `:latest` tag — non-reproducible, insecure |
| [DL3008](https://github.com/hadolint/hadolint/wiki/DL3008) | ⚠️ Warning | 14 | Unpinned `apt-get install` package versions |
| [DL3042](https://github.com/hadolint/hadolint/wiki/DL3042) | ⚠️ Warning | 33 | pip cache not disabled (`--no-cache-dir` missing) |
| [DL3025](https://github.com/hadolint/hadolint/wiki/DL3025) | ⚠️ Warning | 40 | CMD not using JSON notation |
| [DL3015](https://github.com/hadolint/hadolint/wiki/DL3015) | ℹ️ Info | 14 | Missing `--no-install-recommends` flag |

### Top CVE Finding

```text
CVE-2026-31431 (HIGH · CVSS 7.8)
├─ Package: linux-libc-dev 6.8.0-111.111
├─ Vector:  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
├─ Title:   kernel: crypto: algif_aead — Revert to operating out-of-place
└─ Fix:     N/A (no patch available yet)
```

### Generated Reports

| Format | File | Size | Purpose |
|--------|------|------|---------|
| 📊 HTML Dashboard | `reports/security_report.html` | 15 KB | Visual dashboard for security teams |
| 📋 JSON Structured | `reports/security_report.json` | 1.4 MB | CI/CD integration and automation |
| 📝 Markdown Summary | `reports/security_report.md` | 782 B | GitHub PR comments |
| 📦 CycloneDX SBOM | `reports/sbom_vuln-app_latest_cyclonedx.json` | 505 KB | Executive Order 14028 compliance |
| 📦 SPDX SBOM | `reports/sbom_vuln-app_latest_spdx.json` | 576 KB | NTIA minimum elements compliance |

### Docker Images Built

```text
REPOSITORY           TAG      SIZE
security-scanner     latest   520 MB    ← Scanner with Trivy + Hadolint + Gitleaks
vuln-app             latest   517 MB    ← Deliberately vulnerable test image
```

> **Verdict:** All 4 scanning modules executed successfully end-to-end on Docker Desktop.
> The scanner correctly identified **877 CVEs**, **6 hardcoded secrets**, and **5 Dockerfile anti-patterns** in the intentionally vulnerable demo image — then blocked deployment via policy enforcement.

---

## 📁 Repository Structure

```text
docker-security-scanner/
│
├── 🎯 src/docker_security_scanner/   # Core scanning engine (importable package)
│   ├── scanner.py                    # Orchestrator, policy engine + CLI
│   ├── trivy_scanner.py              # CVE detection (Trivy wrapper)
│   ├── hadolint_scanner.py           # Dockerfile linting (Hadolint wrapper)
│   ├── gitleaks_scanner.py           # Secret detection (Gitleaks wrapper)
│   ├── sbom_generator.py             # CycloneDX / SPDX SBOM generation
│   ├── report_generator.py           # HTML, JSON and Markdown reports
│   ├── utils.py                      # Config, logging, severity, redaction
│   └── templates/
│       └── security_report.html.j2   # HTML dashboard (autoescaped)
│
├── ✅ tests/                         # 269 tests, 96% coverage (85% enforced)
│   ├── conftest.py                   # Fixtures and realistic tool output
│   ├── test_scanner.py               # Policy engine, incl. fail-closed tests
│   ├── test_cli.py                   # Pipeline wiring and exit codes
│   ├── test_trivy.py                 # CVE parsing
│   ├── test_dockerfile_validation.py # Hadolint parsing
│   ├── test_gitleaks.py              # Secret detection and redaction
│   ├── test_sbom.py                  # SBOM parsing
│   ├── test_reports.py               # Report escaping and verdict agreement
│   └── test_utils.py                 # Image refs, config, masking
│
├── 📚 examples/                      # Demo targets for the scanner
│   ├── vulnerable-app/               # Intentionally insecure
│   │   ├── Dockerfile                # ⚠️  Security issues (intentional)
│   │   ├── app.py                    # ⚠️  Hardcoded credentials & flaws
│   │   └── requirements.txt
│   └── secure-app/                   # Hardened version
│       ├── Dockerfile                # ✅ Digest-pinned, non-root, multi-stage
│       ├── app.py                    # ✅ Stdlib only, config from env
│       └── requirements.txt          # ✅ Intentionally empty
│
├── 🐳 docker/                        # Self-contained scanner image
│   └── Dockerfile                    # Bundles pinned Trivy/Hadolint/Gitleaks
│
├── 🚀 .github/
│   ├── workflows/
│   │   ├── security-scan.yml         # Lint, test, image build, scan
│   │   └── badge-update.yml          # Reports the latest scan conclusion
│   └── dependabot.yml                # Keeps the pinned action SHAs current
│
├── 📖 docs/
│   ├── getting-started.md            # Step-by-step walkthrough
│   ├── configuration.md             # All settings and environment variables
│   ├── output-formats.md             # Report schemas, JSON structure
│   └── troubleshooting.md            # Common issues and fixes
│
├── ⚙️  pyproject.toml                # black, isort, mypy, pytest, coverage
├── ⚙️  .flake8                       # flake8 (cannot read pyproject.toml)
├── ⚙️  .dockerignore                 # Keeps the build context small
├── 📦 requirements.txt               # 5 runtime dependencies
├── 📦 requirements-dev.txt           # Test and lint tooling
├── 📋 ARCHITECTURE.md                # System design, component interactions
├── 🔐 SECURITY.md                    # Security policy, disclosure
├── 🤝 CONTRIBUTING.md                # Development guide, PR process
└── 📄 README.md                      # This file
```

---

## 🏛️ Compliance & Standards

### Regulatory Alignment

| Standard | What It Requires | How Scanner Helps |
|----------|-----------------|------------------|
| **EO 14028** (U.S. Gov) | Software Bill of Materials | ✅ Generates CycloneDX & SPDX SBOM |
| **NIST SP 800-190** | Vulnerability scanning | ✅ Trivy + Hadolint integrated |
| **CIS Docker Benchmark** | Configuration security | ⚠️ Partial — Hadolint's rules overlap but are not a full implementation |
| **OWASP Top 10 for Docker**| CVE detection + secrets | ✅ Trivy + Gitleaks coverage |
| **SOC 2 Type II** | Evidence of controls | ✅ Automated reports with timestamps |
| **ISO 27001** | Info security management | ✅ Audit trail via GitHub Actions |

> **What this column means.** Each row describes evidence this scanner can
> *contribute* to an assessment, not a certification it confers. Running the
> tool does not make you compliant with any of these standards; it produces
> artifacts an assessor will ask for.

### Enterprise Audit Readiness

Auditors typically ask:
- Q: "How do you prevent vulnerable images from reaching production?"
- A: **[Show CI/CD workflow blocking CRITICAL CVEs]** ✅
- Q: "Can you prove which packages are in your images?"
- A: **[Show generated SBOM artifacts]** ✅
- Q: "How do you detect hardcoded secrets?"
- A: **[Show Gitleaks scan integration]** ✅

All answers backed by automated, auditable evidence.

---

## 🤝 Contributing

We welcome contributions from everyone — security engineers, DevOps practitioners, open source enthusiasts.

### Quick Contribution Path

```bash
# 1. Fork & clone, then create feature branch
git checkout -b feat/new-integration

# 2. Make changes + run tests locally
pytest tests/ --cov --cov-fail-under=85

# 3. Format & lint
black src/ tests/
flake8 src/ tests/

# 4. Commit and push PR
git commit -m "feat: Add new scanner integration"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines, code quality standards, and ideas for contribution.

---

## 📊 Project Metrics

### Quality Metrics

| Metric | Status | Enforced by |
|--------|--------|-------------|
| **Test coverage** | 96% (269 tests) | `pytest --cov-fail-under=85` |
| **Formatting** | clean | `black --check` |
| **Import order** | clean | `isort --check-only` |
| **Lint** | clean | `flake8` |
| **Type check** | clean | `mypy src/` |

Every row is a CI step that fails the build, and all five read their settings
from `pyproject.toml` / `.flake8`, so a local run and a CI run cannot disagree.

### Performance

Wall-clock time is dominated by Trivy's vulnerability-database download on a
cold cache and by image size, not by this scanner. For reference, on a warm
cache:

```text
alpine:3.19  (1 layer,  10 CVEs)    ~25 s  including DB check
ubuntu-based (5 layers, 6186 CVEs)  ~70 s  including both SBOMs
```

Set `TRIVY_CACHE_DIR` to a persistent, writable path and cache it between CI
runs — that is the single biggest win. `TRIVY_SKIP_UPDATE=true` skips the
database refresh entirely for air-gapped runs.

---

## 🚀 Get Started Now

### Option 1: Integrate Into Your Pipeline
See [GitHub Actions Integration](#-github-actions-integration--automated-security-gates) above.

### Option 2: Learn From Examples
```bash
git clone https://github.com/Vaibhav27072004/Automated-Docker-Image-Security-Scanner.git
cd Automated-Docker-Image-Security-Scanner/examples
# See what bad looks like
docker build -t vuln-app:latest vulnerable-app/
docker-scan image vuln-app:latest
```

---

## 📚 Learn More

| Want to... | Go to... |
|-----------|----------|
| **Use the scanner** | [Getting Started](docs/getting-started.md) |
| **Configure policies** | [Configuration Guide](docs/configuration.md) |
| **Understand architecture** | [ARCHITECTURE.md](ARCHITECTURE.md) |
| **Contribute code** | [CONTRIBUTING.md](CONTRIBUTING.md) |
| **Report security issue** | [SECURITY.md](SECURITY.md) |

---

## 🌟 Acknowledgments

This project stands on the shoulders of giants:
- **Trivy** — CVE database by Aqua Security, trusted by Docker, Kubernetes, AWS
- **Hadolint** — Dockerfile linter
- **Gitleaks** — Secret scanning by Zack Rice, adopted enterprise-wide
- **CycloneDX** — SBOM standard maintained by OWASP


<div align="center">

**Building better software security, one image at a time.**

Made for learning of DevSecOps by Vaibhav Kumar Sahu


</div>
