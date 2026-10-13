# Architecture — Docker Security Scanner

## System Overview

Docker Security Scanner is a **pipeline-based, multi-tool security orchestrator** that enforces a zero-trust security gate on Docker images before they reach production. It chains four independent security analysis tools and produces unified, actionable reports.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     docker-scan CLI / GitHub Actions                 │
└─────────────────────────┬───────────────────────────────────────────┘
                           │ scan_image(image, dockerfile, scan_path)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SecurityScanner (scanner.py)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐  │
│  │TrivyScanner  │  │HadolintScanner│  │GitleaksScan│  │SBOM Gen  │  │
│  │CVE Detection │  │Dockerfile Lint│  │Secret Detect│  │CycloneDX │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  └────┬─────┘  │
└─────────┼─────────────────┼────────────────┼──────────────┼─────────┘
          │                 │                │              │
          └─────────────────┴────────────────┴──────────────┘
                                    │
                                    ▼
                        ┌──────────────────────┐
                        │  AggregatedResult    │
                        │  + Policy Check      │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   ReportGenerator    │
                        │  HTML  JSON  MD  SBOM│
                        └──────────────────────┘
```

---

## Component Descriptions

### `src/docker_security_scanner/scanner.py` — Orchestrator
The central coordinator. Responsible for:
- Accepting user input (image reference, paths, configuration)
- Invoking each scanner in the correct order
- Aggregating results into `AggregatedResult`
- Evaluating the security policy into a single `PolicyDecision`
- Coordinating report generation
- Providing the Click-based CLI

**Design decision — one verdict, computed once.** `evaluate_policy()` is the
only place a pass/fail decision is made. It returns a `PolicyDecision`, which is
attached to the `AggregatedResult` *before* any report is written, and the
console output, the HTML/JSON/Markdown reports and the process exit code all
read that one object. Nothing else is allowed to form an opinion, which is what
makes it impossible for the console to say PASSED while the report says failed.

**Design decision — the gate fails closed.** Each per-tool result carries both
an `error` string and a `ran` property. `evaluate_policy()` treats *any*
`ran == False` as a violation when `FAIL_ON_SCANNER_ERROR` is enabled (the
default), because a scanner that could not start reports zero findings and zero
findings would otherwise be indistinguishable from a clean image. An operator
can opt out, but they have to say so explicitly.

**Design decision — `passed` is the policy, `is_clean` is the facts.**
`AggregatedResult.passed` reflects only the configured policy, so a LOW CVE in a
base image does not fail a build unless asked. `is_clean` is the separate,
stricter "nothing at all was found" flag. An unevaluated `PolicyDecision` is
never a pass, so a crash between scanning and reporting cannot read as success.

**Design decision:** Scanners run **sequentially** rather than in parallel. This ensures deterministic output ordering and avoids resource contention when scanning large images, while keeping the codebase simple. Parallelism can be added later with `concurrent.futures`.

---

### `src/docker_security_scanner/trivy_scanner.py` — CVE Detection
Wraps the [Trivy](https://trivy.dev) CLI.

**Data flow:**
```
trivy image --format json --output <tmpfile> <image>
     ↓
TrivyScanner._parse_output()
     ↓
list[CVE] sorted by (severity_rank DESC, cvss_score DESC)
     ↓
TrivyScanResult
```

**Key design choices:**
- Uses `--exit-code 0` so Trivy never fails the subprocess; policy is enforced by our scanner
- Writes the JSON report to a **temporary file**, not `/dev/stdout`. There is no
  such path on Windows, so the previous approach silently produced no output —
  and no output used to look like no findings.
- Extracts CVSS v3 scores from multiple sources (NVD → RedHat → GHSA fallback)
- Sorts vulnerabilities by severity then CVSS score for report readability
- Distinguishes "ran and found nothing" from "could not run": an empty or
  unparseable report sets `error`, which the policy then treats as a violation

---

### `src/docker_security_scanner/hadolint_scanner.py` — Dockerfile Linting
Wraps [Hadolint](https://github.com/hadolint/hadolint).

**Checks performed:**
| Category | Example Rules |
|----------|---------------|
| Base image | DL3007 (no `:latest`), DL3006 |
| Security | DL3002 (no root user), DL4006 |
| Packages | DL3008 (pin apt versions) |
| Shell | SC2035 (glob matching) |

---

### `src/docker_security_scanner/gitleaks_scanner.py` — Secret Detection
Wraps [Gitleaks](https://gitleaks.io) in `--no-git` filesystem scan mode.

**Secret categories detected:**
- Cloud credentials (AWS, GCP, Azure)
- API tokens (GitHub PAT, Slack, Stripe)
- Private keys (RSA, SSH, PEM)
- Database connection strings
- Generic high-entropy strings

---

### `src/docker_security_scanner/sbom_generator.py` — SBOM Generation
Uses Trivy's SBOM output modes to generate:
- **CycloneDX JSON** — for compliance tooling and EO 14028
- **SPDX JSON** — for license auditing and NTIA minimum elements

---

### `src/docker_security_scanner/report_generator.py` — Report Generation
Generates reports without external template files (inline Jinja2 template).

**Report formats:**
| Format | Purpose |
|--------|---------|
| HTML | Human review, browser dashboard |
| JSON | CI/CD integration, programmatic parsing |
| Markdown | GitHub PR comments, plain-text environments |

---

### `src/docker_security_scanner/utils.py` — Shared Utilities
- `ScannerConfig` — Pydantic v2 model with env var loading
- `ImageRef` — parsed Docker image reference
- Custom exception hierarchy (`ScannerError` → specialisations)
- Shared `console` (Rich) and logging setup

---

## Data Flow

```
User Input
  │
  ├─ Image reference   ──► TrivyScanner ──► TrivyScanResult
  ├─ Dockerfile path   ──► HadolintScanner ──► HadolintResult
  ├─ Scan directory    ──► GitleaksScanner ──► GitleaksResult
  └─ Config            ──► SBOMGenerator ──► SBOMResult[]
                                │
                       AggregatedResult
                                │
                       PolicyViolationError?
                                │
                       ReportGenerator
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
         HTML report      JSON report      MD summary
```

---

## Configuration Architecture

```
.env file
    │
    └──► python-dotenv ──► os.environ
                               │
                          ScannerConfig (Pydantic)
                               │
                          SecurityScanner
                               │
               ┌───────────────┼────────────────┐
               │               │                │
         TrivyScanner  HadolintScanner  GitleaksScanner
```

Priority: CLI flags > env vars > Pydantic defaults

---

## Error Handling Strategy

```
ToolNotFoundError      — tool not installed, fail fast with clear message
DockerfileNotFoundError — bad path, fail fast
ScanExecutionError     — subprocess failure, log and continue
PolicyViolationError   — findings exceed thresholds, exit code 1
```

Individual scanner failures are **non-fatal** — the orchestrator continues
and records the error in the result. Policy checks run on what _was_ collected.

---

## Extension Points

### Adding a New Scanner
1. Implement `YourScanner` with `scan(target) -> YourResult`
2. `YourResult` must have `passed`, `to_dict()`, `summary()`
3. Add to `SecurityScanner.scan_image()` pipeline
4. Add `your_results` field to `AggregatedResult`

### Adding a New Report Format
1. Add a `_generate_yourformat()` method to `ReportGenerator`
2. Add the format string to the `report_formats` config option

### Extending SBOM Formats
1. Add a new Trivy output format mapping in `SBOMGenerator._build_command()`
2. Add a parser in `SBOMGenerator._parse_components()`

---

## Performance Considerations

| Component | Typical Duration | Notes |
|-----------|-----------------|-------|
| Trivy DB update | 30–120s | Cached after first run |
| Trivy scan | 10–60s | Depends on image size |
| Hadolint | < 1s | Very fast |
| Gitleaks | 1–10s | Depends on file count |
| SBOM generation | 10–60s | Shares Trivy cache |
| Report generation | < 1s | Pure Python |

**Total typical scan time: 30–120 seconds** (excluding first-time DB download)

---

## Security Model

The scanner itself follows security best practices:
- No network calls beyond tool subprocesses
- Secrets in findings are **redacted** before writing to reports
- Scanner container runs as non-root UID 10001
- No persistent state between scans
- All subprocess calls use `capture_output=True` (no shell injection)
