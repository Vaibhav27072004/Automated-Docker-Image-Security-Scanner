# Output Formats

The Docker Security Scanner generates reports in three formats simultaneously.

---

## HTML Dashboard (`security_report.html`)

A dark-themed, interactive dashboard with:

- **Status banner** — overall PASS/FAIL at a glance
- **Metric cards** — CRITICAL/HIGH/MEDIUM/LOW CVE counts, lint issues, secrets
- **Vulnerability table** — all CVEs with NVD links, severity badges, CVSS scores
- **Lint issues table** — Hadolint findings with rule links and line numbers
- **Secrets table** — Gitleaks findings with redacted values

**Open locally:**
```bash
open reports/security_report.html        # macOS
start reports/security_report.html       # Windows
xdg-open reports/security_report.html   # Linux
```

---

## JSON Report (`security_report.json`)

Machine-parseable structured output. Schema:

```json
{
  "image": "demo-vulnerable:latest",
  "scan_timestamp": "2026-05-04T14:00:00.000000",
  "passed": false,
  "overall_severity": "CRITICAL",
  "trivy": {
    "summary": {
      "total": 116,
      "critical": 12,
      "high": 47,
      "medium": 38,
      "low": 19,
      "fixable": 94
    },
    "vulnerabilities": [
      {
        "id": "CVE-2023-0464",
        "severity": "CRITICAL",
        "package_name": "libssl1.1",
        "installed_version": "1.1.1n-0+deb11u4",
        "fixed_version": "1.1.1n-0+deb11u5",
        "cvss_score": 9.8,
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0464",
        "is_fixable": true
      }
    ]
  },
  "hadolint": {
    "summary": { "total": 8, "errors": 2, "warnings": 6 },
    "issues": [
      {
        "code": "DL3007",
        "level": "warning",
        "severity": "MEDIUM",
        "message": "Using latest is best avoided",
        "line": 1
      }
    ]
  },
  "gitleaks": {
    "summary": { "total": 3, "critical": 2, "high": 1 },
    "findings": [
      {
        "rule_id": "aws-access-token",
        "description": "AWS Access Key",
        "file": "examples/vulnerable-app/.env",
        "line_number": 4,
        "severity": "CRITICAL",
        "secret_snippet": "AKIA********************[REDACTED]"
      }
    ]
  },
  "sbom_results": [
    {
      "format": "cyclonedx",
      "total_components": 487,
      "output_path": "reports/sbom_demo-vulnerable_latest_cyclonedx.json"
    }
  ]
}
```

**Parsing with `jq`:**
```bash
# Get CRITICAL CVE count
jq '.trivy.summary.critical' reports/security_report.json

# List all fixable CRITICAL CVEs
jq '.trivy.vulnerabilities[] | select(.severity=="CRITICAL" and .is_fixable==true) | .id' \
  reports/security_report.json

# Get all secret file locations
jq '.gitleaks.findings[].file' reports/security_report.json
```

---

## Markdown Summary (`security_report.md`)

Used for GitHub PR comments and plain-text environments. Contains:

- Status banner (PASSED / FAILED)
- Summary table (all tools)
- Top 5 CRITICAL CVEs
- Secret findings

**Post to Slack:**
```bash
CONTENT=$(cat reports/security_report.md)
curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-type: application/json' \
  --data "{\"text\": \"${CONTENT}\"}"
```

---

## SBOM Files

### CycloneDX (`sbom_*_cyclonedx.json`)
Standard JSON format used for:
- Software supply chain compliance
- Government contract requirements (EO 14028)
- Enterprise security tools integration

### SPDX (`sbom_*_spdx.json`)
Linux Foundation standard used for:
- Open source license compliance
- Legal auditing
- NTIA SBOM minimum elements compliance
