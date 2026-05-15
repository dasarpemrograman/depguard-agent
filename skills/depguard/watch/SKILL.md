---
name: depguard-watch
description: Cross-reference every dependency against OSV.dev and GitHub Advisory Database for known CVEs.
version: 1.0.0
---

# depguard-watch

## Vulnerability Sources

## Severity Policy
- Auto-patch candidates: CRITICAL and HIGH vulnerabilities with a fixed version.
- Report-only: MEDIUM vulnerabilities with a fixed version, unless the user explicitly asks to patch MEDIUM.
- Ignored by default: LOW and informational findings.

## Failure Contract
If an OSV, GitHub Advisory, or npm audit request fails, record the failed source, package, repo, and short error message in `.depguard.json` under `errors`, then continue with the other vulnerability sources for that dependency. If all vulnerability sources fail for a dependency, mark it `manual_review` instead of treating it as clean.

### Source 1: OSV.dev (free REST API)
```bash
depguard-osv-query --ecosystem npm --package express --version 4.18.2
```
This sends the official OSV package/version request body to `POST /v1/query`:
```json
{"package": {"name": "express", "ecosystem": "npm"}, "version": "4.18.2"}
```
Returns list of CVEs. Filter to fixed-version findings. Mark CRITICAL/HIGH as auto-patch candidates and MEDIUM as report-only by default.

Rate limit: 50/min unauthenticated. Space calls 1.5s apart.

### Source 2: GitHub Advisory Database (GraphQL via gh CLI)
```bash
depguard-github-advisories --ecosystem NPM --package express
```
This helper uses `first: 100`, reads `pageInfo.hasNextPage`, and repeats the GraphQL query with `after: pageInfo.endCursor` until every advisory page is fetched.

### Source 3: npm audit (npm projects only)
```bash
cd /tmp/depguard/<repo> && npm audit --json 2>/dev/null
```
Catches transitive dependencies. Requires package-lock.json.

## Steps
1. Read `.depguard.json` dependencies
2. For each dependency, query all sources
3. Deduplicate on CVE ID, merge results
4. Save findings to `.depguard.json` under `vulnerabilities` with an `action` field:
   - `auto_patch` for CRITICAL/HIGH
   - `report_only` for MEDIUM
   - `manual_review` when severity or fixed version cannot be determined
5. For `manual_review` entries with no `fixed_version`, include guidance:
   - link or identifier for the advisory/CVE
   - current installed version and vulnerable range
   - note that no patched release is published yet
   - recommended action: temporarily remove/replace the dependency, disable the vulnerable feature path, pin to the least vulnerable supported release if the advisory says one exists, or add compensating controls until upstream publishes a fix
   - owner action: subscribe to the advisory and rerun `depguard-monitor` after a patched version is available

## Output Format
```json
{
  "vulnerabilities": [{
    "repo": "user/frontend",
    "package": "express",
    "version": "4.18.2",
    "cve": "CVE-2024-29041",
    "severity": "HIGH",
    "summary": "Open redirect in express.static()",
    "fixed_version": "4.19.2",
    "ecosystem": "npm",
    "action": "auto_patch"
  }]
}
```

## Pitfalls
- OSV ecosystem values: "npm", "PyPI", "Go", "crates.io", "Maven"
- GitHub Advisory may return empty for obscure packages — fall back to OSV
- Only auto-patch CVEs where `fixed_version` is available. Record no-fix CRITICAL/HIGH vulnerabilities as `manual_review` with the guidance above.
