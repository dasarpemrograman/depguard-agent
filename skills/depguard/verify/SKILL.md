---
name: depguard-verify
description: AST reachability analysis + PoC generation. Determines if detected CVEs are actually reachable in the codebase before patching.
version: 2.0.0
---

# depguard-verify

## Position in Pipeline

```
scan → watch → **verify** → patch → report
```

The verify phase sits between watch (vulnerability detection) and patch (auto-fix). Its job: determine whether discovered CVEs are **actually reachable** in the codebase. Unreachable CVEs are skipped from patching to avoid unnecessary churn.

## Trigger

Called automatically after `watch` completes, or manually:

```
depguard-monitor  # verify runs automatically after watch
```

Manual invocation:
```bash
python3 scripts/check-reachability.py --depguard-json .depguard.json --run-poc
```

## Severity Policy (inherited from watch)

- Only CRITICAL and HIGH CVEs proceed to reachability analysis by default.
- MEDIUM CVEs verified only when `--patch-medium` is set.
- Unreachable CVEs (any severity) are **skipped from patching** — no PR is created for code that doesn't use the vulnerable path.

## Failure Contract

If reachability analysis or PoC execution fails for a CVE:
- Mark `reachability.verdict = "unknown"` with `confidence` lowered.
- Record the failure reason in `reachability.reason`.
- Continue processing remaining CVEs.
- Do NOT block the patch phase — errors in verify downgrade confidence but don't halt the pipeline.

## Steps

### Step 1: Load State
```bash
python3 scripts/check-reachability.py --depguard-json .depguard.json --output /tmp/depguard/reachability.json
```

Reads `.depguard.json` to get all vulnerability entries with `action: "auto_patch"` (CRITICAL/HIGH, and optionally MEDIUM).

### Step 2: Build Import Graph
For each ecosystem represented in the vulnerabilities:
- Scan the cloned repo under `/tmp/depguard/scan/<repo>` 
- Parse all import/reference statements:
  - **npm:** `require('x')`, `import x from 'x'`, `import 'x'`
  - **PyPI:** `import x`, `from x import y`
  - **Go:** `import "x"`, `require` blocks in `go.mod`
  - **crates.io:** `use x`, `extern crate x`, `[dependencies]` in Cargo.toml
  - **Maven:** `<groupId>x</groupId>`, `implementation 'x:y'` in build.gradle
  - **RubyGems:** `gem 'x'`, `gem "x"`
- Build a set of all imported packages.

### Step 3: Extract Vulnerable Symbols

For each CVE, extract vulnerable function/method names from:
1. **Curated CVE Symbol Database** (bundled in `check-reachability.py`)
2. **Regex extraction** from advisory summary/description

Examples of extracted symbols:
- CVE-2024-29041 → `express.static`, `res.sendFile`, `res.redirect`, `encodeurl`
- CVE-2024-28849 → `http.request`, `https.request`, `follow-redirects`
- CVE-2023-26136 → `CookieJar`, `tough-cookie`

### Step 4: Search Codebase

Use ripgrep to search the cloned repo for:
1. Package import patterns (is the vulnerable package even used?)
2. Vulnerable function call patterns (is the vulnerable API surface reached?)

```bash
rg --no-heading -n --max-depth 10 'express\.static\s*\(' /tmp/depguard/scan/repo/
rg --no-heading -n --max-depth 10 'res\.sendFile\s*\(' /tmp/depguard/scan/repo/
```

### Step 5: Classify Reachability

| Verdict | Condition | Confidence | Action |
|---------|-----------|------------|--------|
| **unreachable** | Package NOT imported | 90% | Skip patching |
| **likely_unreachable** | Package imported, vulnerable functions NOT found | 60% | Skip patching (flag for review) |
| **reachable** | Package imported AND vulnerable functions found | 85% | Proceed to patch |
| **confirmed_reachable** | PoC test triggered the vulnerability | 100% | Proceed to patch — HIGH priority |
| **unknown** | Analysis error or insufficient data | 30% | Default: proceed to patch (conservative) |

### Step 6: Generate PoC Tests

For CVEs classified as `reachable`, generate PoC test files:

```bash
python3 scripts/check-reachability.py --depguard-json .depguard.json --poc-dir /tmp/depguard/poc
```

PoC files are created under `/tmp/depguard/poc/<cve_id>/vulnerability_poc_<cve_id>.test.{js,py,go,rs}`.

**Demo CVE-2024-29041 (express open redirect):**
The PoC:
1. Starts a minimal express server with `express.static()` and `res.sendFile()`
2. Sends benign request (should succeed)
3. Sends malicious path traversal request (should be blocked)
4. Sends encoded open-redirect request (should be blocked)
5. Exits with code 0 if all blocked → MITIGATED
6. Exits with code 1 if any succeed → VULNERABLE CONFIRMED

### Step 7: Run PoC Tests (optional)

```bash
python3 scripts/check-reachability.py --depguard-json .depguard.json --run-poc
```

Results:
- `triggered` → vulnerability confirmed, confidence = 100%, patch priority MAX
- `not_triggered` → fix may already be in place, confidence downgraded
- `error/timeout` → test failed to run, keep original classification

### Step 8: Update State

Reachability results are written back to `.depguard.json` under each vulnerability entry:

```json
{
  "vulnerabilities": [{
    "repo": "user/frontend",
    "package": "express",
    "version": "4.18.2",
    "cve": "CVE-2024-29041",
    "severity": "HIGH",
    "action": "auto_patch",
    "reachability": {
      "reachable": true,
      "confidence": 100,
      "verdict": "confirmed_reachable",
      "reason": "PoC test confirmed vulnerability is exploitable",
      "poc_result": "triggered",
      "poc_file": "/tmp/depguard/poc/cve-2024-29041/vulnerability_poc_cve-2024-29041.test.js",
      "matched_files": ["server.js", "app.js", "routes/static.js"],
      "matched_patterns": ["express\\.static\\s*\\("]
    }
  }]
}
```

A top-level `reachability_analysis` summary is also written:
```json
{
  "reachability_analysis": {
    "timestamp": "2026-05-15T12:00:00",
    "repo_path": "/tmp/depguard/scan/user__frontend",
    "total_analyzed": 12,
    "reachable": 4,
    "confirmed": 1
  }
}
```

## Integration with Patch

The `patch` skill reads `reachability.reachable`:
- `true` → proceed with auto-patch
- `false` (confidence >= 70%) → skip, save analysis
- `false` (confidence < 70%) → flag for manual review
- `unknown` → conservative: proceed with patch (don't skip potential real vulns)

## CVE Symbol Database

The `check-reachability.py` script includes a curated database of known CVE symbols. This grows over time. To add a new CVE:

```python
CVE_SYMBOLS["CVE-YYYY-NNNNN"] = {
    "package": "package-name",
    "ecosystems": ["npm"],
    "vulnerable_functions": ["func1", "func2"],
    "vulnerable_patterns": [r"func1\s*\(", r"module\.func2\s*\("],
    "advisory_summary": "Description of vulnerability",
    "fixed_version": "X.Y.Z",
    "poc_description": "How to test this vulnerability"
}
```

## Pitfalls

- **Transitive dependencies:** `check-reachability.py` only scans direct imports/calls. A vulnerable transitive dep may be reachable through an intermediate dependency. The tool marks these as `unknown` (confidence lowered) rather than false-negativing them.
- **Dynamic imports:** `require(variable)`, `import(variable)`, or `eval()`-based imports are invisible to static analysis. These are flagged in the reason text.
- **Monorepos:** The import graph is built per-repo-clone-directory. If a monorepo has packages that reference each other via workspace protocols, the analysis may miss cross-package import paths.
- **Advisory quality:** The regex extraction of vulnerable functions from advisory text is heuristic and may miss or incorrectly identify function names. The curated CVE database is more reliable.
- **PoC safety:** PoC tests for express start a local HTTP server on a random port. They do not make external network requests. Always run PoCs in an isolated environment.
- **Confidence scores:** Are heuristic estimates, not rigorous probabilities. A 90% unreachable confidence still means there's a 10% chance the vuln is reachable through paths static analysis can't see.
