---
name: depguard-patch
description: Bump vulnerable dependencies to safe versions, run tests, create PRs. Phase 2 upgrade: dynamic log analysis for smarter fix plans.
version: 2.0.0
---

# depguard-patch

## Steps

## Severity Policy
- Patch CRITICAL and HIGH vulnerabilities by default.
- Do not patch MEDIUM vulnerabilities unless the user explicitly asks for MEDIUM patching.
- Do not patch LOW findings by default.
- **NEW (Phase 2):** Skip patching for CVEs marked `reachability.reachable: false` with confidence >= 70% by the verify phase.

## Failure Contract
If clone, branch creation, manifest edit, install, test, push, or PR creation fails, stop work for that repo, record a `manual_review` entry in `.depguard.json`, and report the command, exit code, and short stderr summary. Continue to the next repo only after clearly reporting the failure for the current repo.

### Phase 1: Plan
1. Read `.depguard.json` vulnerabilities with `fixed_version` and `action == "auto_patch"`
2. **NEW:** Filter out CVEs where `reachability.reachable == false` AND `reachability.confidence >= 70`
3. Group by repo (one PR per repo)
4. For each repo, determine:
   - Manifest files to edit
   - Target version for each vulnerable package
   - Semver compatibility (major bumps flagged for review)

### Phase 2: Apply Fix (per repo)
1. Clean the fix workspace for the repo:
   ```bash
   safe_repo="${repo//\//__}"
   rm -rf "/tmp/depguard/fix/$safe_repo"
   mkdir -p /tmp/depguard/fix
   ```
2. Clone repo: `gh repo clone "$repo" "/tmp/depguard/fix/$safe_repo" -- --depth=1`
3. Create a collision-resistant branch:
   ```bash
   short_hash="$(printf '%s:%s' "$repo" "$(date +%s)" | sha256sum | cut -c1-8)"
   git checkout -b "depguard/fix-vulns-$(date +%Y%m%d)-$short_hash"
   ```
4. For each package:
   - npm: edit `package.json` → bump version, run `npm install`
   - pip: edit `requirements.txt` → bump version, run `pip install`
   - go: edit `go.mod` → bump version, run `go mod tidy`
   - cargo: edit `Cargo.toml` → bump version, run `cargo update`
   - gradle: edit `build.gradle` / `build.gradle.kts` → bump version string
   - maven: edit `pom.xml` → bump `<version>` in dependency block
5. Auto-detect and run tests:
   ```bash
   [ -f package.json ] && npm test 2>&1 | tail -50 | tee /tmp/depguard/test-stderr-${safe_repo}.log
   [ -f pyproject.toml ] && pytest 2>&1 | tail -50 | tee /tmp/depguard/test-stderr-${safe_repo}.log
   [ -f go.mod ] && go test ./... 2>&1 | tail -50 | tee /tmp/depguard/test-stderr-${safe_repo}.log
   [ -f Cargo.toml ] && cargo test 2>&1 | tail -50 | tee /tmp/depguard/test-stderr-${safe_repo}.log
   ```
6. **Tests pass:** commit + push + create PR
7. **Tests fail → Phase 2 Dynamic Log Analysis (NEW):**

### Phase 2 (NEW): Dynamic Log Analysis

When a test fails after patching, DepGuard now performs intelligent failure analysis before flagging for manual review.

#### Step 7a: Capture Failure Context

```bash
# Capture last 50 lines of stderr from the test run
tail -50 /tmp/depguard/test-stderr-${safe_repo}.log > /tmp/depguard/test-failure-${safe_repo}.log

# Also capture which files were changed
git diff --stat HEAD~1 2>/dev/null > /tmp/depguard/patch-diff-${safe_repo}.log
```

#### Step 7b: LLM-Powered Correction Plan

Feed the failure context to the Hermes model for analysis:

```bash
python3 - <<'PY'
import json, os, subprocess

failure_log = open("/tmp/depguard/test-failure-REPO.log").read()
patch_diff = open("/tmp/depguard/patch-diff-REPO.log").read()
vuln_info = json.load(open(".depguard.json"))

# Build the analysis prompt
prompt = f"""Analyze this dependency patch test failure.

## Vulnerability
Package: {vuln_info['vulnerabilities'][0]['package']}
CVE: {vuln_info['vulnerabilities'][0]['cve']}
Version change: {vuln_info['vulnerabilities'][0]['version']} → {vuln_info['vulnerabilities'][0]['fixed_version']}

## Patch Diff
{patch_diff[:3000]}

## Test Failure (last 50 lines of stderr)
{failure_log[:5000]}

## Instructions
1. Identify the ROOT CAUSE of the test failure
2. Determine if this is a breaking API change or a simple version constraint issue
3. Suggest a SPECIFIC Correction Plan with actionable steps
4. Rate the fix difficulty: TRIVIAL / MINOR / MAJOR / BREAKING

Respond in JSON format:
{{
  "root_cause": "...",
  "failure_type": "breaking_change | api_deprecation | type_error | version_conflict | test_config | other",
  "correction_plan": ["step 1", "step 2", ...],
  "difficulty": "TRIVIAL | MINOR | MAJOR | BREAKING",
  "suggested_action": "retry_with_version | update_test | update_code | manual_review",
  "suggested_version": "X.Y.Z or null",
  "confidence": 0-100
}}
"""

# Call the LLM via hermes CLI
result = subprocess.run(
    ["hermes", "chat", "--query", prompt, "--max-turns", "10", "--output-format", "json"],
    capture_output=True, text=True, timeout=60
)
analysis = json.loads(result.stdout)
json.dump(analysis, open("/tmp/depguard/correction-plan-REPO.json", "w"), indent=2)
PY
```

The LLM analyzes:
1. **Root cause** — what specifically broke
2. **Failure type** — breaking change, API deprecation, type error, version conflict, test config issue, or other
3. **Correction Plan** — specific, actionable steps
4. **Difficulty rating** — TRIVIAL (one-liner fix), MINOR (few lines), MAJOR (significant refactor), BREAKING (architectural change)
5. **Suggested action** — retry with different version, update test expectations, update calling code, or flag for manual review

#### Step 7c: Store Correction Plan

The LLM-generated Correction Plan is appended to `manual_review` in `.depguard.json`:

```json
{
  "manual_review": [{
    "repo": "user/backend",
    "package": "django",
    "cve": "CVE-2024-XXXXX",
    "reason": "Test failure after bumping django 4.2.0 → 4.2.11",
    "correction_plan": {
      "root_cause": "django.middleware.csrf.CsrfViewMiddleware changed signature in 4.2.11",
      "failure_type": "api_deprecation",
      "correction_plan": [
        "Update CsrfViewMiddleware import in middleware.py line 23",
        "Add new required parameter 'get_response' to constructor",
        "Run 'python manage.py check' to verify Django config"
      ],
      "difficulty": "MINOR",
      "suggested_action": "update_code",
      "confidence": 85
    },
    "test_stderr_snippet": "...",
    "patch_diff_summary": "..."
  }]
}
```

#### Step 7d: Smart Retry (for TRIVIAL/MINOR difficulties)

If the LLM rates the fix as TRIVIAL or MINOR with confidence > 70%:
1. Apply the Correction Plan steps automatically
2. Re-run tests
3. If tests now pass → commit + PR
4. If still fail → flag manual_review with the full analysis

For MAJOR or BREAKING difficulties, skip the retry and flag directly.

### Phase 3: Report
Generate PR body with markdown table of fixes.

## PR Body Template (Updated)
```markdown
## 🔒 Dependency Guardian — Vulnerability Fix Report

### Summary
- **Scanned:** X repos, Y dependencies
- **Found:** Z vulnerabilities (A CRITICAL, B HIGH, C MEDIUM)
- **Verified reachable:** R (via AST analysis)
- **Fixed:** D (auto-patched)
- **Needs manual review:** E (with AI-generated correction plans)

### Fixed
| Package | From | To | CVE | Severity | Reachable |
|---------|------|----|-----|----------|-----------|
| express | 4.18.2 | 4.19.2 | CVE-2024-29041 | HIGH | ✅ Confirmed (PoC) |

### Skipped (Unreachable)
| Package | CVE | Reason |
|---------|-----|--------|
| braces | CVE-2024-4068 | Not imported in codebase (90% confidence) |

### Needs Manual Review (with AI Correction Plans)
| Package | CVE | Difficulty | Plan |
|---------|-----|-----------|------|
| django | CVE-2024-XXXXX | MINOR | Update CsrfViewMiddleware constructor |

### Auto-patch Details
- Tests: ✅ All passing
- Breaking changes: None
- Patched by: DepGuard Agent (Hermes Agent + OSV Advisory DB)
- Reachability verified by: DepGuard Verify Phase (AST analysis + PoC tests)
```

## Pitfalls
- Semver major bumps (4.x → 5.x) may break APIs → flag manual_review
- Lockfiles auto-update when manifest + install runs
- Protected branches: PR won't auto-merge — human review is the final safety check
- Auth: `gh auth status` must be valid with `repo` scope
- **NEW:** LLM-generated correction plans are suggestions only. They are NOT automatically applied unless difficulty is TRIVIAL/MINOR. Always verify before committing.
- **NEW:** The log analysis captures the last 50 lines of stderr. If the failure is earlier in the output, the LLM may miss context. Consider increasing the capture window for complex test suites.
- **NEW:** `hermes chat` for log analysis may be unavailable in CI/non-interactive contexts. The pipeline gracefully falls back to flagging without the AI correction plan.
