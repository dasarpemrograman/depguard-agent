# Dependency Guardian Agent — OpenClaw Agenthon 2026 Proposal

**Team:** TBD
**Project Name:** Dependency Guardian (DepGuard)
**Timeline:** 12 hours — Friday, 15 May 2026, 09:45–23:00 WIB
**Framework:** Hermes Agent (runtime) + custom skills (domain logic)

---

## 1. Concept

An autonomous AI agent that:

1. **Onboards users** — accepts a GitHub Personal Access Token + repo selection
2. **Enumerates dependencies** — scans repos for all dependency manifests (npm, pip, cargo, go, etc.)
3. **Watches vulnerabilities** — cross-references every dependency against OSV, GitHub Advisory DB, and npm audit
4. **Auto-patches** — bumps vulnerable deps to safe versions, resolves conflicts, runs tests
5. **Pushes fixes** — creates branches, commits, and opens PRs with fix summaries

**One-liner:** *"Add your repos. We watch. We fix. You merge."*

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    DepGuard Agent                        │
│  (Hermes Agent runtime + domain-specific system prompt)  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ onboard  │  │ scan     │  │ watch    │  │ patch   │ │
│  │  .skill  │──▶  .skill   │──▶  .skill  │──▶  .skill │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│       │             │              │              │      │
│       ▼             ▼              ▼              ▼      │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Tools (Hermes built-in)              │   │
│  │  terminal(gh, git, npm, pip) | web(OSV API)      │   │
│  │  browser(GitHub) | file(manifests)               │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │            External Services                      │   │
│  │  GitHub API | OSV.dev | npm audit | PyPI JSON    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
User provides token + repos
        │
        ▼
[onboard] ──▶ Validate token, list repos, user selects which to monitor
        │
        ▼
[scan] ──▶ Clone repo → find manifests → enumerate deps + versions → save to .depguard.json
        │
        ▼
[watch] ──▶ For each dep, query OSV/GitHub Advisory → mark CRITICAL/HIGH CVEs for patching and MEDIUM for report-only
        │
        ▼
[patch] ──▶ For each vulnerable dep → bump to min safe version → npm install/pip install → run tests
        │       │
        │       ├── tests pass → commit → push → create PR
        │       └── tests fail → try next safe version → if all fail, flag for manual review
        │
        ▼
[report] ──▶ Generate markdown summary: found X vulns, fixed Y, flagged Z for manual review
```

### 2.5. Dynamic Model Selection

DepGuard auto-selects the best free model from OpenRouter at startup — no hardcoding. The selector queries the OpenRouter models API, filters to free models, and ranks them by agent-specific criteria.

**How it works:**

```
Startup → query https://openrouter.ai/api/v1/models
       → filter: pricing.prompt=="0" AND pricing.completion=="0"
       → exclude non-chat models (audio gen, image gen, embeddings)
       → rank by: context_window (30%) + agent_capability (30%) + speed (15%) + context_bonus (10%)
       → select top model → write to ~/.hermes/depguard-model.txt
       → feed into Hermes config
```

**Current OpenRouter free model rankings (live query May 2026):**

| # | Model | Score | Context | Notes |
|---|-------|-------|---------|-------|
| 1 | `deepseek/deepseek-v4-flash:free` | 75.0 | 1024K | DeepSeek V4 Flash MoE, fast, 1M window |
| 2 | `openrouter/owl-alpha` | 70.0 | 1024K | Purpose-built for **agentic workloads** |
| 3 | `openrouter/pareto-code` | 50.0 | 1953K | Code routing — huge context |
| 4 | `openrouter/auto` | 50.0 | 1953K | Auto-routing to best model |
| 5 | `nousresearch/hermes-3-llama-3.1-405b:free` | 33.9 | 128K | Hermes 3 — **uncensored**, generalist |

**Notable exclusions:** 32 free models found, but 15+ are non-chat (Google Lyria = music gen, image models, embeddings). These are correctly filtered out.

**Scoring criteria:**

| Criterion | Weight | Rationale |
|-----------|--------|-----------|
| Context window | 30% | Bigger window = scan more deps in one pass |
| Agent capability | 30% | Known-competent chat models (DeepSeek, Hermes, Qwen, Nemotron) |
| Speed (Flash/Lite) | 15% | Faster inference = more tool calls in 12h sprint |
| Context bonus (≥1M) | 10% | Massive advantage for batch dependency scanning |
| Base score | 15% | Any free chat model starts here |

**The selector script (`scripts/select-model.sh`):**

```bash
#!/bin/bash
# Query OpenRouter for best free chat model, cache result for 24h.
# Output: "deepseek/deepseek-v4-flash:free" (or current best)

CACHE_FILE="${HOME}/.hermes/depguard-model.txt"
CACHE_TTL=$((24 * 3600))

if [ -f "$CACHE_FILE" ] && [ $(($(date +%s) - $(stat -c %Y "$CACHE_FILE"))) -lt "$CACHE_TTL" ]; then
    cat "$CACHE_FILE"
    exit 0
fi

# Fallback: ranked list of known good free chat models (updated May 2026)
FALLBACK_MODELS=(
    "deepseek/deepseek-v4-flash:free"
    "openrouter/owl-alpha"
    "openrouter/pareto-code"
    "openrouter/auto"
    "nousresearch/hermes-3-llama-3.1-405b:free"
)

MODELS_JSON=$(curl -sf --max-time 10 "https://openrouter.ai/api/v1/models" 2>/dev/null)

if [ -z "$MODELS_JSON" ]; then
    BEST="${FALLBACK_MODELS[0]}"
    echo "$BEST" | tee "$CACHE_FILE"
    echo "⚠️  OpenRouter API unreachable. Using fallback: $BEST" >&2
    exit 0
fi

BEST=$(echo "$MODELS_JSON" | python3 -c '
import json, sys

data = json.load(sys.stdin)
free_chat = []

# Patterns for non-chat models (audio gen, image gen, embeddings, etc.)
NON_CHAT = ["music", "audio", "song", "lyria", "image", "video",
            "embedding", "rerank", "moderation", "whisper", "tts", "speech"]

for m in data.get("data", []):
    price = m.get("pricing", {})
    if float(price.get("prompt", "1")) > 0: continue
    if float(price.get("completion", "1")) > 0: continue
    
    name = m.get("id", "")
    name_lower = name.lower()
    desc = (m.get("description", "") + m.get("name", "")).lower()
    ctx = int(m.get("context_length", 0))
    
    # Exclude non-chat models
    if any(p in name_lower or p in desc for p in NON_CHAT):
        continue
    
    # Scoring
    ctx_score = min(ctx / 1_000_000, 1.0) * 30
    agent_score = 30 if any(k in name_lower for k in ["hermes", "owl", "agent"]) else \
                  20 if any(k in name_lower for k in ["deepseek", "qwen", "gemma", "nemotron"]) else 10
    speed_score = 15 if any(k in name_lower for k in ["flash", "lite", "mini"]) else 0
    ctx_bonus = 10 if ctx >= 1_000_000 else (5 if ctx >= 256_000 else 0)
    
    total = ctx_score + agent_score + speed_score + ctx_bonus
    free_chat.append((total, name, ctx))

free_chat.sort(key=lambda x: (x[0], x[2]), reverse=True)

if free_chat:
    print(free_chat[0][1])  # best model ID
else:
    print("deepseek/deepseek-v4-flash:free")  # hard fallback
')

echo "$BEST" | tee "$CACHE_FILE"
echo "✅ Selected model: $BEST" >&2
```

**Integration with Hermes config:**

Instead of hardcoding `model:` in `config.yaml`, use a wrapper that injects the dynamic model:

```bash
#!/bin/bash
# depguard-run — launch DepGuard with dynamic model selection

MODEL=$(bash ~/depguard-agent/scripts/select-model.sh)

hermes \
  --config ~/depguard-agent/config.yaml \
  --model "$MODEL" \
  "$@"
```

Or inline in the one-liner:

```bash
hermes --config depguard.yaml --model "$(bash scripts/select-model.sh)" --prompt "monitor"
```

---

## 3. Technical Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Agent runtime | Hermes Agent | Already deployed, familiar, no new infra |
| LLM | **Best free model on OpenRouter (dynamic)** | Queries OpenRouter API at startup, ranks free models by context window, agent capability, and speed. Currently resolves to `deepseek/deepseek-v4-flash:free` (1M ctx, score 75). Runner-up: `openrouter/owl-alpha` (agent-native). Zero cost. |
| Dependency scanning | Native package managers (`npm ls`, `pip freeze`, `cargo tree`) | No extra SDK needed |
| Vulnerability DB | OSV.dev REST API + GitHub Advisory Database (GraphQL) | Free, comprehensive, covers npm/PyPI/Go/Cargo/Maven |
| Git operations | `gh` CLI + `git` | Built into Hermes terminal |
| Language support (MVP) | npm + pip | 90% of projects. Cargo/Go/Maven as stretch |
| Persistence | `.depguard.json` in repo root | Tracks state between agent runs |
| Reporting | Markdown → GitHub PR description | No UI needed |

---

## 4. Skill Decomposition

### Skill 1: `depguard-onboard`

**Purpose:** Accept GitHub token, authenticate GitHub CLI, create `.depguard.json`, validate repos, and let user opt-in.

**Implementation (Hermes skill):**

```markdown
# depguard-onboard

## Trigger
User provides "token: ghp_xxxx, repos: user/repo1, user/repo2"

## Steps
1. Create the initial `.depguard.json` skeleton before any skill reads it.
2. Authenticate with the supplied token:
   ```bash
   set +x
   if ! gh auth status --hostname github.com >/dev/null 2>&1; then
     printf '%s' "$TOKEN" | gh auth login --hostname github.com --with-token
   fi
   gh auth token >/dev/null
   ```
3. Validate requested repos with `gh repo view owner/name --json nameWithOwner,url`.
4. Save selected repos to `.depguard.json`:
   ```json
   {
     "repos": ["user/repo1", "user/repo2"],
     "last_scan": null,
     "token_hash": "<sha256 of token>",
     "dependencies": [],
     "vulnerabilities": [],
     "manual_review": [],
     "errors": []
   }
   ```
5. Confirm: "Monitoring 2 repos. Run `depguard-scan` to start."

## Pitfalls
- Token must have `repo` scope. If `gh auth login --with-token` or `gh auth token` fails, instruct user to create a token with repo scope.
- Never log or echo the token. Use `token_hash` for reference.
- `.depguard.json` is ignored by git and should be chmod `600`.
```

### Skill 2: `depguard-scan`

**Purpose:** Clone repos, find all dependency manifests, enumerate every dependency + version.

**Implementation (Hermes skill):**

```markdown
# depguard-scan

## Steps
1. Read `.depguard.json` → get repo list. If missing, stop and run onboard first.
2. Clean `/tmp/depguard/scan` before cloning to avoid stale collisions.
3. For each repo:
   a. Clone (shallow): `gh repo clone "$repo" "/tmp/depguard/scan/$safe_repo" -- --depth=1`
   b. Find manifests:
      ```bash
      find "/tmp/depguard/scan/$safe_repo" -maxdepth 4 -type f \( \
        -name 'package.json' -o \
        -name 'package-lock.json' -o \
        -name 'yarn.lock' -o \
        -name 'pnpm-lock.yaml' -o \
        -name 'requirements.txt' -o \
        -name 'requirements.in' -o \
        -name 'Pipfile' -o \
        -name 'Pipfile.lock' -o \
        -name 'pyproject.toml' -o \
        -name 'poetry.lock' -o \
        -name 'go.mod' -o \
        -name 'Cargo.toml' -o \
        -name 'Cargo.lock' -o \
        -name 'Gemfile' -o \
        -name 'pom.xml' \
      \)
      ```
   c. For npm projects: parse `package.json`; use lockfiles as audit/update evidence
   d. For pip projects: parse `requirements.txt`, `pyproject.toml`, `Pipfile`, and `Pipfile.lock`
   e. Save to `.depguard.json` under `dependencies`:
      ```json
      {
        "dependencies": [
          {"repo": "user/frontend", "ecosystem": "npm", "name": "express", "version": "4.18.2", "manifest": "package.json"},
          {"repo": "user/backend", "ecosystem": "pip", "name": "django", "version": "4.2.0", "manifest": "requirements.txt"}
        ]
      }
      ```

## Pitfalls
- Do not rely on `npm ls` for direct dependency enumeration; it fails without `node_modules`.
- Prefer deterministic manifest parsing over `pip freeze`.
- On command failure, stop the scan, append an error entry to `.depguard.json`, and report the failed stage.
```

### Skill 3: `depguard-watch`

**Purpose:** For every dependency, query vulnerability databases and flag CVEs.

**Implementation (Hermes skill):**

```markdown
# depguard-watch

## Vulnerability Sources

### Source 1: OSV.dev (free REST API)
```bash
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "express", "ecosystem": "npm"}, "version": "4.18.2"}'
```
Returns list of CVEs. Filter to fixed-version findings; mark CRITICAL/HIGH for auto-patch and MEDIUM as report-only by default.

### Source 2: GitHub Advisory Database (GraphQL — via gh CLI)
```bash
gh api graphql -f query='
  query($package: String!) {
    securityVulnerabilities(first: 10, ecosystem: NPM, package: $package) {
      nodes {
        advisory { summary, severity, identifiers { value } }
        vulnerableVersionRange
        firstPatchedVersion { identifier }
      }
    }
  }
' -f package="express"
```

### Source 3: npm audit (for npm projects)
```bash
cd /tmp/depguard/<repo> && npm audit --json 2>/dev/null
```
Parses directly. Catches transitive deps too.

## Steps
1. Read `.depguard.json` dependencies
2. For each dependency:
   a. Query OSV → record CVEs with `fixed_version != null`
   b. Query GitHub Advisory → merge results (deduplicate on CVE ID)
   c. For npm: also run `npm audit` in repo directory
3. Save findings:
   ```json
   {
     "vulnerabilities": [
       {
         "repo": "user/frontend",
         "package": "express",
         "version": "4.18.2",
         "cve": "CVE-2024-29041",
         "severity": "HIGH",
         "summary": "Open redirect in express.static()",
         "fixed_version": "4.19.2",
         "ecosystem": "npm"
       }
     ]
   }
   ```

## Pitfalls
- OSV API rate limit: 50 req/min unauthenticated. Space calls 1s apart.
- GitHub Advisory GraphQL may return empty for obscure packages → fall back to OSV only.
- `npm audit` needs package-lock.json → if missing, run `npm install` in the repo first.
```

### Skill 4: `depguard-patch`

**Purpose:** Bump vulnerable deps, run tests, push fixes.

**Implementation (Hermes skill):**

```markdown
# depguard-patch

## Steps

### Phase 1: Plan the fix
1. Read `.depguard.json` → get vulnerabilities with `fixed_version`
2. Group by repo (one PR per repo, all fixes together)
3. For each repo, determine:
   - Which manifest files need changes
   - Target versions for each vulnerable package
   - Whether semver constraints allow direct bump

### Phase 2: Apply fix (per repo)
1. Clone repo fresh: `gh repo clone <repo> /tmp/depguard/fix/<repo>`
2. Create branch:
   ```bash
   short_hash="$(printf '%s:%s' "$repo" "$(date +%s)" | sha256sum | cut -c1-8)"
   git checkout -b "depguard/fix-vulnerabilities-$(date +%Y%m%d)-$short_hash"
   ```
3. For each package to fix:
   - npm: edit `package.json` → `"express": "^4.19.2"` → run `npm install`
   - pip: edit `requirements.txt` → `django>=4.2.11,<5` → run `pip install -r requirements.txt`
4. Run tests:
   ```bash
   npm test 2>&1 || pytest 2>&1 || cargo test 2>&1 || go test ./... 2>&1
   ```
5. If tests pass:
   a. Commit: `git commit -m "fix(deps): patch X vulnerable dependencies [depguard]"`
   b. Push: `git push origin depguard/fix-vulnerabilities-YYYYMMDD-SHORTHASH`
   c. Create PR:
      ```bash
      gh pr create \
        --title "🔒 Fix X vulnerable dependencies (auto-patched by DepGuard)" \
        --body "$(cat /tmp/depguard/pr-body.md)" \
        --base main
      ```
6. If tests fail:
   a. Try next safe version (e.g. 4.19.3, 5.0.0)
   b. If all fail → flag as "manual_review" with reason (breaking change, test failure)

### Phase 3: Report
Generate `/tmp/depguard/pr-body.md`:
```markdown
## 🔒 Dependency Guardian — Vulnerability Fix Report

### Summary
- **Scanned:** XX repos, XX dependencies
- **Found:** XX vulnerabilities (X CRITICAL, X HIGH, X MEDIUM)
- **Fixed:** XX (auto-patched)
- **Needs manual review:** XX

### Fixed
| Package | Version | → | CVE | Severity |
|---------|---------|---|-----|----------|
| express | 4.18.2 | 4.19.2 | CVE-2024-29041 | HIGH |

### Auto-patch Details
- Tests: ✅ All passing
- Breaking changes: None detected
- Patched by: DepGuard Agent (Hermes Agent + OSV Advisory DB)
```

## Pitfalls
- Semver major version bumps (e.g., 4.x → 5.x) may break APIs → flag as "manual_review"
- Some repos use lockfiles (package-lock.json, Pipfile.lock) — just editing the manifest + running install updates the lockfile automatically
- If `main` branch is protected, PR won't auto-merge → that's fine, we only create the PR
```

---

## 5. Step-by-Step Build Guide

### One-Liner Install (Fresh VPS)

Deploy DepGuard Agent on any fresh Ubuntu/Debian VPS with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/dasarpemrograman/depguard-agent/main/install.sh | bash -s -- --openrouter-key YOUR_OPENROUTER_KEY
```

Or if you already have OpenRouter set up in `~/.hermes/.env`:

```bash
curl -fsSL https://raw.githubusercontent.com/dasarpemrograman/depguard-agent/main/install.sh | bash
```

Clone-based install:

```bash
git clone https://github.com/dasarpemrograman/depguard-agent.git
cd depguard-agent
bash install.sh --openrouter-key YOUR_OPENROUTER_KEY
```

**What it does:**
1. Installs system deps: `git`, `curl`, `python3`, `pip`, `nodejs`, `npm`, `gh`
2. Clones and installs Hermes Agent
3. Configures OpenRouter with a restrictive-permission .env file and a valid dynamic-model fallback
4. Installs `depguard-*` skills into `~/.hermes/skills/`
5. Copies `config.yaml` to `~/.hermes/depguard-config.yaml` with a valid fallback model
6. Installs `depguard-run` to `~/.local/bin`
7. Prints "DepGuard Agent installed" and the `depguard-run` quick start

The checked-in `install.sh` is the source of truth. It uses `set -euo pipefail`, parses `--openrouter-key`, writes `~/.hermes/.env` with mode `600`, installs `gh`, pins Hermes to `v2026.5.7` by default, and warns that onboarding will authenticate GitHub CLI with `gh auth login --with-token`.

### Hour 1 (09:45–10:45): Setup & Scaffold

```bash
# 1. Create project directory
mkdir ~/depguard-agent && cd ~/depguard-agent

# 2. Create Hermes config
cat > config.yaml << 'EOF'
agent:
  system_prompt: |
    You are DepGuard, an autonomous dependency vulnerability scanner and auto-patching agent.
    Your sole purpose: scan GitHub repositories for vulnerable dependencies and fix them.
    
    RULES:
    - Never modify code outside dependency manifests
    - Never push to main — always create a branch + PR
    - If a fix breaks tests, try the next safe version, then flag for manual review
    - Prioritize CRITICAL severity CVEs first, then HIGH
    - Output: concise markdown reports
    
    WORKFLOW:
    1. User provides GitHub token + repos → depguard-onboard
    2. User says "scan" → depguard-scan → enumerate all deps
    3. User says "watch" → depguard-watch → cross-reference CVEs
    4. User says "patch" → depguard-patch → fix + test + PR
    5. Auto: "monitor" → scan + watch + patch (full autonomous run)
  provider: openrouter
  # model is selected dynamically at runtime via scripts/select-model.sh
  # Do NOT hardcode — run: hermes --model "$(bash scripts/select-model.sh)"
  model: "deepseek/deepseek-v4-flash:free"  # valid fallback; depguard-run updates it at launch
  enabled_toolsets:
    - terminal
    - web
    - file
    - browser
  max_iterations: 120
EOF

# 3. Create skills directory
mkdir -p skills/depguard

# 4. Initialize git repo for the agent itself
git init && git add -A && git commit -m "init: DepGuard agent scaffold"
```

### Hours 2–3 (10:45–12:45): Build `depguard-onboard` + `depguard-scan`

**Files to create:**
```
skills/depguard/
├── onboard/SKILL.md
├── scan/SKILL.md
├── watch/SKILL.md
├── patch/SKILL.md
└── references/
    ├── osv-api.md
    └── github-advisory-graphql.md
```

**Implementation order:**

1. Write `onboard/SKILL.md` — simple, 30 lines. Token validation + repo selection + JSON save.
2. Write `scan/SKILL.md` — the meat. Must correctly parse:
   - `package.json` → dependencies + devDependencies
   - `requirements.txt` → package==version, package>=version
   - `pyproject.toml` → `[tool.poetry.dependencies]` section
   - `go.mod` → `require (...)` blocks
   - `Cargo.toml` → `[dependencies]` section

3. **Test manually:** Run Hermes with `--config config.yaml`, feed it a test repo.

### Hours 4–5 (12:45–14:45): Build `depguard-watch`

**API integration:**

1. Write `references/osv-api.md`:
   ```markdown
   ## OSV.dev API
   
   POST https://api.osv.dev/v1/query
   Body: {"package": {"name": "pkg", "ecosystem": "npm"}, "version": "1.0.0"}
   Response: {"vulns": [{"id": "CVE-...", "summary": "...", "severity": [...], "fixed": "2.0.0"}]}
   
   Rate limit: 50/min unauthenticated. Use `sleep 1.5` between requests.
   Ecosystem values: "npm", "PyPI", "Go", "crates.io", "Maven"
   ```

2. Write `references/github-advisory-graphql.md`:
   ```markdown
   ## GitHub Advisory Database (GraphQL)
   
   Query via `gh api graphql`:
   ```
   query($pkg: String!, $eco: SecurityAdvisoryEcosystem!) {
     securityVulnerabilities(first: 10, ecosystem: $eco, package: $pkg) {
       nodes {
         severity
         advisory { summary identifiers { value } }
         firstPatchedVersion { identifier }
         vulnerableVersionRange
       }
     }
   }
   ```
   Rate limit: 5000/hour (authenticated via gh token)
   ```

3. Write `watch/SKILL.md` — calls both APIs, deduplicates, saves findings.

### Hours 6–8 (14:45–17:45): Build `depguard-patch` + Testing

**Critical implementation details:**

1. **Semver resolution:** When `express@4.18.2` has CVE fixed in `4.19.2`:
   - Direct dep: edit `package.json` → `"express": "^4.19.2"` 
   - Transitive dep: edit `package.json` overrides/resolutions field, or run `npm update express`

2. **Test runner detection:**
   ```bash
   # Auto-detect test command
   if [ -f package.json ]; then
     TEST_CMD=$(node -e "const p=require('./package.json'); console.log(p.scripts?.test || 'npm test')")
   elif [ -f pyproject.toml ]; then
     TEST_CMD="pytest"
   elif [ -f go.mod ]; then
     TEST_CMD="go test ./..."
   elif [ -f Cargo.toml ]; then
     TEST_CMD="cargo test"
   fi
   ```

3. **PR body generation:** Use a template, fill in with actual findings from `.depguard.json`.

### Hours 9–10 (17:45–19:45): Integration Testing + Demo Preparation

**Test with real repos:**
```bash
# Test repo 1: Known vulnerable npm project
# Test repo 2: Python project with outdated deps
# Test repo 3: Clean project (should report 0 vulns)
```

**Record demo video script:**
```
0:00-0:15 — Show DepGuard agent config + skills
0:15-0:45 — Onboard: paste token, select 2 repos, agent validates
0:45-1:15 — Scan: agent clones, finds 47 deps across 4 manifests
1:15-1:45 — Watch: agent queries OSV, finds 3 HIGH CVEs
1:45-2:00 — Patch: agent bumps versions, tests pass, PR created on GitHub
```

### Hours 10–12 (19:45–23:00): Polish + Submission

- Write README.md (installation, usage, architecture)
- Create pitch deck (5 slides)
- Upload to Devpost
- Final test run

---

## 6. Dependencies & Tools

### Runtime dependencies (must be installed on agent host)
```bash
# Already on VPS
git gh node npm python3 pip curl jq

# Verify
gh --version    # GitHub CLI (for PR creation, GraphQL)
npm --version   # For npm audit, package.json parsing
python3 --version
```

### APIs used
| API | Auth | Rate Limit | Cost |
|-----|------|------------|------|
| GitHub API (REST + GraphQL) | User's PAT (`repo` scope) | 5000/hr | Free |
| OSV.dev | Unauthenticated | 50/min | Free |
| npm audit | None (runs locally) | N/A | Free |

### No external SaaS needed
Everything runs on the VPS. Zero paid APIs.

---

## 7. Testing Strategy

### Unit-level (manual, during build)
```bash
# Test token validation
gh auth status 2>&1

# Test dependency enumeration
cd /tmp/depguard/test-repo && npm ls --json

# Test OSV query
curl -s "https://api.osv.dev/v1/query" -d '{"package":{"name":"express","ecosystem":"npm"},"version":"4.18.2"}' | jq '.vulns | length'

# Test npm audit
cd /tmp/depguard/test-repo && npm audit --json | jq '.vulnerabilities | keys | length'
```

### Integration test (end-to-end)
```bash
# Create a test repo with a known vulnerability
mkdir /tmp/test-vuln-repo && cd /tmp/test-vuln-repo
echo '{"dependencies": {"express": "4.18.2"}}' > package.json
npm install
git init && git add -A && git commit -m "test"
gh repo create test-depguard-demo --public --source=. --push

# Run full agent pipeline (dynamic model)
hermes --config ~/depguard-agent/config.yaml \
  --model "$(bash ~/depguard-agent/scripts/select-model.sh)" \
  --prompt "Monitor repo: dasarpemrograman/test-depguard-demo. Full autonomous run."

# Verify: PR should exist on GitHub with express bumped to 4.19.2+
```

---

## 8. Submission Checklist

### Devpost fields
| Field | Content |
|-------|---------|
| Team name | `OpenClaw2026_<TeamName>` |
| Project Description | Dependency Guardian: autonomous AI agent that scans GitHub repos, detects vulnerable dependencies via OSV + GitHub Advisory, auto-patches to safe versions, runs tests, and opens PRs |
| GitHub Repo | `https://github.com/dasarpemrograman/depguard-agent` |
| Demo Video | YouTube unlisted, 2 min |
| Pitch Deck | PDF, 5 slides |
| AI Tools Used | Hermes Agent (runtime), DeepSeek V4 Flash via OpenRouter (LLM — free tier) |
| Best Payment Use Case | N/A (unless integrated later) |

### GitHub repo requirements
```bash
# Repo name
OpenClaw2026_<TeamName>_DepGuard

# Must contain
README.md         # Install + usage + architecture
LICENSE           # MIT
skills/           # All 4 skill files
config.yaml       # Agent config
test-repo/        # Sample vulnerable project for demo
```

### Pitch Deck (5 slides)
1. **Problem:** Dependency rot is universal. Most projects have outdated/vulnerable deps. Developers ignore Dependabot.
2. **Solution:** Autonomous AI agent that doesn't just alert — it **fixes** and ships the PR.
3. **Architecture:** Hermes Agent + 4 modular skills (onboard → scan → watch → patch) + OSV/GitHub APIs
4. **Key Features:** Multi-ecosystem (npm, pip, go, cargo), autonomous test-and-fix loop, severity-prioritized
5. **Impact:** Reduces mean time to patch from weeks to minutes. Works while you sleep.

---

## 9. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking change from version bump | Tests fail, PR gets bad fix | Try next version; if all fail, flag for manual review. Never force-merge. |
| OSV rate limit hit during scan | Some deps not checked | Space API calls 1.5s apart. Cache results in `.depguard.json`. |
| npm audit returns false positives | Unnecessary patches | Cross-reference with OSV + GitHub Advisory. Only fix if 2+ sources agree. |
| Token gets logged/leaked | Security incident | Use `token_hash` only. Never echo or log the raw token. Instruct agent to redact. |
| Large monorepo times out | Scan takes too long | Shallow clone (`--depth=1`). Limit manifest search to depth 3. Max 50 deps per repo for MVP. |
| Protected `main` branch | PR can't be merged | Agent only creates the PR. Human merge is the final safety check. |

---

## 10. Stretch Goals (if time permits)

- **Slack/Discord webhook:** Notify team when PR is ready
- **Scheduled monitoring:** Cron-based periodic scans
- **Maven/Gradle support:** Parse `pom.xml` and `build.gradle`
- **Dockerfile scanning:** Check base image versions against CVEs
- **Severity threshold config:** User sets minimum severity to auto-fix
- **Regression test:** Before/after benchmark to show no perf impact

---

## Quick Reference: Command Cheat Sheet

```bash
# Dynamic model selection (run once, cached 24h)
~/depguard-agent/scripts/select-model.sh

# Start agent with dynamic model
MODEL=$(bash ~/depguard-agent/scripts/select-model.sh)
hermes --config ~/depguard-agent/config.yaml --model "$MODEL"

# Or use the convenience wrapper
~/depguard-agent/depguard-run

# Onboard
@DepGuard onboard token:ghp_xxxx repos:user/repo1,user/repo2

# Full autonomous scan
@DepGuard monitor

# Individual steps
@DepGuard scan
@DepGuard watch
@DepGuard patch

# Check status
cat .depguard.json | jq .

# Create test repo (for demo/testing)
gh repo create test-vuln-demo --public --clone
cd test-vuln-demo
echo '{"dependencies":{"lodash":"4.17.15"}}' > package.json
npm install && git add -A && git commit -m "vulnerable" && git push
```
