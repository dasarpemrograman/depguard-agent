---
name: depguard-onboard
description: Accept GitHub token, authenticate gh, create .depguard.json, validate repos, and let user opt in for monitoring.
version: 1.0.0
---

# depguard-onboard

## Trigger
User: "onboard token:ghp_xxxx, repos:user/repo1,user/repo2"

## Severity Policy
- DepGuard auto-patches CRITICAL and HIGH vulnerabilities.
- MEDIUM findings are recorded in reports unless the user explicitly asks to patch them.
- LOW findings are ignored by default.

## Failure Contract
If any command exits non-zero, stop the workflow and report:
- the step name
- the command that failed, with secrets redacted
- the exit code and stderr summary
- the next manual command the user can run

Do not continue into scan/watch/patch after onboarding failure.

## Steps
1. Parse the user input into:
   - `TOKEN`: the supplied GitHub Personal Access Token
   - `REPOS`: comma-separated `owner/name` repositories
2. Create the initial `.depguard.json` skeleton before any skill reads it:
   ```bash
   python3 - <<'PY'
   import json
   from pathlib import Path

   path = Path(".depguard.json")
   if not path.exists():
       path.write_text(json.dumps({
           "repos": [],
           "last_scan": None,
           "token_hash": None,
           "dependencies": [],
           "vulnerabilities": [],
           "manual_review": [],
           "errors": []
       }, indent=2) + "\n")
   PY
   chmod 600 .depguard.json
   ```
3. Authenticate GitHub CLI with the supplied token. Never echo the raw token:
   ```bash
   set +x
   if ! gh auth status --hostname github.com >/dev/null 2>&1; then
     printf '%s' "$TOKEN" | gh auth login --hostname github.com --with-token
   fi
   gh auth token >/dev/null
   gh auth status --hostname github.com
   ```
4. Validate the requested repos:
   ```bash
   for repo in ${REPOS//,/ }; do
     gh repo view "$repo" --json nameWithOwner,url >/dev/null
   done
   ```
5. Save selected repos and the token hash to `.depguard.json`:
   ```json
   {
     "repos": ["user/repo1"],
     "last_scan": null,
     "token_hash": "<sha256>",
     "dependencies": [],
     "vulnerabilities": [],
     "manual_review": [],
     "errors": []
   }
   ```
   Use this snippet after setting `TOKEN` and `REPOS`:
   ```bash
   python3 - <<'PY'
   import hashlib, json, os
   from pathlib import Path

   token = os.environ["TOKEN"]
   repos = [r.strip() for r in os.environ["REPOS"].split(",") if r.strip()]
   path = Path(".depguard.json")
   data = json.loads(path.read_text()) if path.exists() else {}
   data.update({
       "repos": repos,
       "last_scan": None,
       "token_hash": hashlib.sha256(token.encode()).hexdigest(),
       "dependencies": data.get("dependencies", []),
       "vulnerabilities": data.get("vulnerabilities", []),
       "manual_review": data.get("manual_review", []),
       "errors": data.get("errors", []),
   })
   path.write_text(json.dumps(data, indent=2) + "\n")
   PY
   chmod 600 .depguard.json
   ```
6. Confirm the selected repo count and tell the user to run scan or monitor.

## Pitfalls
- Token needs `repo` scope
- Prefer `gh auth token` when already authenticated; otherwise use `gh auth login --with-token`.
- Never log or echo raw token. Use SHA256 hash for reference only.
- Add `.depguard.json` to `.gitignore`; it contains repo selections and token metadata.
