---
name: depguard-scan
description: Clone repos, find all dependency manifests, enumerate every dependency + version across 9 ecosystems (Phase 4).
version: 2.0.0
---

# depguard-scan

## Steps
1. Read `.depguard.json` for repo list. If the file is missing, stop and ask the user to run onboarding.
2. Clean clone workspace before each scan to avoid stale repo collisions:
   ```bash
   rm -rf /tmp/depguard/scan
   mkdir -p /tmp/depguard/scan
   ```
3. For each repo:
   a. Shallow clone:
      ```bash
      safe_repo="${repo//\//__}"
      gh repo clone "$repo" "/tmp/depguard/scan/$safe_repo" -- --depth=1
      ```
   b. Find manifests and lockfiles (Phase 4: expanded ecosystem support):
      ```bash
      find "/tmp/depguard/scan/$safe_repo" -maxdepth 4 -type f \( \
        -name 'package.json' -o \
        -name 'package-lock.json' -o \
        -name 'yarn.lock' -o \
        -name 'pnpm-lock.yaml' -o \
        -name 'requirements.txt' -o \
        -name 'requirements.in' -o \
        -name 'pyproject.toml' -o \
        -name 'poetry.lock' -o \
        -name 'Pipfile' -o \
        -name 'Pipfile.lock' -o \
        -name 'go.mod' -o \
        -name 'Cargo.toml' -o \
        -name 'Cargo.lock' -o \
        -name 'pom.xml' -o \
        -name 'build.gradle' -o \
        -name 'build.gradle.kts' -o \
        -name 'settings.gradle' -o \
        -name 'settings.gradle.kts' -o \
        -name 'Gemfile' -o \
        -name 'Gemfile.lock' -o \
        -name 'mix.exs' -o \
        -name 'composer.json' -o \
        -name 'composer.lock' -o \
        -name '*.gemspec' \
      \)
      ```
   c. Parse each manifest for dependencies + versions using the helper scripts and snippets below.
   d. Save to `.depguard.json` under `dependencies` array.
4. Report: "Scanned X repos, found Y dependencies".

## Failure Contract
If clone, manifest parsing, or JSON writing fails, stop the scan and append an error object to `.depguard.json`:
```json
{"stage": "scan", "repo": "owner/name", "command": "redacted command", "exit_code": 1, "message": "short stderr summary"}
```
Then report the failure clearly. Do not continue into watch with partial dependency data unless the user explicitly approves.

## Supported Ecosystems
- npm: `package.json` → dependencies + devDependencies + peerDependencies + optionalDependencies
- npm lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` detected as evidence for audit/update commands
- pip: `requirements.txt`, `requirements.in`, `pyproject.toml`, `Pipfile`
- Python lockfiles: `poetry.lock`, `Pipfile.lock` detected and parsed where possible
- Go: `go.mod` → require blocks
- Rust: `Cargo.toml` → [dependencies]
- Rust lockfiles: `Cargo.lock` detected for transitive/package version evidence

## Severity Policy
- Scan records all direct dependencies it can parse.
- Watch filters vulnerability results according to the shared policy: auto-patch CRITICAL and HIGH, report MEDIUM, ignore LOW by default.

## Parser Helpers

Use the installed parser script for supported lockfiles:

```bash
depguard-parse-lockfile "$manifest" "$repo"
```

It emits JSON Lines records for:
- `package-lock.json` (npm)
- `poetry.lock` (Python/PyPI)
- `Pipfile.lock` (Python/PyPI)
- `Cargo.lock` (Rust/crates.io)

For source manifests, use the snippets below.

## Parser Snippets

### npm `package.json`
```bash
node - "$manifest" "$repo" <<'NODE'
const fs = require("fs");
const manifest = process.argv[2];
const repo = process.argv[3];
const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
for (const section of sections) {
  for (const [name, version] of Object.entries(pkg[section] || {})) {
    console.log(JSON.stringify({repo, ecosystem: "npm", name, version, manifest, source: section}));
  }
}
NODE
```

### Python `requirements.txt` / `requirements.in`
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, re, sys
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([=<>!~]{1,2})?\s*([^;#\s]+)?")
for raw in Path(manifest).read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith(("#", "-r ", "--")):
        continue
    match = pattern.match(line)
    if not match:
        continue
    name, op, version = match.groups()
    print(json.dumps({
        "repo": repo,
        "ecosystem": "PyPI",
        "name": name,
        "version": version or "",
        "constraint": f"{op or ''}{version or ''}",
        "manifest": manifest,
        "source": "requirements"
    }))
PY
```

### Python `pyproject.toml`
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, tomllib
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
data = tomllib.loads(Path(manifest).read_text())

def emit(name, spec, source):
    if name.lower() == "python":
        return
    version = spec if isinstance(spec, str) else json.dumps(spec, sort_keys=True)
    print(json.dumps({"repo": repo, "ecosystem": "PyPI", "name": name, "version": version, "manifest": manifest, "source": source}))

project = data.get("project", {})
for dep in project.get("dependencies", []):
    name = dep.split(";", 1)[0].split("[", 1)[0].replace("~=", " ").replace(">=", " ").replace("<=", " ").replace("==", " ").replace(">", " ").replace("<", " ").split()[0]
    emit(name, dep, "project.dependencies")

poetry = data.get("tool", {}).get("poetry", {})
for section in ("dependencies", "dev-dependencies"):
    for name, spec in poetry.get(section, {}).items():
        emit(name, spec, f"tool.poetry.{section}")
for group, group_data in poetry.get("group", {}).items():
    for name, spec in group_data.get("dependencies", {}).items():
        emit(name, spec, f"tool.poetry.group.{group}.dependencies")
PY
```

### Python `Pipfile`
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, tomllib
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
data = tomllib.loads(Path(manifest).read_text())
for section in ("packages", "dev-packages"):
    for name, spec in data.get(section, {}).items():
        version = spec if isinstance(spec, str) else json.dumps(spec, sort_keys=True)
        print(json.dumps({"repo": repo, "ecosystem": "PyPI", "name": name, "version": version, "manifest": manifest, "source": section}))
PY
```

### Go `go.mod`
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, re, sys
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
in_block = False
for raw in Path(manifest).read_text().splitlines():
    line = raw.strip()
    if line == "require (":
        in_block = True
        continue
    if in_block and line == ")":
        in_block = False
        continue
    if line.startswith("require "):
        line = line.removeprefix("require ").strip()
    if in_block or raw.strip().startswith("require "):
        parts = re.split(r"\s+", line.split("//", 1)[0].strip())
        if len(parts) >= 2:
            print(json.dumps({"repo": repo, "ecosystem": "Go", "name": parts[0], "version": parts[1], "manifest": manifest, "source": "go.mod"}))
PY
```

### Rust `Cargo.toml`
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, tomllib
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
data = tomllib.loads(Path(manifest).read_text())
for section in ("dependencies", "dev-dependencies", "build-dependencies"):
    for name, spec in data.get(section, {}).items():
        version = spec if isinstance(spec, str) else spec.get("version", "")
        print(json.dumps({"repo": repo, "ecosystem": "crates.io", "name": name, "version": version, "manifest": manifest, "source": section}))
PY
```

### Maven `pom.xml` (Phase 4)
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, re
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
text = Path(manifest).read_text()
dep_pattern = re.compile(
    r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]*)</version>',
    re.DOTALL
)
for match in dep_pattern.finditer(text):
    gid, aid, ver = match.groups()
    print(json.dumps({
        "repo": repo, "ecosystem": "Maven",
        "name": f"{gid}:{aid}", "version": ver.strip(),
        "manifest": manifest, "source": "pom.xml"
    }))
PY
```

### Gradle `build.gradle` / `build.gradle.kts` (Phase 4)
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, re
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
text = Path(manifest).read_text()
dep_pattern = re.compile(
    r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation|annotationProcessor)\s*[\(]\s*[\'"]([^:\'"]+):([^:\'"]+):([^\'")\s]+)',
    re.IGNORECASE
)
for match in dep_pattern.finditer(text):
    gid, aid, ver = match.groups()
    print(json.dumps({
        "repo": repo, "ecosystem": "Maven",
        "name": f"{gid}:{aid}", "version": ver.strip().rstrip('"').rstrip("'"),
        "manifest": manifest, "source": "build.gradle"
    }))
PY
```

### Ruby `Gemfile` (Phase 4)
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, re
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
text = Path(manifest).read_text()
gem_pattern = re.compile(
    r'^\s*gem\s+[\'"]([^\'"]+)[\'"](?:\s*,\s*[\'"]([^\'"]*)[\'"])?',
    re.MULTILINE
)
for match in gem_pattern.finditer(text):
    name, ver = match.groups()
    print(json.dumps({
        "repo": repo, "ecosystem": "RubyGems",
        "name": name, "version": ver or "",
        "manifest": manifest, "source": "Gemfile"
    }))
PY
```

### Elixir `mix.exs` (Phase 4)
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys, re
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
text = Path(manifest).read_text()
dep_pattern = re.compile(
    r'{:(\w+(?:[._]\w+)*)\s*,\s*"(?:[~>=<\s]*)?(\d+\.\d+\.\d+(?:[-\w.]*)?)"',
)
for match in dep_pattern.finditer(text):
    name, ver = match.groups()
    print(json.dumps({
        "repo": repo, "ecosystem": "Hex",
        "name": name, "version": ver.strip(),
        "manifest": manifest, "source": "mix.exs"
    }))
PY
```

### PHP `composer.json` (Phase 4)
```bash
python3 - "$manifest" "$repo" <<'PY'
import json, sys
from pathlib import Path

manifest, repo = sys.argv[1], sys.argv[2]
data = json.loads(Path(manifest).read_text())
for section in ("require", "require-dev"):
    for name, version in data.get(section, {}).items():
        if name == "php":
            continue
        print(json.dumps({
            "repo": repo, "ecosystem": "Packagist",
            "name": name, "version": version,
            "manifest": manifest, "source": f"composer.{section}"
        }))
PY
```

## Pitfalls
- Do not rely on `npm ls` for direct manifest enumeration; it fails without `node_modules`. Parse manifests first, then use `npm audit` during watch when a lockfile exists.
- Python venv detection is optional. Prefer deterministic manifest parsing over `pip freeze`.
- Large repos: use shallow clone + limit manifest search depth to 3
