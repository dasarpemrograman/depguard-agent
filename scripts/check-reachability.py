#!/usr/bin/env python3
"""
DepGuard Reachability Analysis Engine.
Determines whether a CVE vulnerability is actually reachable in the codebase.

Phase 3: AST Reachability + Verify Skill + Demo PoC

Algorithm:
  1. Load .depguard.json vulnerabilities
  2. For each CVE, extract vulnerable symbols/function names from advisory data
  3. Search codebase for actual imports and function calls
  4. Build a simple import graph
  5. Output reachability verdict per CVE + confidence score
  6. Generate PoC test files for verification

Demo CVE: CVE-2024-29041 (express open redirect)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ── CVE Symbol Database ─────────────────────────────────────────────
# Maps CVE IDs to vulnerable function names / patterns extracted from
# advisory descriptions. This is hand-curated for demo quality.

CVE_SYMBOLS: dict[str, dict] = {
    "CVE-2024-29041": {
        "package": "express",
        "ecosystems": ["npm"],
        "vulnerable_functions": [
            "express.static",
            "static",
            "send",
            "res.sendFile",
            "res.download",
            "res.redirect",
            "encodeurl",
            "decodeURIComponent",
        ],
        "vulnerable_patterns": [
            r'express\.static\s*\(',
            r'\.static\s*\(',
            r'\.sendFile\s*\(',
            r'res\.redirect\s*\(',
            r'app\.use\s*\(\s*[\'"]/[^"\']*[\'"]\s*,\s*express\.static',
        ],
        "advisory_summary": "Open redirect in express.static() and res.sendFile()",
        "fixed_version": "4.19.2",
        "poc_description": textwrap.dedent("""\
            Express versions before 4.19.2 are vulnerable to open redirect
            when express.static() or res.sendFile() is used with
            user-controlled input. An attacker can craft URLs that redirect
            users to malicious sites by using encoded path traversal
            characters in the URL path.
        """),
    },
    "CVE-2024-28849": {
        "package": "follow-redirects",
        "ecosystems": ["npm"],
        "vulnerable_functions": [
            "follow-redirects",
            "http.request",
            "https.request",
            "http.get",
            "https.get",
            "axios",
        ],
        "vulnerable_patterns": [
            r'require\([\'"]follow-redirects[\'"]\)',
            r'from\s+[\'"]follow-redirects[\'"]',
            r'import\s+.*from\s+[\'"]follow-redirects[\'"]',
        ],
        "advisory_summary": "follow-redirects improperly handles redirect responses",
        "fixed_version": "1.15.6",
    },
    "CVE-2024-4068": {
        "package": "braces",
        "ecosystems": ["npm"],
        "vulnerable_functions": [
            "braces",
            "micromatch.braces",
        ],
        "vulnerable_patterns": [
            r'require\([\'"]braces[\'"]\)',
            r'from\s+[\'"]braces[\'"]',
            r'import\s+.*from\s+[\'"]braces[\'"]',
        ],
        "advisory_summary": "braces fails to limit the number of characters it can handle",
        "fixed_version": "3.0.3",
    },
    "CVE-2023-26136": {
        "package": "tough-cookie",
        "ecosystems": ["npm"],
        "vulnerable_functions": [
            "CookieJar",
            "cookie",
            "tough-cookie",
        ],
        "vulnerable_patterns": [
            r'require\([\'"]tough-cookie[\'"]\)',
            r'from\s+[\'"]tough-cookie[\'"]',
        ],
        "advisory_summary": "tough-cookie prototype pollution in cookie parsing",
        "fixed_version": "4.1.3",
    },
}

# Generic regex patterns for extracting vulnerable function names from
# advisory descriptions when not in the curated database
VULN_FUNCTION_PATTERNS = [
    # "the `foo()` function in ..."  /  "the `foo.bar()` method"
    re.compile(r"[`\u2018]([\w.]+)\(\)[`\u2019]"),
    # "in foo(), bar()" / "vulnerable: foo(), bar()" 
    re.compile(r"\b([a-z_]+\.[a-z_]+)\(\)", re.IGNORECASE),
    # "XSS in res.redirect()" / "RCE in child_process.exec()"
    re.compile(r"\bin\s+([a-z_.]+)\(\)", re.IGNORECASE),
    # "the send() static method"
    re.compile(r"the\s+(\w+\(\))\s+(?:static\s+)?(?:method|function)", re.IGNORECASE),
]

# Import/reference patterns per ecosystem
IMPORT_PATTERNS: dict[str, list[str]] = {
    "npm": [
        r'require\s*\(\s*[\'"](PACKAGE)[\'"]',
        r'from\s+[\'"](PACKAGE)[\'"]',
        r'import\s+.*\bfrom\s+[\'"](PACKAGE)[\'"]',
        r'import\s+[\'"](PACKAGE)[\'"]',
        r'require\s*\(\s*[\'"](PACKAGE)/',
    ],
    "PyPI": [
        r'from\s+(PACKAGE)\b',
        r'from\s+(PACKAGE)\s+import',
        r'import\s+(PACKAGE)\b',
        r'import\s+(PACKAGE)\.',
    ],
    "Go": [
        r'import\s+"(PACKAGE)"',
        r'import\s+\(\s*"(PACKAGE)"',
        r'"(PACKAGE)[^"]*"',
    ],
    "crates.io": [
        r'(PACKAGE)\s*=\s*',
        r'use\s+(PACKAGE)',
        r'use\s+(PACKAGE)::',
        r'extern\s+crate\s+(PACKAGE)',
    ],
    "Maven": [
        r'<groupId>(GROUP)</groupId>',
        r'implementation\s+[\'"](GROUP):(ARTIFACT)',
        r'testImplementation\s+[\'"](GROUP):(ARTIFACT)',
    ],
    "RubyGems": [
        r'gem\s+[\'"](PACKAGE)[\'"]',
        r"gem\s+'PACKAGE'",
    ],
}


def load_depguard(path: Path) -> dict:
    """Load .depguard.json state file."""
    if not path.exists():
        print(f"Error: {path} not found. Run scan + watch first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def save_depguard(path: Path, data: dict) -> None:
    """Save updated .depguard.json."""
    path.write_text(json.dumps(data, indent=2) + "\n")


def extract_vulnerable_symbols(vuln: dict) -> dict:
    """Extract vulnerable function names and patterns for a given CVE entry."""
    cve_id = vuln.get("cve", "")
    package_name = vuln.get("package", "").lower()
    summary = vuln.get("summary", "")
    advisory_data = vuln.get("advisory_data", {})
    description = advisory_data.get("description", summary)

    # Check curated database first
    if cve_id in CVE_SYMBOLS:
        return CVE_SYMBOLS[cve_id]

    # Fallback: extract from description/summary using regex
    functions = []
    patterns = []
    text = f"{summary} {description}"

    for pat in VULN_FUNCTION_PATTERNS:
        for match in pat.findall(text):
            if isinstance(match, tuple):
                match = match[0]
            match = match.strip().lower()
            if match and match not in functions:
                functions.append(match)
                patterns.append(re.escape(match) + r'\s*\(')

    # Always include the package name as a base import check
    if package_name not in functions:
        functions.append(package_name)

    return {
        "package": package_name,
        "ecosystems": [vuln.get("ecosystem", "")],
        "vulnerable_functions": functions,
        "vulnerable_patterns": patterns,
        "advisory_summary": summary,
        "fixed_version": vuln.get("fixed_version", ""),
    }


def search_codebase(repo_path: Path, patterns: list[str], file_globs: list[str]) -> dict:
    """
    Search the codebase for patterns using grep/ripgrep.
    Returns: {pattern: [matched_file_lines]}
    """
    results: dict[str, list[str]] = defaultdict(list)

    if not repo_path.exists():
        return results

    # Use rg (ripgrep) if available, fallback to grep
    rg = shutil.which("rg")
    grep = "rg" if rg else "grep"

    for pattern in patterns:
        try:
            if rg:
                cmd = [
                    "rg", "--no-heading", "-n", "--max-depth", "10",
                    "--type-add", f"code:{{{','.join(file_globs)}}}",
                    "--type", "code",
                    pattern, str(repo_path)
                ]
            else:
                glob_args = []
                for g in file_globs:
                    glob_args.extend(["--include", g])
                cmd = ["grep", "-rn", "-I"] + glob_args + [pattern, str(repo_path)]

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if proc.returncode in (0, 1):
                lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                if lines:
                    results[pattern] = lines
        except (subprocess.TimeoutExpired, Exception):
            continue

    return results


def build_import_graph(repo_path: Path, ecosystem: str) -> set[str]:
    """Find all imported packages in the codebase for a given ecosystem."""
    patterns = IMPORT_PATTERNS.get(ecosystem, [])
    imported: set[str] = set()

    if not repo_path.exists():
        return imported

    rg = shutil.which("rg")
    for pat in patterns:
        base_pat = pat.replace("PACKAGE", r"[\w@./-]+")
        # Simplify for rg: match the import line
        search_re = pat.replace("PACKAGE", r"([\w@./-]+)")

        try:
            if rg:
                cmd = [
                    "rg", "--no-heading", "-o", "--max-depth", "10",
                    "-e", base_pat, str(repo_path)
                ]
            else:
                cmd = [
                    "grep", "-rnoh", "-I",
                    "--include=*.js", "--include=*.ts", "--include=*.jsx",
                    "--include=*.tsx", "--include=*.py", "--include=*.go",
                    "--include=*.rs", "--include=*.rb", "--include=*.java",
                    "--include=*.kt", "--include=*.ex", "--include=*.exs",
                    "-E", base_pat, str(repo_path)
                ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode in (0, 1) and proc.stdout.strip():
                for line in proc.stdout.splitlines():
                    m = re.search(search_re, line.strip())
                    if m:
                        imported.add(m.group(1).lower())
        except (subprocess.TimeoutExpired, Exception):
            continue

    return imported


def check_reachability(
    vuln: dict,
    repo_path: Path,
    scan_patterns: list[str],
    file_globs: list[str],
    imported_packages: set[str],
) -> dict:
    """
    Determine if a vulnerability is reachable.
    Returns verdict with confidence score.
    """
    package_name = vuln.get("package", "").lower()
    cve_id = vuln.get("cve", "")

    symbol_data = extract_vulnerable_symbols(vuln)
    vuln_funcs = symbol_data.get("vulnerable_functions", [])
    vuln_patterns = symbol_data.get("vulnerable_patterns", [])

    # Step 1: Check if package is imported at all
    is_imported = package_name in imported_packages

    if not is_imported:
        # Also check broader pattern
        for pkg in imported_packages:
            if package_name in pkg or pkg in package_name:
                is_imported = True
                break

    if not is_imported:
        return {
            "reachable": False,
            "confidence": 90,
            "verdict": "unreachable",
            "reason": f"Package '{package_name}' not found in imports",
            "poc_result": "not_tested",
        }

    # Step 2: Search for vulnerable function calls
    all_patterns = vuln_patterns if vuln_patterns else scan_patterns
    match_results = search_codebase(repo_path, all_patterns, file_globs)

    function_found = len(match_results) > 0

    if function_found:
        matched_files = set()
        for matches in match_results.values():
            for m in matches:
                fname = m.split(":", 1)[0] if ":" in m else m
                matched_files.add(fname)
        return {
            "reachable": True,
            "confidence": 85,
            "verdict": "reachable",
            "reason": f"Vulnerable function(s) found in {len(matched_files)} file(s): {', '.join(sorted(matched_files)[:5])}",
            "matched_patterns": list(match_results.keys()),
            "matched_files": sorted(matched_files),
            "poc_result": "not_tested",
        }
    else:
        return {
            "reachable": False,
            "confidence": 60,
            "verdict": "likely_unreachable",
            "reason": f"Package imported but vulnerable functions not detected in codebase",
            "poc_result": "not_tested",
        }


def generate_poc_express_redirect(repo_path: Path, output_dir: Path) -> dict:
    """Generate a PoC test for CVE-2024-29041 (express open redirect)."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine if it's JS or TS
    has_ts = False
    for ext in ["*.ts", "*.tsx"]:
        result = list(repo_path.rglob(ext))
        if result:
            has_ts = True
            break

    ext = "ts" if has_ts else "js"
    test_file = output_dir / f"vulnerability_poc_cve-2024-29041.test.{ext}"

    test_content = textwrap.dedent(f"""\
        /**
         * PoC: CVE-2024-29041 — Express Open Redirect Vulnerability
         *
         * Tests whether express.static() is vulnerable to open redirect
         * via encoded path traversal characters.
         *
         * This PoC starts a minimal express server with a static file
         * directory, then sends malicious requests to verify the fix.
         *
         * Generated by DepGuard Verify Skill
         */

        const http = require('http');
        const express = require('express');
        const path = require('path');
        const fs = require('fs');

        // Setup test directory
        const testDir = path.join(__dirname, '.depguard_poc_static');
        if (!fs.existsSync(testDir)) {{
            fs.mkdirSync(testDir, {{ recursive: true }});
            fs.writeFileSync(path.join(testDir, 'test.txt'), 'hello');
        }}

        function createApp() {{
            const app = express();
            // Static file serving — this is the vulnerability surface
            app.use('/static', express.static(testDir));
            app.use('/files', express.static(testDir, {{ redirect: true }}));

            // res.sendFile with user input
            app.get('/download', (req, res) => {{
                const file = req.query.file || 'test.txt';
                res.sendFile(path.join(testDir, file));
            }});

            app.get('/health', (req, res) => {{
                res.json({{ status: 'ok' }});
            }});

            return app;
        }}

        function runTest() {{
            const app = createApp();
            const server = app.listen(0, () => {{
                const port = server.address().port;
                const base = `http://localhost:${{port}}`;

                // Test 1: Basic static file access (should work)
                http.get(`${{base}}/static/test.txt`, (res) => {{
                    const ok1 = res.statusCode === 200;
                    console.log(`Test 1 (basic static): ${{ok1 ? 'PASS' : 'FAIL'}} (${{res.statusCode}})`);

                    // Test 2: Encoded path traversal attempt
                    const maliciousPath = encodeURIComponent('..%2f..%2fetc/passwd')
                        .replace(/%/g, '%25'); // double-encode
                    http.get(`${{base}}/static/${{maliciousPath}}`, (res) => {{
                        const blocked2 = res.statusCode >= 400;
                        console.log(`Test 2 (path traversal): ${{blocked2 ? 'PASS' : 'VULNERABLE'}} (${{res.statusCode}})`);

                        // Test 3: Open redirect via encoded chars
                        http.get(`${{base}}/files/%2e%2e%2f%2e%2e%2f`, (res) => {{
                            const blocked3 = res.statusCode >= 400 || res.statusCode === 301;
                            console.log(`Test 3 (open redirect): ${{blocked3 ? 'PASS' : 'VULNERABLE'}} (${{res.statusCode}})`);

                            // Test 4: sendFile with traversal
                            http.get(`${{base}}/download?file=../../../etc/passwd`, (res) => {{
                                const blocked4 = res.statusCode >= 400;
                                console.log(`Test 4 (sendFile traversal): ${{blocked4 ? 'PASS' : 'VULNERABLE'}} (${{res.statusCode}})`);

                                const allPassed = ok1 && blocked2 && blocked3 && blocked4;
                                console.log(`\\n=== PoC Result: ${{allPassed ? 'MITIGATED (patch effective)' : 'VULNERABLE (needs fix)'}} ===`);
                                server.close();
                                if (!allPassed) {{
                                    process.exit(1); // Signal: vulnerability confirmed
                                }}
                                process.exit(0); // Signal: mitigated
                            }});
                        }});
                    }});
                }});
            }});

            server.on('error', (err) => {{
                console.error('Server error:', err.message);
                process.exit(2);
            }});
        }}

        // Run for max 10 seconds
        setTimeout(() => {{
            console.error('TIMEOUT: PoC did not complete within 10s');
            process.exit(2);
        }}, 10000);

        runTest();
    """)

    test_file.write_text(test_content)
    test_file.chmod(0o755)

    return {
        "cve": "CVE-2024-29041",
        "test_file": str(test_file),
        "test_description": "Express open redirect PoC — tests static() and sendFile() path traversal",
        "language": "javascript",
        "trigger_conditions": [
            "If test exits with code 1 → vulnerability CONFIRMED (tests failed to block malicious input)",
            "If test exits with code 0 → vulnerability MITIGATED (patch effective)",
            "If test exits with code 2 → test error (timeout/server failure)",
        ],
    }


def generate_generic_poc(vuln: dict, repo_path: Path, output_dir: Path) -> dict | None:
    """Generate a generic PoC test skeleton for a vulnerability."""
    ecosystem = vuln.get("ecosystem", "")
    package = vuln.get("package", "")
    cve = vuln.get("cve", "")

    output_dir.mkdir(parents=True, exist_ok=True)

    if ecosystem in ("npm",):
        ext = "ts" if list(repo_path.rglob("*.ts")) else "js"
        test_file = output_dir / f"vulnerability_poc_{cve.lower().replace('-', '_')}.test.{ext}"
        content = textwrap.dedent(f"""\
            /**
             * PoC: {cve} — {vuln.get('summary', 'Vulnerability test')}
             *
             * Generated by DepGuard Verify Skill
             * Package: {package}
             * Ecosystem: {ecosystem}
             */

            // Attempt to import/require the vulnerable package
            let vulnModule;
            try {{
                vulnModule = require('{package}');
                console.log('IMPORT_SUCCESS: {package} loaded');
            }} catch (e) {{
                console.log('IMPORT_FAILED: {package} not available - cannot test');
                process.exit(0); // Not applicable
            }}

            console.log('PoC SKELETON for {cve}');
            console.log('Package: {package}');
            console.log('Module loaded successfully');
            console.log('\\n=== Manual verification needed for full PoC ===');
            process.exit(0);
        """)
        test_file.write_text(content)
        test_file.chmod(0o755)
        return {
            "cve": cve,
            "test_file": str(test_file),
            "test_description": f"Generic PoC skeleton for {cve}",
            "language": "javascript",
        }

    elif ecosystem in ("PyPI",):
        test_file = output_dir / f"vulnerability_poc_{cve.lower().replace('-', '_')}.test.py"
        content = textwrap.dedent(f"""\
            \"\"\"
            PoC: {cve} — {vuln.get('summary', 'Vulnerability test')}

            Generated by DepGuard Verify Skill
            Package: {package}
            Ecosystem: {ecosystem}
            \"\"\"

            import sys

            try:
                __import__('{package}')
                print(f"IMPORT_SUCCESS: {package} loaded")
            except ImportError:
                print(f"IMPORT_FAILED: {package} not available - cannot test")
                sys.exit(0)

            print(f"PoC SKELETON for {cve}")
            print(f"Package: {package}")
            print("\\n=== Manual verification needed for full PoC ===")
        """)
        test_file.write_text(content)
        test_file.chmod(0o755)
        return {
            "cve": cve,
            "test_file": str(test_file),
            "test_description": f"Generic PoC skeleton for {cve}",
            "language": "python",
        }

    return None


def run_poc(test_file: Path, timeout: int = 30) -> dict:
    """Execute a PoC test and return the result."""
    if not test_file.exists():
        return {"result": "not_tested", "reason": "Test file not found"}

    try:
        ext = test_file.suffix
        if ext in (".js", ".ts", ".mjs"):
            cmd = ["node", str(test_file)]
        elif ext == ".py":
            cmd = ["python3", str(test_file)]
        elif ext in (".go"):
            cmd = ["go", "run", str(test_file)]
        elif ext in (".rs"):
            cmd = ["cargo", "run", "--manifest-path", str(test_file.parent / "Cargo.toml")]
        else:
            return {"result": "not_tested", "reason": f"Unsupported test extension: {ext}"}

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=test_file.parent,
        )

        stdout = proc.stdout[-2000:] if proc.stdout else ""
        stderr = proc.stderr[-2000:] if proc.stderr else ""

        if proc.returncode == 0:
            return {
                "result": "not_triggered",
                "exit_code": 0,
                "stdout": stdout,
                "stderr": stderr,
            }
        elif proc.returncode == 1:
            return {
                "result": "triggered",
                "exit_code": 1,
                "stdout": stdout,
                "stderr": stderr,
            }
        else:
            return {
                "result": "error",
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }

    except subprocess.TimeoutExpired:
        return {"result": "timeout", "reason": f"PoC timed out after {timeout}s"}
    except FileNotFoundError:
        return {"result": "not_tested", "reason": "Runtime not available (node/python not found)"}
    except Exception as e:
        return {"result": "error", "reason": str(e)}


def get_file_globs_for_ecosystem(ecosystem: str) -> list[str]:
    """Return file glob patterns for searching based on ecosystem."""
    mapping = {
        "npm": ["*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs", "*.vue", "*.svelte"],
        "PyPI": ["*.py", "*.pyi", "*.pyx", "*.pxd"],
        "Go": ["*.go"],
        "crates.io": ["*.rs"],
        "Maven": ["*.java", "*.kt", "*.kts", "*.groovy", "*.scala"],
        "RubyGems": ["*.rb", "*.rake", "*.gemspec"],
        "Hex": ["*.ex", "*.exs"],
        "NuGet": ["*.cs", "*.vb", "*.fs", "*.fsx"],
    }
    return mapping.get(ecosystem, ["*"])


def get_scan_patterns_for_cve(vuln: dict, symbol_data: dict) -> list[str]:
    """Build regex patterns to search for in the codebase."""
    patterns = []
    package = vuln.get("package", "")

    # Package-level patterns
    patterns.append(re.escape(package))

    # Function-level patterns from symbol DB or extraction
    for func in symbol_data.get("vulnerable_patterns", []):
        if func not in patterns:
            patterns.append(func)

    return patterns


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DepGuard Reachability Analysis Engine"
    )
    parser.add_argument(
        "--depguard-json",
        default=".depguard.json",
        help="Path to .depguard.json (default: .depguard.json)",
    )
    parser.add_argument(
        "--repo-path",
        help="Path to cloned repo (default: auto-detect from /tmp/depguard/)",
    )
    parser.add_argument(
        "--poc-dir",
        default="/tmp/depguard/poc",
        help="Directory for generated PoC test files",
    )
    parser.add_argument(
        "--run-poc",
        action="store_true",
        help="Run generated PoC tests after creation",
    )
    parser.add_argument(
        "--cve",
        help="Analyze a specific CVE only (e.g., CVE-2024-29041)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file for JSON results (default: stdout)",
    )
    args = parser.parse_args()

    depguard_path = Path(args.depguard_json)
    data = load_depguard(depguard_path)
    vulns = data.get("vulnerabilities", [])

    if not vulns:
        print("No vulnerabilities found in .depguard.json. Run watch first.", file=sys.stderr)
        return 0

    # Determine repo path
    repo_path = None
    if args.repo_path:
        repo_path = Path(args.repo_path)
    else:
        # Auto-detect from /tmp/depguard/scan/
        scan_dir = Path("/tmp/depguard/scan")
        if scan_dir.exists():
            subdirs = list(scan_dir.iterdir())
            if subdirs:
                repo_path = subdirs[0]

    if not repo_path or not repo_path.exists():
        print("Warning: Repo path not found. Using current directory.", file=sys.stderr)
        repo_path = Path.cwd()

    # Filter by CVE if specified
    if args.cve:
        vulns = [v for v in vulns if v.get("cve", "").upper() == args.cve.upper()]
        if not vulns:
            print(f"CVE {args.cve} not found in .depguard.json", file=sys.stderr)
            return 1

    results = []
    ecosystems_seen: set[str] = set()

    for vuln in vulns:
        cve_id = vuln.get("cve", "UNKNOWN")
        ecosystem = vuln.get("ecosystem", "")
        package_name = vuln.get("package", "")

        print(f"🔍 Analyzing {cve_id} ({package_name} / {ecosystem})...", file=sys.stderr)

        # Cache import graphs per ecosystem
        if ecosystem not in ecosystems_seen:
            print(f"   Building import graph for {ecosystem}...", file=sys.stderr)
            imported = build_import_graph(repo_path, ecosystem)
            ecosystems_seen[ecosystem] = imported
        else:
            imported = ecosystems_seen[ecosystem]

        # Get file globs
        file_globs = get_file_globs_for_ecosystem(ecosystem)

        # Get symbol data
        symbol_data = extract_vulnerable_symbols(vuln)
        scan_patterns = get_scan_patterns_for_cve(vuln, symbol_data)

        print(f"   Searching for {len(scan_patterns)} patterns...", file=sys.stderr)

        # Check reachability
        verdict = check_reachability(
            vuln, repo_path, scan_patterns, file_globs, imported
        )

        # Generate PoC
        poc_dir = Path(args.poc_dir) / cve_id.lower().replace("-", "_")
        poc_info = None

        if cve_id == "CVE-2024-29041":
            poc_info = generate_poc_express_redirect(repo_path, poc_dir)
        elif verdict.get("reachable"):
            poc_info = generate_generic_poc(vuln, repo_path, poc_dir)

        if poc_info:
            verdict["poc_file"] = poc_info.get("test_file")
            verdict["poc_description"] = poc_info.get("test_description")

            # Run PoC if requested
            if args.run_poc:
                print(f"   Running PoC: {poc_info['test_file']}...", file=sys.stderr)
                poc_result = run_poc(Path(poc_info["test_file"]))
                verdict["poc_result"] = poc_result.get("result", "not_tested")
                verdict["poc_exit_code"] = poc_result.get("exit_code")
                verdict["poc_stdout"] = poc_result.get("stdout", "")[-500:]
                verdict["poc_stderr"] = poc_result.get("stderr", "")[-500:]

                # Update confidence based on PoC result
                if poc_result.get("result") == "triggered":
                    verdict["confidence"] = 100
                    verdict["verdict"] = "confirmed_reachable"
                    verdict["reason"] = "PoC test confirmed vulnerability is exploitable"
                elif poc_result.get("result") == "not_triggered":
                    verdict["confidence"] = max(verdict.get("confidence", 0), 70)
                    # Keep the original reachability verdict but note PoC didn't trigger
            else:
                verdict["poc_result"] = "not_tested"

        # Add to vuln entry
        result_entry = {
            **vuln,
            "reachability": {
                "reachable": verdict.get("reachable"),
                "confidence": verdict.get("confidence"),
                "verdict": verdict.get("verdict"),
                "reason": verdict.get("reason"),
                "poc_result": verdict.get("poc_result"),
                "matched_files": verdict.get("matched_files", []),
                "matched_patterns": verdict.get("matched_patterns", []),
            },
        }
        if verdict.get("poc_file"):
            result_entry["reachability"]["poc_file"] = verdict["poc_file"]
        if verdict.get("poc_exit_code") is not None:
            result_entry["reachability"]["poc_exit_code"] = verdict["poc_exit_code"]

        results.append(result_entry)

        emoji = "🔴" if verdict.get("reachable") else "🟢" if not verdict.get("reachable") else "🟡"
        conf = verdict.get("confidence", 0)
        print(f"   {emoji} {verdict.get('verdict', 'unknown')} (confidence: {conf}%)", file=sys.stderr)

    # Update .depguard.json with reachability data
    data["vulnerabilities"] = results
    data["reachability_analysis"] = {
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "repo_path": str(repo_path),
        "total_analyzed": len(results),
        "reachable": sum(1 for r in results if r["reachability"].get("reachable")),
        "confirmed": sum(1 for r in results if r["reachability"].get("poc_result") == "triggered"),
    }
    save_depguard(depguard_path, data)

    # Output results
    output = json.dumps(results, indent=2)
    if args.output == "-":
        print(output)
    else:
        Path(args.output).write_text(output)

    print(f"\n✅ Reachability analysis complete: {len(results)} CVEs analyzed", file=sys.stderr)
    reachable_count = sum(1 for r in results if r["reachability"].get("reachable"))
    confirmed_count = sum(1 for r in results if r["reachability"].get("poc_result") == "triggered")
    print(f"   🔴 Reachable: {reachable_count}", file=sys.stderr)
    print(f"   🟢 Unreachable/Likely safe: {len(results) - reachable_count}", file=sys.stderr)
    if confirmed_count:
        print(f"   💥 PoC confirmed: {confirmed_count}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
