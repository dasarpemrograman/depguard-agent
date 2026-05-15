# OSV.dev API Reference

Base URL: `https://api.osv.dev/v1`

## Query Vulnerabilities
```
POST /v1/query
Content-Type: application/json

{
  "package": {"name": "express", "ecosystem": "npm"},
  "version": "4.18.2"
}
```

CLI helper:
```bash
depguard-osv-query --ecosystem PyPI --package jinja2 --version 2.4.1
```

## Response
```json
{
  "vulns": [{
    "id": "CVE-2024-29041",
    "summary": "Open redirect in express.static()",
    "details": "Express.js versions before 4.19.2...",
    "modified": "2024-06-15T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    "affected": [{
      "ranges": [{
        "type": "SEMVER",
        "events": [
          {"introduced": "0"},
          {"fixed": "4.19.2"}
        ]
      }]
    }]
  }]
}
```

## Ecosystems
| Value | Package Manager |
|-------|----------------|
| npm | Node.js / npm |
| PyPI | Python / pip |
| Go | Go modules |
| crates.io | Rust / Cargo |
| Maven | Java / Maven |
| NuGet | .NET / NuGet |
| RubyGems | Ruby / gem |

## Rate Limits
- 50 requests/minute (unauthenticated)
- Space requests by 1.5 seconds minimum

## Extracting Fixed Version
Look for `affected[].ranges[].events[]` where `fixed` exists.
Take the earliest fixed version across all ranges.
