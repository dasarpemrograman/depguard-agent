# GitHub Advisory Database — GraphQL API

## Query Template
```graphql
query($package: String!, $eco: SecurityAdvisoryEcosystem!, $cursor: String) {
  securityVulnerabilities(
    first: 100
    after: $cursor
    ecosystem: $eco
    package: $package
  ) {
    nodes {
      severity
      advisory {
        summary
        description
        identifiers { type value }
        publishedAt
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

## Execute via gh CLI
```bash
gh api graphql \
  -f query="$(cat query.graphql)" \
  -f package="express" \
  -f eco="NPM"
```

Repeat with `-f cursor="$endCursor"` while `pageInfo.hasNextPage` is true.

## Ecosystem values
| Value | Package Manager |
|-------|----------------|
| NPM | npm |
| PIP | pip/PyPI |
| GO | Go modules |
| RUST | Cargo/crates.io |
| MAVEN | Java/Maven |
| RUBYGEMS | Ruby gems |
| COMPOSER | PHP/Composer |

## Rate Limits
- Authenticated via `gh`: 5,000 points/hour
- GraphQL queries cost 1 point each
- Response includes `rateLimit { remaining resetAt }`

## Extracting Patched Version
- `firstPatchedVersion.identifier` — the version that fixes the vulnerability
- `vulnerableVersionRange` — semver range that is vulnerable (e.g., "< 4.19.2")
- If `firstPatchedVersion` is null, no fix exists yet

## Fallback
If GitHub Advisory returns empty for a package, fall back to OSV.dev.
OSV has broader coverage for obscure packages.
