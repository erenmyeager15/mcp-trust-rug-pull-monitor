# Public task publication guide

Create the tasks from the JSON files in this directory, verify their cloud runs,
then publish each task manually from its **Publication** tab in Apify Console.

## Shared safety settings

- All targets are owner-controlled public fixtures.
- `authorizedUseConfirmed` is true for those fixtures only.
- `baselineMode` is `compare_only`.
- `dryRun` is true.
- No webhook URL or secret header is present.
- Private-network and plain-HTTP access remain disabled.

## 1. MCP Tool & Permission Drift Monitor

- Slug: `mcp-tool-permission-drift-monitor`
- SEO title: `Detect MCP Tool and Permission Drift`
- SEO description: `Inspect authorized public MCP metadata for risky tool, schema, authentication, and permission changes without invoking any discovered tool.`
- Public input fields: `servers`, `authorizedUseConfirmed`, `baselineMode`, `checkTls`, `minimumAlertSeverity`
- Dataset view: `securityReview`

## 2. MCP Package Vulnerability & TLS Audit

- Slug: `mcp-package-vulnerability-tls-audit`
- SEO title: `Audit MCP Packages, Vulnerabilities and TLS`
- SEO description: `Check authorized public MCP metadata for exposed package vulnerabilities and TLS problems, with evidence, severity, and recommended actions.`
- Public input fields: `servers`, `authorizedUseConfirmed`, `checkVulnerabilities`, `checkTls`, `minimumAlertSeverity`
- Dataset view: `securityReview`

## 3. MCP Server Trust Baseline Check

- Slug: `mcp-server-trust-baseline-check`
- SEO title: `Check an MCP Server Against a Trusted Baseline`
- SEO description: `Compare authorized public MCP metadata with a trusted baseline and surface security-relevant drift, risk scores, and review actions.`
- Public input fields: `servers`, `authorizedUseConfirmed`, `baselineMode`, `checkTls`, `minimumAlertSeverity`
- Dataset view: `overview`

## Publication verification

After publishing, confirm that each task:

1. opens without being logged into the owner account;
2. shows the intended title and SEO description;
3. exposes only the listed input fields;
4. uses the intended Dataset view;
5. retains `compare_only`, `dryRun`, no webhook, and blocked private-network defaults.

