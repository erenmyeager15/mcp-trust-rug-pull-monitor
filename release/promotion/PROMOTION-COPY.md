# Promotion copy

## LinkedIn

I built a defensive MCP server trust monitor for teams adopting AI-agent tools.

It inspects authorized public MCP metadata without invoking tools, then surfaces:

- new or suspicious tools and permission-like behavior;
- input/output schema and authentication drift;
- package vulnerability signals from OSV;
- TLS certificate problems;
- evidence, severity, risk score, and recommended action.

The public proof uses controlled fixtures and keeps private networks, tool execution,
and baseline mutation disabled.

Actor: https://apify.com/fascinating_lentil/mcp-trust-rug-pull-monitor

#MCP #AISecurity #AIEngineering #DevSecOps #Apify

## Apify Discord

I published three safe examples for my MCP Trust & Rug-Pull Monitor: tool and
permission drift, package/TLS auditing, and trusted-baseline checks. The Actor is
metadata-only and never invokes discovered tools. I would value feedback from
people building MCP integrations, especially on which trust signals matter before
approving a server update.

https://apify.com/fascinating_lentil/mcp-trust-rug-pull-monitor

## Reddit

Title: Which MCP server changes should block an update automatically?

Body:

I am testing a metadata-only MCP trust monitor that never invokes discovered tools.
It checks authorized public endpoints for tool/schema/authentication drift, suspicious
descriptions, package vulnerabilities, and TLS problems.

For teams using MCP servers, which changes should be an automatic block versus a
manual-review warning? Examples might include authentication removal, a new tool that
claims shell or environment access, required-input changes, or a vulnerable package.

I am looking for practical trust-policy feedback before expanding the workflow.

