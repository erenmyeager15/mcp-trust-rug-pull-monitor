# MCP Trust & Rug-Pull Monitor launch package

This directory contains reproducible public-task presets and proof assets for the
MCP Trust & Rug-Pull Monitor Actor.

The public presets are deliberately conservative:

- metadata-only inspection;
- explicit authorization attestation;
- no tool invocation;
- no private-network access;
- no webhook delivery;
- compare-only, dry-run baseline behavior;
- controlled public fixtures owned by the Actor developer.

## Public task presets

1. `mcp-tool-permission-drift-monitor.json`
2. `mcp-package-vulnerability-tls-audit.json`
3. `mcp-server-trust-baseline-check.json`

See `tasks/PUBLICATION-GUIDE.md` for the exact Store fields, views, and SEO copy.

## Verified proof assets

- `sample-output/mcp-tool-permission-drift-sample.json` summarizes cloud run
  `HdzVYlWPdhW3TCf5z`.
- `sample-output/mcp-package-vulnerability-tls-sample.json` summarizes cloud run
  `zCs82wX9dYZTlifhF`.
- `promotion/mcp-trust-proof.png` is the checked 1200x630 launch image.
- `promotion/PROMOTION-COPY.md` contains channel-specific launch copy.
