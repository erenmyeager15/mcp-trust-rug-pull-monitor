# Changelog

## 1.0.4 - 2026-07-21
- Made baseline locking use the run-authorized default Request Queue so it works under limited Actor permissions.
- Removed completed synthetic lock requests instead of accumulating queue entries.
- Documented that recurring comparisons must pin both default KVS and Request Queue storage across runs.
- Added three controlled public task presets and proof fixtures for MCP trust, tool-risk, package, and TLS review.

## 1.0.1 - 2026-07-19
- Replaced the placeholder Store prefill with the public, no-secret MCP fixture.
- Made automated QA use compare-only dry-run settings without TLS, OSV, webhook, baseline, or PPE side effects.
- Kept normal API defaults conservative and authorization-gated.

## 1.0.0 — 2026-07-19
- Initial defensive MCP metadata monitoring MVP.
- Added public-only Streamable HTTP, legacy HTTP/SSE endpoint discovery, and static JSON manifest inspection.
- Added redacted trusted/candidate baseline storage, deterministic schema drift/risk analysis, OSV checks, TLS checks, webhook alerts, and PPE event accounting.
