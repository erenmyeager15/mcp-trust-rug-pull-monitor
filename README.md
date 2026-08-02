# MCP Server Security & Trust Monitor

Detect security-relevant changes in **authorized** MCP servers before accepting a new configuration as trusted. The Actor compares exposed discovery metadata with a trusted baseline and returns severity, a deterministic risk score, evidence, and a recommended action.

The public Actor runs with **Apify Limited Permissions**. It reads bounded discovery metadata only: it never invokes discovered tools, executes local processes, or accesses localhost or private-network targets. HTTPS is required by default, and DNS plus redirects are revalidated before access.

Use it to answer practical review questions:

- Did a server add tools or expand an existing tool's schema?
- Did tool descriptions, resources, prompts, or exposed capabilities change?
- Did an explicitly declared package version gain a known OSV advisory?
- Did the endpoint's TLS certificate or transport metadata change?
- Is the new state safe to review, or should it remain quarantined as a candidate?

Risky changes are never trusted automatically. New states remain reviewable candidates until explicitly promoted.

## Try a safe example

These public examples use controlled, non-secret fixtures and safe dry-run settings:

- [Establish an MCP server trust baseline](https://apify.com/fascinating_lentil/mcp-trust-rug-pull-monitor/examples/mcp-server-trust-baseline-check)
- [Monitor MCP tool and permission drift](https://apify.com/fascinating_lentil/mcp-trust-rug-pull-monitor/examples/mcp-tool-permission-drift-monitor)
- [Audit MCP package vulnerabilities and TLS](https://apify.com/fascinating_lentil/mcp-trust-rug-pull-monitor/examples/mcp-package-vulnerability-tls-audit)

Each enabled server produces one structured Dataset report. Current Store pricing starts at **$0.001 per completed server inspection**, plus **$0.0005 per generated risk report** and a **$0.00005 Actor start**. Baseline comparisons and completed OSV lookups are optional billed events at **$0.0005** and **$0.001** respectively. Failed or unpersisted inspections are not charged as completed reports.

> **Authorization and legal notice:** Set `authorizedUseConfirmed: true` only when every target intentionally exposes public metadata, belongs to you, or you have explicit permission to inspect it. You are responsible for applicable terms, law, and organizational policy. This Actor does not certify safety or detect every attack.

## Supported metadata transports and safety scope

- **Streamable HTTP:** bounded `initialize`, `tools/list`, `resources/list`, and `prompts/list` discovery only. Discovered tools are never called.
- **Static JSON:** bounded MCP manifests or exported discovery metadata.
- **Legacy HTTP/SSE:** recognized but returns `unsupported_transport` in this release because no bounded correlated streaming client is implemented.

The hosted Actor blocks localhost, loopback, RFC1918/private, link-local, cloud metadata, Unix socket, `file:`, and unsupported targets. HTTPS is required by default. Plain HTTP requires explicit `allowHttp: true`; private-network access remains unsupported. DNS and redirects are revalidated, cross-origin credential redirects are rejected, and response sizes, retries, request time, per-server wall time, and concurrency are bounded.

## Input and safe defaults

```json
{
  "authorizedUseConfirmed": true,
  "servers": [
    {
      "name": "production-mcp",
      "url": "https://mcp.example.com/mcp",
      "transport": "auto",
      "headers": { "Authorization": "Bearer <APIFY_SECRET_VALUE>" },
      "enabled": true,
      "tags": ["production", "customer-support"]
    }
  ],
  "baselineMode": "compare_only",
  "promoteCandidateBaseline": false,
  "minimumAlertSeverity": "medium",
  "checkVulnerabilities": true,
  "checkTls": true,
  "includeRawNormalizedSnapshot": false,
  "requestTimeoutSeconds": 20,
  "maxRetries": 2,
  "concurrency": 5,
  "dryRun": false,
  "allowHttp": false,
  "maxResponseBytes": 1048576
}
```

`compare_only` is the production and schema default: an omitted `baselineMode` never creates or updates a trusted baseline. For compatibility with the pinned schema validator, the input schema marks the complete `servers` JSON array as encrypted secret input, which covers every nested `headers` object and value. Put authorized credentials only in `headers`; never put real secrets in names, tags, target URLs, webhook URLs, examples, logs, or reports. Credential-shaped target query parameters and URL credentials are rejected. Metadata strings are redacted before logs, reports, webhooks, and baseline storage; inside JSON Schema `properties`/`patternProperties`, credential-shaped property names are preserved while value-bearing `default`, `const`, `examples`, and `enum` values are replaced before hashing, storage, Dataset output, evidence, or OSV processing.

Input limits match runtime validation:

- 1–25 server entries; enabled targets must have unique effective name/URL baseline keys.
- Server names: 1–128 characters. Tags: at most 20, each 1–128 characters.
- Header names: 1–128 valid header-token characters; values: 1–4096 characters without line breaks; combined names and values: at most 8192 bytes. Connection-routing and framing headers are rejected.
- Request timeout: 1–120 seconds; retries: 0–4; concurrency: 1–10.
- Metadata response limit: 16,384–5,242,880 bytes.
- Optional webhook: public HTTPS, at most 2048 characters, and no URL credentials.

### Baseline and candidate modes

- `compare_only` (**safe default**): compare with a compatible trusted baseline when present; never write trusted or candidate state.
- `initialize_only`: initialize a trusted baseline when none exists; otherwise compare without updating it.
- `compare_and_update`: initialize or update trusted state only after a successful complete classified inspection. High/critical initialization or drift is retained as a separate candidate instead of being trusted automatically.
- `manual_approval`: write a separate candidate and never overwrite trusted state.
- `promoteCandidateBaseline: true`: promote only a compatible stored candidate whose endpoint identity, current snapshot hash, and recorded trusted-parent hash (or explicit no-parent state) exactly match current state. Any missing, incompatible, endpoint/hash/parent mismatch returns structured `promotion_mismatch`, preserves both records, and never substitutes a new candidate. A valid attempt durably marks its exact target before updating trusted state, so retry can safely finish candidate consumption if deletion was interrupted after the trusted write. Successful promotion consumes the candidate.
- `dryRun: true`: disable all trusted, candidate, and promotion writes regardless of mode.
- `baselineKeyValueStoreId` + `baselineRequestQueueId`: optional persistent stores selected through Apify resource pickers. Both are required for any non-dry-run initialization, update, candidate write, or promotion. Reuse the same two stores across task or scheduled runs.

Unreachable, malformed, timed-out, unauthenticated, empty, incomplete, incompatible, unclassified, or lease-conflicted inspections never replace trusted state.

## Reports, persistence, and alerting

Each enabled server produces one redacted Dataset `Report` containing status, reachability, concrete transport, baseline and snapshot hashes, severity, 0–100 risk score, classified changes, OSV outcomes, TLS metadata, recommendations, baseline/candidate flags, timestamps, bounded inspection metadata, and structured errors. `includeRawNormalizedSnapshot` adds the redacted canonical snapshot only when explicitly enabled.

The Actor persists the Dataset report first with `persistence.succeeded: true`. Only after that write succeeds can it deliver the optional webhook and attempt pay-per-event charges. Dataset, webhook, PPE, and finalizer waits are bounded by the same per-server deadline. If Dataset persistence fails or reaches that deadline, webhook delivery and PPE charging are suppressed for that report; the timed-out promise is rejection-safe but is not treated as durable success even if its provider later settles. Because webhook and PPE outcomes occur after the Dataset write, those late runtime fields are normally visible in logs rather than the already persisted item. Webhook or charging failure does not rewrite or invalidate a durable report.

Trusted and candidate snapshots are stored as versioned records in the default Key-Value Store only when the selected mode permits writes. Baseline mutation also uses the run's default Request Queue for atomic ownership. For scheduled or task-based monitoring, pin both the default Key-Value Store and default Request Queue across runs; otherwise each run receives fresh state and cannot compare with an earlier baseline. Candidates carry their exact trusted-parent hash (or explicit no-parent state), and successful promotion deletes the consumed candidate.

Every trusted/candidate set or delete requires verified ownership of an atomic lock in the run's authorized default Apify Request Queue. The queue temporarily contains one synthetic unique-key request per active baseline mutation with owner/expiry metadata; successful release removes that request, and the Actor never fetches its synthetic `.invalid` URL. Native lock expiry is longer than the maximum per-server mutation window, ownership is heartbeated while an overdue KVS mutation settles, and platform KVS mutation calls use a shorter non-retrying timeout. Expiry permits safe stale-owner takeover after a terminated run. If the queue API or ownership verification is unavailable, mutating modes fail closed; ordinary `compare_only` reads remain bounded, side-effect-free KVS reads. KVS records alone cannot provide cross-run atomicity, so deployments that cannot access the run's default Apify Request Queue cannot mutate baseline state.

A public HTTPS webhook is eligible only when the report meets `minimumAlertSeverity` and its status is alertable. Changed comparisons and relevant failures can alert; candidate initialization alerts only at high/critical severity, and trusted initialization alerts only at critical severity. Payloads are compact and redacted, delivery is bounded, and failures do not alter monitoring results.

## Vulnerability, TLS, and risk interpretation

When metadata explicitly contains an unambiguous package name, version, and ecosystem, the Actor can query the public OSV API. It does not infer package identity or treat a match as proof of exploitability. Unavailable lookups are represented as unavailable rather than fabricated findings. Optional TLS inspection reports certificate validity, hostname issues, expiry within 30 days, and protocol metadata.

Changes include a stable ID, category, entity, JSON path where applicable, redacted values, deterministic severity and score contribution, rule ID, explanation, evidence, confidence, and recommended action. The rule-based score is not an LLM judgment. This remains a change monitor with possible false positives and false negatives; review medium, high, and critical results before action.

## Verified Sample Output

The following compact report came from the controlled Northstar MCP package-risk proof. Values such as package, severity, risk score, and vulnerability counts are stored in the full Dataset report.

```json
{
  "serverName": "Northstar MCP package-risk proof",
  "status": "baseline_missing",
  "reachable": true,
  "transport": "static_json",
  "overallSeverity": "critical",
  "riskScore": 100,
  "package": "lodash@4.17.20",
  "vulnerabilityCount": 5,
  "vulnerabilitiesBySeverity": {
    "high": 2,
    "medium": 3
  },
  "tlsAuthorized": true,
  "recommendedAction": "Review the OSV advisories and update, mitigate, or remove the affected package."
}
```

## License

Apache-2.0. See [LICENSE](LICENSE).
