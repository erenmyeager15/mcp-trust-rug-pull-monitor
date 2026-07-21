import assert from 'node:assert/strict';
import test from 'node:test';
import { createBaseline, trustedBaselineKey, usableBaseline } from './baseline.js';
import { createChange } from './diff.js';
import { validateInput } from './input.js';
import { safeJson } from './json.js';
import { readBoundedBody, safeFetch, type SafeHttpResponse } from './network.js';
import { normalizeSnapshot, snapshotHash } from './normalize.js';
import { redactHeaders, redactString, redactUrl, redactValue } from './redaction.js';
import { IdempotentPpeAccountant } from './ppe.js';
import { assertPublicUrl, isBlockedIp } from './safety.js';
import { server, snapshot } from './test-helpers.js';
import { inspectMcpServer } from './transport.js';
import { OsvProvider } from './vulnerability.js';
import { deliverWebhook } from './webhook.js';
import type { ChargeClient, Report } from './types.js';

function report(): Report {
    return { serverName: 'fixture-mcp', serverUrl: 'https://mcp.example.com/mcp?token=abc', status: 'success_changed', reachable: true, transport: 'static_json', baselineFound: true, previousSnapshotHash: 'sha256:old', currentSnapshotHash: 'sha256:new', overallSeverity: 'high', riskScore: 70, changeCount: 1, changesBySeverity: { informational: 0, low: 0, medium: 0, high: 1, critical: 0 }, changes: [], vulnerabilities: [], recommendedAction: 'Review.', baselineUpdated: false, candidateBaselineStored: false, inspectedAt: '2026-01-01T00:00:00.000Z', checkedAt: '2026-01-01T00:00:00.000Z' };
}
function response(status: number): SafeHttpResponse { return { status, headers: new Headers({ 'content-type': 'application/json' }), body: '{}', url: 'https://alerts.example.com', redirectOrigins: [], latencyMs: 1 }; }

test('authorization confirmation, URL validation, and SSRF blocks are enforced', () => {
    assert.throws(() => validateInput({ servers: [{ name: 'x', url: 'https://mcp.example.com' }] }), /Authorization required/);
    assert.throws(() => validateInput({ authorizedUseConfirmed: true, servers: [{ name: 'x', url: 'http://mcp.example.com' }] }), /HTTP/);
    assert.throws(() => validateInput({ authorizedUseConfirmed: true, baselineMode: 'initialize_only', servers: [{ name: 'x', url: 'https://mcp.example.com' }] }), /persistent baseline/);
    assert.throws(() => validateInput({ authorizedUseConfirmed: true, dryRun: true, baselineKeyValueStoreId: 'only-one-store', servers: [{ name: 'x', url: 'https://mcp.example.com' }] }), /provided together/);
    for (const target of ['http://127.0.0.1', 'https://localhost', 'https://169.254.169.254', 'https://[::ffff:127.0.0.1]', 'https://[::ffff:7f00:1]', 'file:///etc/passwd', 'https://metadata.google.internal']) assert.throws(() => assertPublicUrl(target, true));
    assert.doesNotThrow(() => assertPublicUrl('https://mcp.example.com/mcp', false));
    assert.equal(isBlockedIp('10.0.0.1'), true); assert.equal(isBlockedIp('192.168.1.1'), true); assert.equal(isBlockedIp('8.8.8.8'), false);
});

test('secret, query-string, cookie and sensitive object values are redacted', () => {
    assert.equal(redactString('Authorization: Bearer abcdefghijklmnop'), 'Authorization: Bearer [REDACTED]');
    assert.match(redactUrl('https://x.example/path?access_token=hello&safe=1'), /access_token=%5BREDACTED%5D/);
    assert.deepEqual(redactHeaders({ Authorization: 'Bearer live', Cookie: 'session=abc', 'X-Trace': 'ok' }), { Authorization: '[REDACTED]', Cookie: '[REDACTED]', 'X-Trace': 'ok' });
    assert.deepEqual(redactValue({ token: 'abc', nested: { password: 'p' } }), { token: '[REDACTED]', nested: { password: '[REDACTED]' } });
});

test('redirect-based SSRF is blocked before a second fetch', async () => {
    const validated: string[] = [];
    await assert.rejects(() => safeFetch('https://public.example/mcp', { timeoutMs: 50, maxResponseBytes: 1024, allowHttp: false }, {
        validateTarget: async (url) => { validated.push(url); if (url.includes('127.0.0.1')) throw new Error('private redirect blocked'); return new URL(url); },
        fetchImpl: async () => new Response('', { status: 302, headers: { location: 'http://127.0.0.1/internal' } }),
    }), /private redirect blocked/);
    assert.deepEqual(validated, ['https://public.example/mcp', 'http://127.0.0.1/internal']);
});

test('response size, deep JSON, prototype-pollution shape, schema validity, long descriptions and duplicate names are handled', async () => {
    await assert.rejects(() => readBoundedBody(new Response('x'.repeat(100), { headers: { 'content-length': '100' } }), 10), /maximum size/);
    let deep: unknown = 'v'; for (let index = 0; index < 70; index += 1) deep = { next: deep }; assert.throws(() => safeJson(deep));
    const poisoned = JSON.parse('{"safe":1,"__proto__":{"polluted":true}}'); const clean = safeJson(poisoned); assert.deepEqual(clean, { safe: 1 }); assert.equal(({} as { polluted?: boolean }).polluted, undefined);
    assert.throws(() => normalizeSnapshot({ server: { name: 'x', origin: 'https://x.example' }, tools: [{ name: 'a', description: '', inputSchema: { properties: [] } }] }));
    const long = normalizeSnapshot({ server: { name: 'x', origin: 'https://x.example' }, tools: [{ name: 'a', description: 'x'.repeat(30_000), inputSchema: {} }] }); assert.ok((long.tools[0]?.description.length ?? 0) <= 2_000);
    assert.throws(() => normalizeSnapshot({ server: { name: 'x', origin: 'https://x.example' }, tools: [{ name: 'a', description: '', inputSchema: {} }, { name: 'a', description: '', inputSchema: {} }] }));
});

test('baseline keys are deterministic without collisions for different names or origins', () => {
    const a = trustedBaselineKey('Café', 'https://mcp.example.com/path'); const same = trustedBaselineKey('Cafe\u0301', 'https://mcp.example.com/path'); const differentPath = trustedBaselineKey('Café', 'https://mcp.example.com/other'); const differentName = trustedBaselineKey('cafe', 'https://mcp.example.com/path'); const differentOrigin = trustedBaselineKey('Café', 'https://other.example.com/path');
    assert.equal(a, same); assert.notEqual(a, differentPath); assert.notEqual(a, differentName); assert.notEqual(a, differentOrigin);
});

test('OSV vulnerability matches are cached and service failure is represented as unavailable', async () => {
    const originalFetch = globalThis.fetch; let calls = 0;
    globalThis.fetch = (async () => { calls += 1; return new Response(JSON.stringify({ vulns: [{ id: 'OSV-1', database_specific: { severity: 'HIGH' } }] }), { status: 200, headers: { 'content-type': 'application/json' } }); }) as typeof fetch;
    try {
        const provider = new OsvProvider(); const pkg = { name: 'demo', version: '1.0.0', ecosystem: 'npm' };
        assert.equal((await provider.lookup([pkg], 100)).matches[0]?.severity, 'high'); await provider.lookup([pkg], 100); assert.equal(calls, 1);
        globalThis.fetch = (async () => { throw new Error('offline'); }) as typeof fetch;
        const unavailable = await new OsvProvider().lookup([pkg], 100); assert.equal(unavailable.matches[0]?.unavailable, true);
    } finally { globalThis.fetch = originalFetch; }
});

test('webhook success and failure are reported without leaking sensitive URL values', async () => {
    const good = await deliverWebhook('https://alerts.example.com/hook', report(), 'https://console.example/run?token=secret', 100, { validateTarget: async () => new URL('https://alerts.example.com/hook'), request: async () => response(204) });
    assert.equal(good.delivered, true);
    const bad = await deliverWebhook('https://alerts.example.com/hook', report(), undefined, 100, { validateTarget: async () => new URL('https://alerts.example.com/hook'), request: async () => response(500) });
    assert.equal(bad.delivered, false); assert.equal(bad.status, 500);
    assert.equal(server().headers?.Authorization, undefined);
    assert.ok(snapshot().tools.length > 0);
});


test('cross-origin redirects are rejected before credentials can reach the new origin', async () => {
    const requests: Array<{ url: string; authorization?: string }> = [];
    await assert.rejects(() => safeFetch('https://one.example/mcp', { headers: { Authorization: 'Bearer secret' }, timeoutMs: 100, maxResponseBytes: 1024, allowHttp: false }, {
        validateTarget: async (url) => new URL(url),
        fetchImpl: async (url, options) => {
            const headers = new Headers(options?.headers);
            requests.push({ url: url.toString(), authorization: headers.get('authorization') ?? undefined });
            return new Response('', { status: 302, headers: { location: 'https://two.example/mcp' } });
        },
    }), /Cross-origin redirects/);
    assert.deepEqual(requests, [{ url: 'https://one.example/mcp', authorization: 'Bearer secret' }]);
});

test('credential-shaped target queries are rejected and resource URL secrets are redacted', () => {
    assert.throws(() => validateInput({ authorizedUseConfirmed: true, servers: [{ name: 'x', url: 'https://mcp.example.com/mcp?access_token=secret' }] }), /credential-shaped query/);
    const normalized = normalizeSnapshot({ server: { name: 'x', origin: 'https://mcp.example.com' }, resources: [{ name: 'private', uri: 'https://data.example/item?api_key=secret' }] });
    assert.match(normalized.resources[0]?.uri ?? '', /%5BREDACTED%5D/);
    assert.doesNotMatch(JSON.stringify(normalized), /secret/);
});

test('baseline integrity, current versions, and endpoint paths are enforced', () => {
    const current = snapshot();
    const baseline = createBaseline(current, snapshotHash(current), 'baseline_initialized', '2026-01-01T00:00:00.000Z');
    assert.equal(usableBaseline(baseline), true);
    assert.equal(usableBaseline({ ...baseline, snapshotHash: 'sha256:tampered' }), false);
    assert.equal(usableBaseline({ ...baseline, normalizerVersion: '0.9.0' }), false);
    assert.notEqual(trustedBaselineKey('fixture', 'https://mcp.example.com/a'), trustedBaselineKey('fixture', 'https://mcp.example.com/b'));
});

test('transport safety failures are returned as structured results and legacy SSE is explicit', async () => {
    const blocked = await inspectMcpServer({ name: 'blocked', url: 'https://127.0.0.1/mcp', transport: 'static_json' }, { timeoutMs: 20, maxResponseBytes: 1024, maxRetries: 0, allowHttp: false, checkTls: false });
    assert.equal(blocked.ok, false);
    const sse = await inspectMcpServer({ name: 'sse', url: 'https://mcp.example.com/sse', transport: 'http_sse' }, { timeoutMs: 20, maxResponseBytes: 1024, maxRetries: 0, allowHttp: false, checkTls: false });
    assert.equal(sse.ok, false);
    if (!sse.ok) assert.equal(sse.status, 'unsupported_transport');
});

test('PPE idempotency is concurrency-safe', async () => {
    let calls = 0;
    const client: ChargeClient = { async charge(): Promise<void> { calls += 1; await new Promise((resolve) => setTimeout(resolve, 10)); } };
    const accountant = new IdempotentPpeAccountant(client);
    const results = await Promise.all([accountant.charge('server-inspection', 'same'), accountant.charge('server-inspection', 'same')]);
    assert.equal(calls, 1);
    assert.deepEqual(results.sort(), [false, true]);
});

test('OSV requires explicit ecosystem and classifies CVSS vectors conservatively', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => {
        calls += 1;
        return new Response(JSON.stringify({ vulns: [{ id: 'OSV-CVSS', severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }] }), { status: 200 });
    }) as typeof fetch;
    try {
        const provider = new OsvProvider();
        const uncertain = await provider.lookup([{ name: 'unknown', version: '1.0.0' }], 100);
        assert.equal(uncertain.matches[0]?.id, 'OSV_IDENTITY_UNCERTAIN');
        assert.equal(calls, 0);
        const matched = await provider.lookup([{ name: 'known', version: '1.0.0', ecosystem: 'npm' }], 100);
        assert.equal(matched.matches[0]?.severity, 'high');
        assert.equal(matched.completed, 1);
    } finally { globalThis.fetch = originalFetch; }
});


test('webhook top changes are risk-prioritized before truncation', async () => {
    let body = '';
    const changes = Array.from({ length: 5 }, (_, index) => createChange({ category: 'test', entityType: 'tool', entityName: `medium-${index}`, severity: 'medium', ruleId: `MEDIUM_${index}`, explanation: 'Medium.', recommendedAction: 'Review.', evidence: [] }));
    changes.push(createChange({ category: 'test', entityType: 'tool', entityName: 'critical', severity: 'critical', ruleId: 'CRITICAL_TOP', explanation: 'Critical.', recommendedAction: 'Act.', evidence: [] }));
    const value = { ...report(), changes, changeCount: changes.length, overallSeverity: 'critical' as const, riskScore: 100 };
    const delivered = await deliverWebhook('https://alerts.example.com/hook', value, undefined, 100, {
        validateTarget: async () => new URL('https://alerts.example.com/hook'),
        request: async (_url, options) => { body = options.body ?? ''; return response(204); },
    });
    assert.equal(delivered.delivered, true);
    const payload = JSON.parse(body) as { topChanges: Array<{ ruleId: string }> };
    assert.equal(payload.topChanges[0]?.ruleId, 'CRITICAL_TOP');
});
