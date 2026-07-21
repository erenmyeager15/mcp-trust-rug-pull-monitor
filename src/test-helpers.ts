import { validateInput } from './input.js';
import { normalizeSnapshot } from './normalize.js';
import type { ActorInput, InspectionResult, JsonObject, NormalizedSnapshot, ServerInput, TlsMetadata, VulnerabilityMatch } from './types.js';
import type { VulnerabilityProvider } from './vulnerability.js';

export const TEST_URL = 'https://mcp.example.com/mcp';
export function input(overrides: Partial<ActorInput> = {}): ActorInput {
    const result = validateInput({ authorizedUseConfirmed: true, servers: [{ name: 'fixture-mcp', url: TEST_URL, transport: 'static_json', enabled: true }], baselineKeyValueStoreId: 'fixture-kvs', baselineRequestQueueId: 'fixture-rq', baselineMode: 'compare_and_update', checkTls: false, checkVulnerabilities: false, ...overrides });
    return result;
}
export function server(): ServerInput { return input().servers[0] as ServerInput; }
export function snapshot(overrides: { tools?: unknown; capabilities?: unknown; authentication?: unknown; resources?: unknown; prompts?: unknown; packages?: unknown; version?: unknown; protocolVersion?: unknown; tls?: TlsMetadata } = {}): NormalizedSnapshot {
    return normalizeSnapshot({
        server: { name: 'fixture-mcp', origin: TEST_URL, identity: 'fixture-mcp', version: overrides.version ?? '1.0.0', protocolVersion: overrides.protocolVersion ?? '2024-11-05', capabilities: overrides.capabilities ?? ['tools'], authentication: overrides.authentication ?? { required: true, schemes: ['bearer'] }, contentType: 'application/json' },
        tools: overrides.tools ?? [{ name: 'lookup_customer', description: 'Look up a customer by identifier.', inputSchema: { type: 'object', properties: { customerId: { type: 'string', minLength: 1 } }, required: ['customerId'] }, outputSchema: { type: 'object', properties: { name: { type: 'string' } } } }],
        resources: overrides.resources ?? [], prompts: overrides.prompts ?? [], packages: overrides.packages ?? [], ...(overrides.tls ? { tls: overrides.tls } : {}),
    });
}
export function success(current: NormalizedSnapshot, extras: Partial<Extract<InspectionResult, { ok: true }>> = {}): Extract<InspectionResult, { ok: true }> {
    return { ok: true, transport: 'static_json', snapshot: current, responseStatus: 200, responseContentType: 'application/json', latencyMs: 10, redirectOrigins: [], ...extras };
}
export function failure(status: Exclude<Extract<InspectionResult, { ok: false }>['status'], never>, message = status): Extract<InspectionResult, { ok: false }> { return { ok: false, status, message, transport: 'static_json' }; }
export function staticVulnerabilities(matches: VulnerabilityMatch[], completed = matches.some((entry) => !entry.unavailable) ? 1 : 0): VulnerabilityProvider { return { async lookup() { return { matches, attempted: 1, completed }; } }; }
export function object(value: Record<string, unknown>): JsonObject { return value as unknown as JsonObject; }
