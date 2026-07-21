import { redactMetadataText, redactUrl } from './redaction.js';
import { trustedBaselineKey } from './baseline.js';
import { DEFAULT_MAX_RESPONSE_BYTES, MAX_HEADER_BYTES, MAX_SERVERS } from './constants.js';
import type { ActorInput, BaselineMode, JsonObject, ServerInput, Severity, TransportName } from './types.js';

const severities: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
const modes: BaselineMode[] = ['initialize_only', 'compare_only', 'compare_and_update', 'manual_approval'];
const transports: TransportName[] = ['auto', 'streamable_http', 'http_sse', 'static_json'];
const blockedKeys = new Set(['__proto__', 'prototype', 'constructor']);
const blockedRequestHeaders = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'upgrade', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer']);

function fail(message: string): never { throw new Error(`Invalid input: ${message}`); }
function object(value: unknown, label: string): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
    return value as Record<string, unknown>;
}
function string(value: unknown, label: string, max = 10_000): string {
    if (typeof value !== 'string' || !value.trim() || value.length > max) fail(`${label} must be a non-empty string up to ${max} characters`);
    return value.trim();
}
function bool(value: unknown, fallback: boolean, label: string): boolean {
    if (value === undefined) return fallback;
    if (typeof value !== 'boolean') fail(`${label} must be boolean`);
    return value;
}
function integer(value: unknown, fallback: number, label: string, min: number, max: number): number {
    if (value === undefined) return fallback;
    if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) fail(`${label} must be an integer between ${min} and ${max}`);
    return value as number;
}
function enumValue<T extends string>(value: unknown, fallback: T, allowed: readonly T[], label: string): T {
    if (value === undefined || value === '') return fallback;
    if (typeof value !== 'string' || !allowed.includes(value as T)) fail(`${label} must be one of: ${allowed.join(', ')}`);
    return value as T;
}

export function validateInput(raw: unknown, runtimeBaselineDefault: BaselineMode = 'compare_only'): ActorInput {
    const root = object(raw, 'input');
    if (root.authorizedUseConfirmed !== true) throw new Error('Authorization required: set authorizedUseConfirmed to true only for public metadata or systems you own or are explicitly authorized to inspect.');
    if (!Array.isArray(root.servers) || !root.servers.length) fail('servers must contain at least one enabled server');
    if (root.servers.length > MAX_SERVERS) fail(`servers may contain at most ${MAX_SERVERS} entries`);
    const allowHttp = bool(root.allowHttp, false, 'allowHttp');
    const allowPrivateNetwork = bool(root.allowPrivateNetwork, false, 'allowPrivateNetwork');
    if (allowPrivateNetwork) fail('allowPrivateNetwork is not supported in this hosted MVP; use only public Internet targets.');
    const servers = root.servers.map((entry, index) => validateServer(entry, index, allowHttp));
    const baselineKeys = new Set<string>();
    for (const server of servers.filter((entry) => entry.enabled !== false)) {
        const key = trustedBaselineKey(server.name, server.url);
        if (baselineKeys.has(key)) fail(`servers contains duplicate effective target ${redactMetadataText(server.name, 128)} at ${redactUrl(server.url)}`);
        baselineKeys.add(key);
    }
    const baselineMode = enumValue(root.baselineMode, runtimeBaselineDefault, modes, 'baselineMode');
    const dryRun = bool(root.dryRun, false, 'dryRun');
    const promoteCandidateBaseline = bool(root.promoteCandidateBaseline, false, 'promoteCandidateBaseline');
    const baselineKeyValueStoreId = root.baselineKeyValueStoreId === undefined || root.baselineKeyValueStoreId === ''
        ? undefined : string(root.baselineKeyValueStoreId, 'baselineKeyValueStoreId', 128);
    const baselineRequestQueueId = root.baselineRequestQueueId === undefined || root.baselineRequestQueueId === ''
        ? undefined : string(root.baselineRequestQueueId, 'baselineRequestQueueId', 128);
    if (Boolean(baselineKeyValueStoreId) !== Boolean(baselineRequestQueueId)) fail('baselineKeyValueStoreId and baselineRequestQueueId must be provided together');
    const mutationRequested = !dryRun && (baselineMode !== 'compare_only' || promoteCandidateBaseline);
    if (mutationRequested && (!baselineKeyValueStoreId || !baselineRequestQueueId)) {
        fail('persistent baseline Key-Value Store and Request Queue selections are required for non-dry-run baseline mutation');
    }
    return {
        servers,
        authorizedUseConfirmed: true,
        ...(baselineKeyValueStoreId ? { baselineKeyValueStoreId } : {}),
        ...(baselineRequestQueueId ? { baselineRequestQueueId } : {}),
        baselineMode,
        minimumAlertSeverity: enumValue(root.minimumAlertSeverity, 'medium', severities, 'minimumAlertSeverity'),
        webhookUrl: root.webhookUrl === undefined || root.webhookUrl === '' ? undefined : validateWebhook(root.webhookUrl),
        checkVulnerabilities: bool(root.checkVulnerabilities, true, 'checkVulnerabilities'),
        checkTls: bool(root.checkTls, true, 'checkTls'),
        includeRawNormalizedSnapshot: bool(root.includeRawNormalizedSnapshot, false, 'includeRawNormalizedSnapshot'),
        requestTimeoutSeconds: integer(root.requestTimeoutSeconds, 20, 'requestTimeoutSeconds', 1, 120),
        maxRetries: integer(root.maxRetries, 2, 'maxRetries', 0, 4),
        concurrency: integer(root.concurrency, 5, 'concurrency', 1, 10),
        dryRun,
        promoteCandidateBaseline,
        allowHttp,
        allowPrivateNetwork: false,
        maxResponseBytes: integer(root.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 'maxResponseBytes', 16_384, 5_242_880),
    };
}

function validateServer(raw: unknown, index: number, allowHttp: boolean): ServerInput {
    const value = object(raw, `servers[${index}]`);
    const urlString = string(value.url, `servers[${index}].url`);
    let url: URL;
    try { url = new URL(urlString); } catch { fail(`servers[${index}].url must be an absolute URL`); }
    if (!['https:', 'http:'].includes(url.protocol)) fail(`servers[${index}].url must use HTTPS${allowHttp ? ' or explicitly allowed HTTP' : ''}`);
    if (url.protocol === 'http:' && !allowHttp) fail(`servers[${index}].url uses HTTP; set allowHttp: true only when transport confidentiality is intentionally not required`);
    if (url.username || url.password) fail(`servers[${index}].url must not contain URL credentials`);
    if (url.hash) fail(`servers[${index}].url must not contain a fragment`);
    for (const key of url.searchParams.keys()) if (/auth|authorization|cookie|token|secret|api[-_]?key|password|credential|session|signature|^sig$|^key$/i.test(key)) fail(`servers[${index}].url must not contain credential-shaped query parameters; use secret headers instead`);
    const headers = validateHeaders(value.headers, index);
    const tags = value.tags === undefined ? [] : validateTags(value.tags, index);
    return {
        name: string(value.name, `servers[${index}].name`, 128),
        url: url.toString(),
        transport: enumValue(value.transport, 'auto', transports, `servers[${index}].transport`),
        headers,
        enabled: bool(value.enabled, true, `servers[${index}].enabled`),
        tags,
    };
}

function validateHeaders(raw: unknown, index: number): Record<string, string> {
    if (raw === undefined) return {};
    const value = object(raw, `servers[${index}].headers`);
    const headers: Record<string, string> = {};
    let total = 0;
    for (const [key, rawValue] of Object.entries(value)) {
        if (blockedKeys.has(key) || blockedRequestHeaders.has(key.toLowerCase()) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(key)) fail(`servers[${index}].headers contains an invalid or restricted header name`);
        const headerValue = string(rawValue, `servers[${index}].headers.${key}`, 4_096);
        if (/\r|\n/.test(headerValue)) fail(`servers[${index}].headers.${key} must not contain line breaks`);
        total += Buffer.byteLength(key) + Buffer.byteLength(headerValue);
        headers[key] = headerValue;
    }
    if (total > MAX_HEADER_BYTES) fail(`servers[${index}].headers exceeds ${MAX_HEADER_BYTES} bytes`);
    return headers;
}
function validateTags(raw: unknown, index: number): string[] {
    if (!Array.isArray(raw) || raw.length > 20) fail(`servers[${index}].tags must contain at most 20 strings`);
    return raw.map((value, tagIndex) => string(value, `servers[${index}].tags[${tagIndex}]`, 128));
}
function validateWebhook(raw: unknown): string {
    const value = string(raw, 'webhookUrl', 2_048);
    let url: URL;
    try { url = new URL(value); } catch { fail('webhookUrl must be an absolute HTTPS URL'); }
    if (url.protocol !== 'https:' || url.username || url.password) fail('webhookUrl must be an HTTPS URL without URL credentials');
    return url.toString();
}

export function safeInputSummary(input: ActorInput): JsonObject {
    return {
        servers: input.servers.map((server) => ({
            name: redactMetadataText(server.name, 128),
            url: redactUrl(new URL(server.url).origin),
            transport: server.transport,
            enabled: server.enabled,
            tags: server.tags?.map((tag) => redactMetadataText(tag, 128)),
        })),
        baselineMode: input.baselineMode,
        persistentBaselineStorageConfigured: Boolean(input.baselineKeyValueStoreId && input.baselineRequestQueueId),
    };
}
