import { MAX_MCP_COLLECTION_ITEMS, MAX_MCP_COLLECTION_PAGES, MAX_MCP_REQUESTS_PER_SERVER, MAX_SERVER_WALL_CLOCK_MS } from './constants.js';
import { normalizeSnapshot, type DiscoveredMetadata } from './normalize.js';
import { safeFetch } from './network.js';
import type { InspectionFailure, InspectionResult, JsonObject, JsonValue, ServerInput, TransportName } from './types.js';

interface InspectOptions { timeoutMs: number; maxResponseBytes: number; maxRetries: number; allowHttp: boolean; checkTls: boolean; tls?: import('./types.js').TlsMetadata; deadlineAt?: number; }
interface InspectContext { deadlineAt: number; requests: number; }
interface RpcResult { result: JsonObject; headers: Record<string, string>; status: number; contentType: string; latencyMs: number; redirectOrigins: string[]; }
interface CollectionResult { items: JsonValue[]; latencyMs: number; redirectOrigins: string[]; }
interface StatusError extends Error { status: InspectionFailure['status']; httpStatus?: number; latencyMs?: number; responseContentType?: string; redirectOrigins?: string[]; responseReceived?: boolean; }

export async function inspectMcpServer(server: ServerInput, options: InspectOptions): Promise<InspectionResult> {
    const derivedDeadline = Date.now() + Math.min(MAX_SERVER_WALL_CLOCK_MS, Math.max(options.timeoutMs, options.timeoutMs * 3));
    const context: InspectContext = { deadlineAt: Math.min(options.deadlineAt ?? derivedDeadline, derivedDeadline), requests: 0 };
    const transportOrder: TransportName[] = server.transport === 'auto' ? ['streamable_http', 'http_sse', 'static_json'] : [server.transport ?? 'auto'];
    let lastFailure: InspectionFailure | undefined;
    for (const transport of transportOrder) {
        if (remainingMs(context) <= 0) return fail('timeout', 'Per-server inspection deadline exceeded.', transport);
        const result = await retry(() => inspectWithTransport(server, transport, options, context), options.maxRetries, context);
        if (result.ok || server.transport !== 'auto' || ['authentication_failed', 'rate_limited', 'timeout', 'inspection_incomplete'].includes(result.status)) return result;
        lastFailure = result;
    }
    return lastFailure ?? fail('unsupported_transport', 'No supported MCP metadata transport could be inspected.');
}

async function retry(operation: () => Promise<InspectionResult>, attempts: number, context: InspectContext): Promise<InspectionResult> {
    let result = await operation();
    for (let index = 0; index < attempts && !result.ok && ['unreachable', 'timeout', 'rate_limited'].includes(result.status); index += 1) {
        const delayMs = 150 * (index + 1);
        if (remainingMs(context) <= delayMs) return fail('timeout', 'Per-server inspection deadline exceeded before retry.', result.transport, result.httpStatus, result.latencyMs, result.responseContentType, result.redirectOrigins, result.responseReceived);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        if (remainingMs(context) <= 0) return fail('timeout', 'Per-server inspection deadline exceeded before retry.', result.transport, result.httpStatus, result.latencyMs, result.responseContentType, result.redirectOrigins, result.responseReceived);
        result = await operation();
    }
    return result;
}

async function inspectWithTransport(server: ServerInput, transport: TransportName, options: InspectOptions, context: InspectContext): Promise<InspectionResult> {
    try {
        if (transport === 'streamable_http') return await inspectStreamableHttp(server, options, context);
        if (transport === 'http_sse') return fail('unsupported_transport', 'Legacy standalone HTTP/SSE requires a correlated long-lived event channel and is not supported.', 'http_sse');
        if (transport === 'static_json') return await inspectStaticJson(server, options, context);
        return fail('unsupported_transport', `Unsupported transport: ${transport}`);
    } catch (error) { return classifyError(error, transport); }
}

async function inspectStreamableHttp(server: ServerInput, options: InspectOptions, context: InspectContext): Promise<InspectionResult> {
    const initialize = await rpc(server.url, server.headers ?? {}, 'initialize', {
        protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'mcp-trust-rug-pull-monitor', version: '1.0.0' },
    }, options, context);
    const protocolVersion = stringValue(initialize.result.protocolVersion ?? initialize.result.protocol_version) ?? '2024-11-05';
    const sessionHeaders = { ...(server.headers ?? {}), ...initialize.headers, 'MCP-Protocol-Version': protocolVersion };
    await notifyInitialized(server.url, sessionHeaders, options, context);
    const capabilities = asObject(initialize.result.capabilities);
    const collections: Record<string, CollectionResult> = {};
    if (Object.hasOwn(capabilities, 'tools')) collections.tools = await listCollection(server.url, sessionHeaders, 'tools/list', 'tools', options, context);
    if (Object.hasOwn(capabilities, 'resources')) collections.resources = await listCollection(server.url, sessionHeaders, 'resources/list', 'resources', options, context);
    if (Object.hasOwn(capabilities, 'prompts')) collections.prompts = await listCollection(server.url, sessionHeaders, 'prompts/list', 'prompts', options, context);
    const discovered = discoveryFromRpc(server, initialize.result, collections, initialize.contentType, options.tls);
    const latencyMs = initialize.latencyMs + Object.values(collections).reduce((total, value) => total + value.latencyMs, 0);
    const redirectOrigins = [...initialize.redirectOrigins, ...Object.values(collections).flatMap((value) => value.redirectOrigins)];
    return { ok: true, transport: 'streamable_http', snapshot: normalizeSnapshot(discovered), responseStatus: initialize.status, responseContentType: initialize.contentType, latencyMs, redirectOrigins };
}

async function listCollection(endpoint: string, headers: Record<string, string>, method: string, field: string, options: InspectOptions, context: InspectContext): Promise<CollectionResult> {
    const items: JsonValue[] = [];
    const redirectOrigins: string[] = [];
    const cursors = new Set<string>();
    let latencyMs = 0;
    let cursor: string | undefined;
    for (let page = 0; page < MAX_MCP_COLLECTION_PAGES; page += 1) {
        assertCanRequest(context, method);
        const result = await rpc(endpoint, headers, method, cursor ? { cursor } : {}, options, context);
        const pageItems = result.result[field];
        if (!Array.isArray(pageItems)) throw statusError('inspection_incomplete', `${method} did not return an array in ${field}.`, result);
        items.push(...pageItems);
        if (items.length > MAX_MCP_COLLECTION_ITEMS) throw statusError('inspection_incomplete', `${method} exceeded the ${MAX_MCP_COLLECTION_ITEMS}-item safety limit.`, result);
        latencyMs += result.latencyMs;
        redirectOrigins.push(...result.redirectOrigins);
        const next = result.result.nextCursor ?? result.result.next_cursor;
        if (next === undefined || next === null || next === '') return { items, latencyMs, redirectOrigins };
        if (typeof next !== 'string') throw statusError('inspection_incomplete', `${method} returned an invalid pagination cursor.`, result);
        if (cursors.has(next)) throw statusError('inspection_incomplete', `${method} repeated a pagination cursor.`, result);
        cursors.add(next);
        cursor = next;
    }
    throw statusError('inspection_incomplete', `${method} exceeded the ${MAX_MCP_COLLECTION_PAGES}-page safety limit.`);
}

async function notifyInitialized(endpoint: string, headers: Record<string, string>, options: InspectOptions, context: InspectContext): Promise<void> {
    consumeRequest(context, 'notifications/initialized');
    const response = await safeFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
        headers: { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json', ...headers },
        timeoutMs: requestTimeout(options, context),
        deadlineAt: context.deadlineAt,
        maxResponseBytes: Math.min(options.maxResponseBytes, 65_536),
        bodyComplete: (_body, _headers, status) => ![200, 202, 204].includes(status),
        allowHttp: options.allowHttp,
    });
    if (![200, 202, 204].includes(response.status)) throw responseError(response, `MCP initialized notification returned HTTP ${response.status}`);
}

async function inspectStaticJson(server: ServerInput, options: InspectOptions, context: InspectContext): Promise<InspectionResult> {
    consumeRequest(context, 'static metadata');
    const response = await safeFetch(server.url, { headers: { Accept: 'application/json, application/mcp+json', ...(server.headers ?? {}) }, timeoutMs: requestTimeout(options, context), deadlineAt: context.deadlineAt, maxResponseBytes: options.maxResponseBytes, bodyComplete: (_body, _headers, status) => status !== 200, allowHttp: options.allowHttp });
    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    if (response.status === 401 || response.status === 403) return fail('authentication_failed', `Static manifest endpoint returned HTTP ${response.status}`, 'static_json', response.status, response.latencyMs, contentType, response.redirectOrigins, true);
    if (response.status !== 200) return fail(statusForHttp(response.status), `Static manifest endpoint returned HTTP ${response.status}`, 'static_json', response.status, response.latencyMs, contentType, response.redirectOrigins, true);
    if (!contentType.includes('json') && !response.body.trim().startsWith('{')) return fail('invalid_response', 'Static metadata endpoint did not return JSON.', 'static_json', response.status, response.latencyMs, contentType, response.redirectOrigins, true);
    try {
        const payload = parseJson(response.body);
        return { ok: true, transport: 'static_json', snapshot: normalizeSnapshot(discoveryFromStatic(server, payload, contentType, options.tls)), responseStatus: response.status, responseContentType: contentType, latencyMs: response.latencyMs, redirectOrigins: response.redirectOrigins };
    } catch (error) {
        const value = error as StatusError;
        value.httpStatus = response.status; value.latencyMs = response.latencyMs; value.responseContentType = contentType; value.redirectOrigins = response.redirectOrigins; value.responseReceived = true;
        throw value;
    }
}

async function rpc(endpoint: string, headers: Record<string, string>, method: string, params: JsonObject, options: InspectOptions, context: InspectContext): Promise<RpcResult> {
    consumeRequest(context, method);
    const requestId = `${method}:${context.requests}`;
    const response = await safeFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }),
        headers: { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json', ...headers },
        timeoutMs: requestTimeout(options, context),
        deadlineAt: context.deadlineAt,
        maxResponseBytes: options.maxResponseBytes,
        bodyComplete: (body, responseHeaders, status) => status !== 200 || (responseHeaders.get('content-type')?.toLowerCase().includes('text/event-stream') === true && hasMatchingSseResponse(body, requestId)),
        allowHttp: options.allowHttp,
    });
    if (response.status === 401 || response.status === 403) throw responseError(response, `MCP endpoint returned HTTP ${response.status}`, 'authentication_failed');
    if (response.status !== 200) throw responseError(response, `MCP endpoint returned HTTP ${response.status}`);
    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    let parsed: JsonObject;
    try { parsed = parseRpcPayload(response.body, requestId, contentType); }
    catch (error) {
        const value = error as StatusError;
        value.httpStatus = response.status; value.latencyMs = response.latencyMs; value.responseContentType = contentType; value.redirectOrigins = response.redirectOrigins; value.responseReceived = true;
        throw value;
    }
    if (parsed.error) throw statusError('invalid_response', `MCP metadata call ${method} returned an error.`, response);
    if (!parsed.result || typeof parsed.result !== 'object' || Array.isArray(parsed.result)) throw statusError('invalid_response', `MCP metadata call ${method} did not return an object result.`, response);
    const sessionId = response.headers.get('mcp-session-id');
    return { result: parsed.result as JsonObject, headers: sessionId ? { 'mcp-session-id': sessionId } : {}, status: response.status, contentType, latencyMs: response.latencyMs, redirectOrigins: response.redirectOrigins };
}

function discoveryFromRpc(server: ServerInput, init: JsonObject, collections: Record<string, CollectionResult>, contentType: string, tls: import('./types.js').TlsMetadata | undefined): DiscoveredMetadata {
    const serverInfo = asObject(init.serverInfo ?? init.server_info);
    return {
        server: { name: stringValue(serverInfo.name) ?? server.name, origin: new URL(server.url).origin, identity: serverInfo.id ?? serverInfo.name, version: serverInfo.version, protocolVersion: init.protocolVersion ?? init.protocol_version, capabilities: Object.keys(asObject(init.capabilities)), authentication: init.authentication ?? init.auth ?? init.security, contentType },
        tools: collections.tools?.items ?? [], resources: collections.resources?.items ?? [], prompts: collections.prompts?.items ?? [],
        packages: init.packages ?? init.packageMetadata ?? serverInfo.packages, ...(tls ? { tls } : {}),
    };
}

export function discoveryFromStatic(server: ServerInput, payload: JsonObject, contentType: string, tls?: import('./types.js').TlsMetadata): DiscoveredMetadata {
    const serverInfo = asObject(payload.serverInfo ?? payload.server_info ?? payload.server);
    return { server: { name: stringValue(serverInfo.name) ?? stringValue(payload.name) ?? server.name, origin: new URL(server.url).origin, identity: serverInfo.id ?? payload.id, version: serverInfo.version ?? payload.version, protocolVersion: payload.protocolVersion ?? payload.protocol_version, capabilities: Array.isArray(payload.capabilities) ? payload.capabilities : Object.keys(asObject(payload.capabilities)), authentication: payload.authentication ?? payload.auth ?? payload.security, contentType }, tools: payload.tools ?? asObject(payload.result).tools, resources: payload.resources, prompts: payload.prompts, packages: payload.packages ?? payload.packageMetadata, ...(tls ? { tls } : {}) };
}

function parseJson(body: string): JsonObject {
    try { const parsed: unknown = JSON.parse(body); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not object'); return parsed as JsonObject; }
    catch { throw statusError('invalid_response', 'Metadata response contained malformed JSON.'); }
}
function parseRpcPayload(body: string, requestId: string, contentType: string): JsonObject {
    const candidates: unknown[] = [];
    if (contentType.includes('text/event-stream') || /^(?:\s*:.*\r?\n)*\s*(?:event|data|id|retry)\s*:/m.test(body)) {
        for (const data of parseSseData(body)) {
            try { candidates.push(JSON.parse(data)); } catch { /* Ignore non-JSON SSE data events. */ }
        }
    } else {
        try { candidates.push(JSON.parse(body)); } catch { throw statusError('invalid_response', 'MCP response contained malformed JSON.'); }
    }
    for (const candidate of candidates) {
        if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) continue;
        const object = candidate as JsonObject;
        if (object.id === requestId) return object;
    }
    throw statusError('invalid_response', 'MCP response did not contain a JSON-RPC response matching the request ID.');
}
function hasMatchingSseResponse(body: string, requestId: string): boolean {
    for (const data of parseSseData(body, true)) {
        try {
            const value = JSON.parse(data) as JsonObject;
            if (value && typeof value === 'object' && !Array.isArray(value) && value.id === requestId) return true;
        } catch { /* Continue until a complete matching JSON event is framed. */ }
    }
    return false;
}
function parseSseData(body: string, completeEventsOnly = false): string[] {
    const normalized = body.replace(/\r\n?/g, '\n');
    const lastBoundary = normalized.lastIndexOf('\n\n');
    const source = completeEventsOnly ? (lastBoundary < 0 ? '' : normalized.slice(0, lastBoundary)) : normalized;
    const events = source.split(/\n\n+/);
    const payloads: string[] = [];
    for (const event of events) {
        const data: string[] = [];
        for (const line of event.split('\n')) {
            if (!line || line.startsWith(':')) continue;
            const separator = line.indexOf(':');
            const field = separator < 0 ? line : line.slice(0, separator);
            let value = separator < 0 ? '' : line.slice(separator + 1);
            if (value.startsWith(' ')) value = value.slice(1);
            if (field === 'data') data.push(value);
        }
        if (data.length) payloads.push(data.join('\n'));
    }
    return payloads;
}
function asObject(value: unknown): JsonObject { return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {}; }
function stringValue(value: unknown): string | undefined { return typeof value === 'string' ? value : undefined; }
function statusForHttp(status: number): InspectionFailure['status'] { return status === 429 ? 'rate_limited' : [404, 405, 406, 415, 501].includes(status) ? 'unsupported_transport' : status >= 500 ? 'unreachable' : 'invalid_response'; }
function statusError(status: InspectionFailure['status'], message: string, response?: Partial<{ status: number; latencyMs: number; headers: Headers; redirectOrigins: string[] }> | RpcResult): StatusError {
    const contentType = response && 'contentType' in response ? response.contentType : response?.headers instanceof Headers ? response.headers.get('content-type')?.toLowerCase() ?? '' : undefined;
    return Object.assign(new Error(message), { status, ...(response?.status === undefined ? {} : { httpStatus: response.status, responseReceived: true }), ...(response?.latencyMs === undefined ? {} : { latencyMs: response.latencyMs }), ...(contentType === undefined ? {} : { responseContentType: contentType }), ...(response?.redirectOrigins ? { redirectOrigins: response.redirectOrigins } : {}) });
}
function responseError(response: { status: number; latencyMs: number; headers: Headers; redirectOrigins: string[] }, message: string, status = statusForHttp(response.status)): StatusError { return statusError(status, message, response); }
function fail(status: InspectionFailure['status'], message: string, transport?: TransportName, httpStatus?: number, latencyMs?: number, responseContentType?: string, redirectOrigins?: string[], responseReceived?: boolean): InspectionFailure {
    return { ok: false, status, message, ...(transport ? { transport } : {}), ...(httpStatus === undefined ? {} : { httpStatus }), ...(latencyMs === undefined ? {} : { latencyMs }), ...(responseContentType === undefined ? {} : { responseContentType }), ...(redirectOrigins === undefined ? {} : { redirectOrigins }), ...(responseReceived === undefined ? {} : { responseReceived }) };
}
function classifyError(error: unknown, transport: TransportName): InspectionFailure {
    const value = error as StatusError;
    const message = value?.message ?? 'Unknown inspection error';
    const status = value?.status ?? (value?.name === 'AbortError' || /timed out|deadline|abort/i.test(message) ? 'timeout' : /DNS|ENOTFOUND|ECONNREFUSED|network|fetch failed/i.test(message) ? 'unreachable' : /maximum size|safety limit|pagination|request cap/i.test(message) ? 'inspection_incomplete' : 'invalid_response');
    return fail(status, message, transport, value.httpStatus, value.latencyMs, value.responseContentType, value.redirectOrigins, value.responseReceived);
}
function remainingMs(context: InspectContext): number { return context.deadlineAt - Date.now(); }
function requestTimeout(options: InspectOptions, context: InspectContext): number {
    const remaining = remainingMs(context);
    if (remaining <= 0) throw statusError('timeout', 'Per-server inspection deadline exceeded.');
    return Math.max(1, Math.min(options.timeoutMs, remaining));
}
function assertCanRequest(context: InspectContext, operation: string): void {
    if (remainingMs(context) <= 0) throw statusError('timeout', `Per-server inspection deadline exceeded before ${operation}.`);
    if (context.requests >= MAX_MCP_REQUESTS_PER_SERVER) throw statusError('inspection_incomplete', `MCP metadata request cap of ${MAX_MCP_REQUESTS_PER_SERVER} was reached.`);
}
function consumeRequest(context: InspectContext, operation: string): void { assertCanRequest(context, operation); context.requests += 1; }
