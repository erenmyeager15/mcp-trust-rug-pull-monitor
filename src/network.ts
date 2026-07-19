import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { IncomingMessage, RequestOptions } from 'node:http';
import { checkServerIdentity, connect } from 'node:tls';
import { resolvePublicTarget, sameOrigin, type ResolvedPublicTarget } from './safety.js';
import type { TlsMetadata } from './types.js';

export interface SafeHttpResponse { status: number; headers: Headers; body: string; url: string; redirectOrigins: string[]; latencyMs: number; }
export interface SafeRequestOptions { headers?: Record<string, string>; method?: 'GET' | 'POST'; body?: string; timeoutMs: number; deadlineAt?: number; maxResponseBytes: number; allowHttp: boolean; bodyComplete?: (body: string, headers: Headers, status: number) => boolean; }
export interface SafeNetworkDependencies {
    validateTarget?: (url: string, allowHttp: boolean) => Promise<URL>;
    fetchImpl?: typeof fetch;
}

export async function safeFetch(rawUrl: string, options: SafeRequestOptions, dependencies: SafeNetworkDependencies = {}): Promise<SafeHttpResponse> {
    const started = Date.now();
    const redirectOrigins: string[] = [];
    let currentUrl = rawUrl;
    const deadlineAt = options.deadlineAt ?? Date.now() + options.timeoutMs;
    for (let hop = 0; hop < 4; hop += 1) {
        const remaining = deadlineAt - Date.now();
        if (remaining <= 0) throw Object.assign(new Error('Request deadline exceeded'), { name: 'AbortError' });
        const boundedOptions = { ...options, timeoutMs: Math.max(1, Math.min(options.timeoutMs, remaining)) };
        const operation = dependencies.fetchImpl || dependencies.validateTarget
            ? requestWithInjectedFetch(currentUrl, boundedOptions, dependencies)
            : resolvePublicTarget(currentUrl, options.allowHttp).then((target) => requestPinned(target, boundedOptions));
        const response = await withinDeadline(operation, remaining);
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get('location');
            if (!location) throw new Error('Redirect response did not provide a Location header');
            const nextUrl = new URL(location, currentUrl).toString();
            const validation = dependencies.validateTarget
                ? dependencies.validateTarget(nextUrl, options.allowHttp)
                : resolvePublicTarget(nextUrl, options.allowHttp).then((target) => target.url);
            const validationRemaining = deadlineAt - Date.now();
            if (validationRemaining <= 0) throw Object.assign(new Error('Request deadline exceeded'), { name: 'AbortError' });
            const validatedNext = await withinDeadline(validation, validationRemaining);
            if (!sameOrigin(currentUrl, validatedNext.toString())) throw new Error('Cross-origin redirects are not allowed for monitored endpoints or webhooks.');
            currentUrl = validatedNext.toString();
            redirectOrigins.push(validatedNext.origin);
            continue;
        }
        return { ...response, url: currentUrl, redirectOrigins, latencyMs: Date.now() - started };
    }
    throw new Error('Too many redirects');
}

async function requestWithInjectedFetch(rawUrl: string, options: SafeRequestOptions, dependencies: SafeNetworkDependencies): Promise<Omit<SafeHttpResponse, 'url' | 'redirectOrigins' | 'latencyMs'>> {
    const url = dependencies.validateTarget ? await dependencies.validateTarget(rawUrl, options.allowHttp) : new URL(rawUrl);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
        const response = await (dependencies.fetchImpl ?? fetch)(url, { method: options.method ?? 'GET', headers: options.headers, body: options.body, redirect: 'manual', signal: controller.signal });
        const shouldSkipBody = options.bodyComplete?.('', response.headers, response.status) ?? false;
        const body = shouldSkipBody ? '' : await readBoundedBody(response, options.maxResponseBytes, (value) => options.bodyComplete?.(value, response.headers, response.status) ?? false);
        return { status: response.status, headers: response.headers, body };
    } finally { clearTimeout(timer); }
}

async function requestPinned(target: ResolvedPublicTarget, options: SafeRequestOptions): Promise<Omit<SafeHttpResponse, 'url' | 'redirectOrigins' | 'latencyMs'>> {
    return new Promise((resolve, reject) => {
        const url = target.url;
        const headers = { ...(options.headers ?? {}), Host: url.host };
        const requestOptions: RequestOptions = {
            protocol: url.protocol,
            hostname: target.address,
            family: target.family,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: `${url.pathname}${url.search}`,
            method: options.method ?? 'GET',
            headers,
            ...(url.protocol === 'https:' ? { servername: url.hostname.replace(/^\[|\]$/g, ''), rejectUnauthorized: true } : {}),
        };
        let settled = false;
        const finish = (error?: unknown, value?: Omit<SafeHttpResponse, 'url' | 'redirectOrigins' | 'latencyMs'>): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (error) reject(error);
            else if (value) resolve(value);
        };
        const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(requestOptions, async (response) => {
            try {
                const headers = nodeHeaders(response);
                const status = response.statusCode ?? 0;
                const shouldSkipBody = options.bodyComplete?.('', headers, status) ?? false;
                const body = shouldSkipBody ? '' : await readBoundedNodeBody(response, options.maxResponseBytes, (value) => options.bodyComplete?.(value, headers, status) ?? false);
                if (shouldSkipBody) response.destroy();
                finish(undefined, { status, headers, body });
            } catch (error) { finish(error); }
        });
        const timer = setTimeout(() => request.destroy(Object.assign(new Error('Request timed out'), { name: 'AbortError' })), options.timeoutMs);
        request.once('error', (error) => finish(error));
        if (options.body) request.write(options.body);
        request.end();
    });
}

export async function readBoundedBody(response: Response, maxBytes: number, bodyComplete?: (body: string) => boolean): Promise<string> {
    if (!response.body) return '';
    const declared = Number(response.headers.get('content-length') ?? '0');
    if (Number.isFinite(declared) && declared > maxBytes) throw new Error(`Response exceeds maximum size of ${maxBytes} bytes`);
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxBytes) throw new Error(`Response exceeds maximum size of ${maxBytes} bytes`);
            chunks.push(value);
            if (bodyComplete?.(new TextDecoder().decode(concat(chunks, size)))) { await reader.cancel(); break; }
        }
    } finally { reader.releaseLock(); }
    return new TextDecoder().decode(concat(chunks, size));
}

async function readBoundedNodeBody(response: IncomingMessage, maxBytes: number, bodyComplete?: (body: string) => boolean): Promise<string> {
    const declared = Number(response.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > maxBytes) { response.destroy(); throw new Error(`Response exceeds maximum size of ${maxBytes} bytes`); }
    const chunks: Buffer[] = [];
    let size = 0;
    let completed = false;
    try {
        for await (const chunk of response) {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
            size += buffer.byteLength;
            if (size > maxBytes) { response.destroy(); throw new Error(`Response exceeds maximum size of ${maxBytes} bytes`); }
            chunks.push(buffer);
            if (bodyComplete?.(Buffer.concat(chunks, size).toString('utf8'))) { completed = true; response.destroy(); break; }
        }
    } catch (error) { if (!completed) throw error; }
    return Buffer.concat(chunks, size).toString('utf8');
}

function nodeHeaders(response: IncomingMessage): Headers {
    const headers = new Headers();
    for (const [key, value] of Object.entries(response.headers)) {
        if (Array.isArray(value)) for (const item of value) headers.append(key, item);
        else if (value !== undefined) headers.set(key, value);
    }
    return headers;
}
function concat(chunks: Uint8Array[], length: number): Uint8Array {
    const output = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
    return output;
}
async function withinDeadline<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            operation,
            new Promise<T>((_resolve, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('Request deadline exceeded'), { name: 'AbortError' })), timeoutMs); }),
        ]);
    } finally { if (timer) clearTimeout(timer); }
}

export async function inspectTls(rawUrl: string, timeoutMs: number, allowHttp: boolean): Promise<TlsMetadata> {
    const target = await resolvePublicTarget(rawUrl, allowHttp);
    const url = target.url;
    if (url.protocol !== 'https:') return { authorized: false, authorizationError: 'TLS is unavailable for plain HTTP targets.', hostname: url.hostname };
    return new Promise<TlsMetadata>((resolve) => {
        const hostname = url.hostname.replace(/^\[|\]$/g, '');
        let settled = false;
        const finish = (result: TlsMetadata): void => { if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); resolve(result); };
        const socket = connect({ host: target.address, port: Number(url.port || 443), servername: hostname, rejectUnauthorized: false });
        const timer = setTimeout(() => finish({ authorized: false, authorizationError: 'TLS probe timed out.', hostname: url.hostname }), timeoutMs);
        socket.once('secureConnect', () => {
            const certificate = socket.getPeerCertificate();
            const validTo = certificate.valid_to ? new Date(certificate.valid_to).toISOString() : undefined;
            const validFrom = certificate.valid_from ? new Date(certificate.valid_from).toISOString() : undefined;
            const hostnameError = certificate && Object.keys(certificate).length ? checkServerIdentity(hostname, certificate) : new Error('Peer did not present a certificate');
            const daysRemaining = validTo ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86_400_000) : undefined;
            finish({ protocol: socket.getProtocol() || undefined, ...(validFrom ? { validFrom } : {}), ...(validTo ? { validTo } : {}), ...(daysRemaining === undefined ? {} : { daysRemaining }), authorized: socket.authorized && !hostnameError, ...(socket.authorizationError || hostnameError ? { authorizationError: String(socket.authorizationError ?? hostnameError?.message) } : {}), subject: certificate.subject?.CN, issuer: certificate.issuer?.CN, hostname: url.hostname });
        });
        socket.once('error', (error) => finish({ authorized: false, authorizationError: error.message, hostname: url.hostname }));
    });
}
