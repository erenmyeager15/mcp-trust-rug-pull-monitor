import { MAX_DESCRIPTION_LENGTH, NORMALIZER_VERSION } from './constants.js';
import { asStringArray, canonicalSchema, isJsonObject, normalizeText, safeJson, sha256, stableStringify } from './json.js';
import { redactMetadataText, redactSchemaValue, redactUrl, redactValue } from './redaction.js';
import type { AuthMetadata, JsonObject, JsonValue, NormalizedSnapshot, PackageReference, PromptDefinition, ResourceDefinition, TlsMetadata, ToolDefinition } from './types.js';

export interface DiscoveredMetadata {
    server: { name: string; origin: string; identity?: unknown; version?: unknown; protocolVersion?: unknown; capabilities?: unknown; authentication?: unknown; contentType?: string; };
    tools?: unknown;
    resources?: unknown;
    prompts?: unknown;
    packages?: unknown;
    tls?: TlsMetadata;
}

export function normalizeSnapshot(discovered: DiscoveredMetadata): NormalizedSnapshot {
    const name = requireMetadataText(discovered.server.name, 'server name', 128);
    const origin = new URL(discovered.server.origin).origin;
    const identity = optionalMetadataText(discovered.server.identity, 512);
    const version = optionalMetadataText(discovered.server.version, 128);
    const protocolVersion = optionalMetadataText(discovered.server.protocolVersion, 128);
    return {
        schemaVersion: 1,
        normalizerVersion: NORMALIZER_VERSION,
        server: {
            name,
            origin,
            ...(identity ? { identity } : {}),
            ...(version ? { version } : {}),
            ...(protocolVersion ? { protocolVersion } : {}),
            capabilities: normalizeMetadataArray(discovered.server.capabilities, 512, 'capability'),
            authentication: normalizeAuth(discovered.server.authentication),
            ...(discovered.server.contentType ? { contentType: redactMetadataText(discovered.server.contentType, 256).toLowerCase() } : {}),
        },
        tools: normalizeTools(discovered.tools),
        resources: normalizeResources(discovered.resources),
        prompts: normalizePrompts(discovered.prompts),
        packages: normalizePackages(discovered.packages),
        ...(discovered.tls ? { tls: normalizeTls(discovered.tls) } : {}),
    };
}

export function snapshotHash(snapshot: NormalizedSnapshot): string {
    const hashable = structuredClone(snapshot);
    if (hashable.tls) delete hashable.tls.daysRemaining;
    return sha256(hashable as unknown as JsonValue);
}

function normalizeTools(raw: unknown): ToolDefinition[] {
    if (raw === undefined) return [];
    if (!Array.isArray(raw)) throw new Error('MCP tools must be an array');
    if (raw.length > 10_000) throw new Error('MCP tools exceed the 10,000-item safety limit');
    const names = new Set<string>();
    const tools = raw.map((entry, index) => {
        if (!isJsonObject(entry)) throw new Error(`Tool ${index} must be an object`);
        const name = requireMetadataText(entry.name, `tool ${index} name`, 256);
        ensureUniqueName(names, name, 'tool');
        const inputSchema = canonicalSchema(entry.inputSchema ?? entry.input_schema ?? { type: 'object', properties: {} });
        const outputRaw = entry.outputSchema ?? entry.output_schema;
        const annotations = entry.annotations;
        return {
            name,
            description: optionalMetadataText(entry.description, MAX_DESCRIPTION_LENGTH) ?? '',
            inputSchema: redactSchemaValue(inputSchema) as JsonObject,
            ...(outputRaw === undefined ? {} : { outputSchema: redactSchemaValue(canonicalSchema(outputRaw)) as JsonObject }),
            ...(annotations === undefined ? {} : { annotations: redactValue(safeJson(annotations)) as JsonObject }),
        };
    });
    return tools.sort((left, right) => compareText(left.name, right.name));
}

function normalizeResources(raw: unknown): ResourceDefinition[] {
    if (raw === undefined) return [];
    if (!Array.isArray(raw)) throw new Error('MCP resources must be an array');
    if (raw.length > 10_000) throw new Error('MCP resources exceed the 10,000-item safety limit');
    const names = new Set<string>();
    return raw.map((entry, index) => {
        if (!isJsonObject(entry)) throw new Error(`Resource ${index} must be an object`);
        const name = requireMetadataText(entry.name ?? entry.uri ?? entry.uriTemplate, `resource ${index} name`, 512);
        ensureUniqueName(names, name, 'resource');
        const uri = optionalMetadataText(entry.uri, 2_048);
        const uriTemplate = optionalMetadataText(entry.uriTemplate ?? entry.uri_template, 2_048);
        if (!uri && !uriTemplate) throw new Error(`Resource ${name} needs uri or uriTemplate`);
        const description = optionalMetadataText(entry.description, MAX_DESCRIPTION_LENGTH);
        const mimeType = optionalMetadataText(entry.mimeType ?? entry.mime_type, 128);
        return { name, ...(uri ? { uri: redactUrl(uri) } : {}), ...(uriTemplate ? { uriTemplate: redactUrl(uriTemplate) } : {}), ...(description ? { description } : {}), ...(mimeType ? { mimeType } : {}) };
    }).sort((left, right) => compareText(left.name, right.name));
}

function normalizePrompts(raw: unknown): PromptDefinition[] {
    if (raw === undefined) return [];
    if (!Array.isArray(raw)) throw new Error('MCP prompts must be an array');
    if (raw.length > 10_000) throw new Error('MCP prompts exceed the 10,000-item safety limit');
    const names = new Set<string>();
    return raw.map((entry, index) => {
        if (!isJsonObject(entry)) throw new Error(`Prompt ${index} must be an object`);
        const name = requireMetadataText(entry.name, `prompt ${index} name`, 256);
        ensureUniqueName(names, name, 'prompt');
        const description = optionalMetadataText(entry.description, MAX_DESCRIPTION_LENGTH);
        const text = optionalMetadataText(entry.text ?? entry.template, MAX_DESCRIPTION_LENGTH);
        return { name, ...(description ? { description } : {}), ...(text ? { text } : {}), ...(entry.arguments === undefined ? {} : { arguments: redactValue(safeJson(entry.arguments)) }) };
    }).sort((left, right) => compareText(left.name, right.name));
}

function normalizePackages(raw: unknown): PackageReference[] {
    if (raw === undefined) return [];
    if (!Array.isArray(raw)) throw new Error('Package metadata must be an array');
    if (raw.length > 500) throw new Error('Package metadata exceeds the 500-item safety limit');
    const seen = new Set<string>();
    return raw.map((entry, index) => {
        if (!isJsonObject(entry)) throw new Error(`Package ${index} must be an object`);
        const name = requireMetadataText(entry.name, `package ${index} name`, 256);
        const version = requireMetadataText(entry.version, `package ${index} version`, 128);
        const ecosystem = optionalMetadataText(entry.ecosystem, 128);
        const key = `${ecosystem ?? ''}:${name}`;
        if (seen.has(key)) throw new Error(`Duplicate package identity after normalization, truncation, or redaction: ${key}`);
        seen.add(key);
        return { name, version, ...(ecosystem ? { ecosystem } : {}) };
    }).sort((left, right) => compareText(`${left.ecosystem ?? ''}:${left.name}@${left.version}`, `${right.ecosystem ?? ''}:${right.name}@${right.version}`));
}

function normalizeAuth(raw: unknown): AuthMetadata {
    if (!isJsonObject(raw)) return {};
    const schemes = normalizeMetadataArray(raw.schemes, 512, 'authentication scheme');
    const scopes = normalizeMetadataArray(raw.scopes, 512, 'authentication scope');
    const permissions = normalizeMetadataArray(raw.permissions, 512, 'authentication permission');
    const capabilities = normalizeMetadataArray(raw.capabilities, 512, 'authentication capability');
    return {
        ...(typeof raw.required === 'boolean' ? { required: raw.required } : {}),
        ...(schemes.length ? { schemes } : {}),
        ...(scopes.length ? { scopes } : {}),
        ...(permissions.length ? { permissions } : {}),
        ...(capabilities.length ? { capabilities } : {}),
    };
}

function normalizeTls(raw: TlsMetadata): TlsMetadata {
    return {
        ...(raw.protocol ? { protocol: redactMetadataText(raw.protocol, 64) } : {}),
        ...(raw.validFrom ? { validFrom: redactMetadataText(raw.validFrom, 128) } : {}),
        ...(raw.validTo ? { validTo: redactMetadataText(raw.validTo, 128) } : {}),
        ...(typeof raw.daysRemaining === 'number' && Number.isFinite(raw.daysRemaining) ? { daysRemaining: Math.floor(raw.daysRemaining) } : {}),
        ...(typeof raw.authorized === 'boolean' ? { authorized: raw.authorized } : {}),
        ...(raw.authorizationError ? { authorizationError: redactMetadataText(raw.authorizationError, 512) } : {}),
        ...(raw.subject ? { subject: redactMetadataText(raw.subject, 512) } : {}),
        ...(raw.issuer ? { issuer: redactMetadataText(raw.issuer, 512) } : {}),
        ...(raw.hostname ? { hostname: redactMetadataText(raw.hostname, 512) } : {}),
    };
}

function normalizeMetadataArray(value: unknown, maxLength: number, label: string): string[] {
    const seen = new Set<string>();
    return asStringArray(value).map((entry) => {
        const safe = redactMetadataText(entry, maxLength);
        if (seen.has(safe)) throw new Error(`${label} values collide after normalization, truncation, or redaction`);
        seen.add(safe);
        return safe;
    }).sort(compareText);
}
function ensureUniqueName(names: Set<string>, name: string, kind: string): void {
    if (names.has(name)) throw new Error(`Duplicate ${kind} name after normalization, truncation, or redaction: ${name}`);
    names.add(name);
}
function compareText(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function requireMetadataText(value: unknown, label: string, max: number): string {
    if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
    const normalized = value.normalize('NFC').replace(/\r\n/g, '\n').trim();
    if (normalized.length > max) throw new Error(`${label} exceeds the ${max}-character safety limit`);
    return redactMetadataText(normalized, max);
}
function optionalMetadataText(value: unknown, max: number): string | undefined {
    if (typeof value !== 'string' || !value.trim()) return undefined;
    return redactMetadataText(normalizeText(value, max), max);
}

export function toolFingerprint(tool: ToolDefinition): string {
    return stableStringify({ description: tool.description, inputSchema: tool.inputSchema, outputSchema: tool.outputSchema, annotations: tool.annotations } as unknown as JsonValue);
}
