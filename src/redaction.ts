import { createHash } from 'node:crypto';
import { normalizeText } from './json.js';
import type { JsonObject, JsonValue } from './types.js';

const SENSITIVE_KEY = /authorization|cookie|token|secret|api[-_]?key|password|credential|session/i;
const SCHEMA_PROPERTY_CONTAINERS = new Set(['properties', 'patternProperties', '$defs', 'definitions']);
const SCHEMA_VALUE_KEYWORDS = new Set(['default', 'const', 'examples', 'enum']);
const BEARER = /\b(bearer|basic)\s+[a-z0-9._~+\/=:-]+/gi;
const QUERY_SECRET = /([?&](?:token|access_token|api[_-]?key|key|secret|signature|sig|password)=)[^&#\s]+/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?\b/g;
const HEX_TOKEN = /\b[a-fA-F0-9]{32,}\b/g;
const OPAQUE_TOKEN = /[A-Za-z0-9_+\/=.-]{24,}/g;
const MAX_STRING_LENGTH = 2_000;

export function isTokenShaped(value: string): boolean {
    const candidate = value.trim();
    if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?$/.test(candidate)) return true;
    if (/^[a-fA-F0-9]{32,}$/.test(candidate)) return true;
    if (!/^[A-Za-z0-9_+\/=.-]{24,}$/.test(candidate)) return false;
    const categories = [/[a-z]/.test(candidate), /[A-Z]/.test(candidate), /\d/.test(candidate), /[_+\/=.-]/.test(candidate)].filter(Boolean).length;
    const diversity = new Set(candidate).size;
    return diversity >= 10 && (categories >= 3 || (candidate.length >= 32 && categories >= 2) || (candidate.length >= 40 && diversity >= 12));
}

export function redactString(value: string): string {
    return value
        .replace(BEARER, '$1 [REDACTED]')
        .replace(QUERY_SECRET, '$1[REDACTED]')
        .replace(/\b(?:sk|pk|ghp|xox[baprs])[-_A-Za-z0-9]{12,}\b/g, '[REDACTED]')
        .replace(JWT, '[REDACTED]')
        .replace(HEX_TOKEN, '[REDACTED]')
        .replace(OPAQUE_TOKEN, (candidate) => isTokenShaped(candidate) ? '[REDACTED]' : candidate)
        .slice(0, MAX_STRING_LENGTH);
}

export function redactMetadataText(value: string, maxLength = MAX_STRING_LENGTH): string {
    return redactString(value.normalize('NFC').replace(/\r\n/g, '\n').trim()).slice(0, Math.min(maxLength, MAX_STRING_LENGTH));
}

export function redactUrl(value: string): string {
    try {
        const url = new URL(value);
        const safeSegments = url.pathname.split('/').map((segment) => {
            if (!segment) return '';
            let decoded = segment;
            try { decoded = decodeURIComponent(segment); } catch { /* Preserve malformed escaping as text for redaction. */ }
            return encodeURIComponent(redactMetadataText(decoded, 512));
        });
        url.pathname = safeSegments.join('/');
        for (const key of [...url.searchParams.keys()]) {
            const current = url.searchParams.get(key) ?? '';
            url.searchParams.set(key, SENSITIVE_KEY.test(key) ? '[REDACTED]' : redactMetadataText(current, 512));
        }
        if (url.hash) {
            let fragment = url.hash.slice(1);
            try { fragment = decodeURIComponent(fragment); } catch { /* Preserve malformed escaping as text for redaction. */ }
            url.hash = redactMetadataText(fragment, 512);
        }
        return url.toString();
    } catch { return redactString(value); }
}

export function redactValue(value: JsonValue | undefined, key = ''): JsonValue | undefined {
    if (value === undefined) return undefined;
    if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
    if (typeof value === 'string') return redactMetadataText(value);
    if (Array.isArray(value)) return value.map((entry) => redactValue(entry) ?? null);
    if (value && typeof value === 'object') {
        const clean: JsonObject = {};
        const seen = new Map<string, string>();
        for (const [childKey, childValue] of Object.entries(value)) {
            const safeKey = redactMetadataText(childKey, 256);
            const prior = seen.get(safeKey);
            if (prior !== undefined && prior !== childKey) throw new Error('Metadata object keys collide after normalization, truncation, or redaction');
            seen.set(safeKey, childKey);
            clean[safeKey] = redactValue(childValue, childKey);
        }
        return clean;
    }
    return value;
}

export function redactSchemaValue(value: JsonValue | undefined): JsonValue | undefined {
    const sensitiveReferences = collectSensitiveSchemaReferences(value);
    return redactSchemaNode(value, false, sensitiveReferences, []);
}

function redactSchemaNode(value: JsonValue | undefined, credentialProperty: boolean, sensitiveReferences: ReadonlySet<string>, path: string[]): JsonValue | undefined {
    const sensitive = credentialProperty || sensitiveReferences.has(schemaPointer(path));
    if (value === undefined) return undefined;
    if (typeof value === 'string') return redactMetadataText(value);
    if (Array.isArray(value)) return value.map((entry, index) => redactSchemaNode(entry, sensitive, sensitiveReferences, [...path, String(index)]) ?? null);
    if (value && typeof value === 'object') {
        const clean: JsonObject = {};
        const seen = new Map<string, string>();
        for (const [childKey, childValue] of Object.entries(value)) {
            const safeKey = redactMetadataText(childKey, 256);
            const prior = seen.get(safeKey);
            if (prior !== undefined && prior !== childKey) throw new Error('Schema keys collide after normalization, truncation, or redaction');
            seen.set(safeKey, childKey);
            if (sensitive && SCHEMA_VALUE_KEYWORDS.has(childKey)) {
                clean[safeKey] = redactSchemaKeywordValue(childValue);
            } else if (SCHEMA_PROPERTY_CONTAINERS.has(childKey) && childValue && typeof childValue === 'object' && !Array.isArray(childValue)) {
                const properties: JsonObject = {};
                const propertyNames = new Map<string, string>();
                for (const [propertyName, propertySchema] of Object.entries(childValue)) {
                    const safePropertyName = redactMetadataText(propertyName, 256);
                    const propertyPrior = propertyNames.get(safePropertyName);
                    if (propertyPrior !== undefined && propertyPrior !== propertyName) throw new Error('Schema property names collide after normalization, truncation, or redaction');
                    propertyNames.set(safePropertyName, propertyName);
                    const propertyPath = [...path, childKey, propertyName];
                    const propertySensitive = sensitive
                        || isSensitiveSchemaName(propertyName, childKey)
                        || sensitiveReferences.has(schemaPointer(propertyPath));
                    properties[safePropertyName] = redactSchemaNode(propertySchema, propertySensitive, sensitiveReferences, propertyPath);
                }
                clean[safeKey] = properties;
            } else {
                clean[safeKey] = redactSchemaNode(childValue, sensitive, sensitiveReferences, [...path, childKey]);
            }
        }
        return clean;
    }
    return value;
}

function collectSensitiveSchemaReferences(value: JsonValue | undefined): Set<string> {
    const sensitiveReferences = new Set<string>();
    let changed = true;
    while (changed) {
        changed = false;
        visit(value, false, []);
    }
    return sensitiveReferences;

    function visit(node: JsonValue | undefined, inheritedSensitive: boolean, path: string[]): void {
        if (node === undefined || node === null || typeof node !== 'object') return;
        const sensitive = inheritedSensitive || sensitiveReferences.has(schemaPointer(path));
        if (Array.isArray(node)) {
            node.forEach((entry, index) => visit(entry, sensitive, [...path, String(index)]));
            return;
        }
        if (sensitive && typeof node.$ref === 'string') {
            const target = localSchemaPointer(node.$ref);
            if (target && !sensitiveReferences.has(target)) {
                sensitiveReferences.add(target);
                changed = true;
            }
        }
        for (const [childKey, childValue] of Object.entries(node)) {
            if (SCHEMA_PROPERTY_CONTAINERS.has(childKey) && childValue && typeof childValue === 'object' && !Array.isArray(childValue)) {
                for (const [propertyName, propertySchema] of Object.entries(childValue)) {
                    visit(propertySchema, sensitive || isSensitiveSchemaName(propertyName, childKey), [...path, childKey, propertyName]);
                }
            } else {
                visit(childValue, sensitive, [...path, childKey]);
            }
        }
    }
}

function isSensitiveSchemaName(name: string, container: string): boolean {
    if (SENSITIVE_KEY.test(name)) return true;
    return container === 'patternProperties' && SENSITIVE_KEY.test(name.replace(/[^a-z0-9]/gi, ''));
}

function localSchemaPointer(value: string): string | undefined {
    if (value === '#') return '#';
    if (!value.startsWith('#/')) return undefined;
    try {
        const segments = value.slice(2).split('/').map((segment) => normalizeText(decodeURIComponent(segment).replace(/~1/g, '/').replace(/~0/g, '~'), 256));
        return schemaPointer(segments);
    } catch {
        return undefined;
    }
}

function schemaPointer(path: readonly string[]): string {
    if (path.length === 0) return '#';
    return `#/${path.map((segment) => segment.replace(/~/g, '~0').replace(/\//g, '~1')).join('/')}`;
}

function redactSchemaKeywordValue(value: JsonValue | undefined): JsonValue {
    if (Array.isArray(value)) return value.map(() => '[REDACTED]');
    return '[REDACTED]';
}

export function secretSafeFingerprint(value: string): string {
    return `sha256:${createHash('sha256').update(value).digest('hex').slice(0, 16)}`;
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
    return Object.fromEntries(Object.entries(headers).map(([key, value]) => [redactMetadataText(key, 128), SENSITIVE_KEY.test(key) ? '[REDACTED]' : redactString(value)]));
}
