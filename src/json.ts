import { createHash } from 'node:crypto';
import { MAX_JSON_DEPTH } from './constants.js';
import type { JsonObject, JsonValue } from './types.js';

const POISONED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const SCHEMA_SET_ARRAYS = new Set(['required', 'enum', 'type', 'allOf', 'anyOf', 'oneOf', 'examples']);
const SCHEMA_ARRAY_OF_SCHEMAS = new Set(['allOf', 'anyOf', 'oneOf', 'prefixItems']);
const SCHEMA_SINGLE_SCHEMA = new Set(['items', 'contains', 'additionalProperties', 'unevaluatedProperties', 'propertyNames', 'not', 'if', 'then', 'else']);

export function isJsonObject(value: unknown): value is JsonObject {
    return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function normalizeText(value: string, maxLength = 20_000): string {
    return value.normalize('NFC').replace(/\r\n/g, '\n').trim().slice(0, maxLength);
}

function normalizedEntries(value: JsonObject, maxKeyLength = 256): Array<[string, JsonValue | undefined]> {
    const seen = new Map<string, string>();
    return Object.keys(value).sort().map((rawKey) => {
        const key = normalizeText(rawKey, maxKeyLength);
        const prior = seen.get(key);
        if (prior !== undefined && prior !== rawKey) throw new Error('JSON object keys collide after NFC normalization or truncation');
        seen.set(key, rawKey);
        return [key, value[rawKey]];
    });
}

export function safeJson(value: unknown, depth = 0): JsonValue {
    if (depth > MAX_JSON_DEPTH) throw new Error(`JSON exceeds maximum depth of ${MAX_JSON_DEPTH}`);
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') return normalizeText(value);
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) throw new Error('JSON contains a non-finite number');
        return value;
    }
    if (Array.isArray(value)) return value.map((entry) => safeJson(entry, depth + 1));
    if (isJsonObject(value)) {
        const result: JsonObject = {};
        for (const [key, child] of normalizedEntries(value)) {
            if (POISONED_KEYS.has(key)) continue;
            if (child !== undefined) result[key] = safeJson(child, depth + 1);
        }
        return result;
    }
    throw new Error('Value is not JSON-compatible');
}

export function canonicalSchema(value: unknown, depth = 0): JsonObject {
    if (!isJsonObject(value)) throw new Error('JSON Schema must be an object');
    if (depth > MAX_JSON_DEPTH) throw new Error(`JSON Schema exceeds maximum depth of ${MAX_JSON_DEPTH}`);
    const result: JsonObject = {};
    for (const [key, child] of normalizedEntries(value)) {
        if (POISONED_KEYS.has(key) || child === undefined) continue;
        if (key === 'properties' || key === 'patternProperties' || key === '$defs' || key === 'definitions') {
            if (!isJsonObject(child)) throw new Error(`${key} must be an object in JSON Schema`);
            const properties: JsonObject = {};
            for (const [propertyName, propertyValue] of normalizedEntries(child)) properties[propertyName] = canonicalSchema(propertyValue, depth + 1);
            result[key] = properties;
        } else if (SCHEMA_SINGLE_SCHEMA.has(key) && isJsonObject(child)) {
            result[key] = canonicalSchema(child, depth + 1);
        } else if (Array.isArray(child)) {
            const normalized = child.map((entry) => SCHEMA_ARRAY_OF_SCHEMAS.has(key) && isJsonObject(entry) ? canonicalSchema(entry, depth + 1) : safeJson(entry, depth + 1));
            result[key] = SCHEMA_SET_ARRAYS.has(key) ? normalized.sort((a, b) => stableStringify(a).localeCompare(stableStringify(b))) : normalized;
        } else if (isJsonObject(child)) {
            result[key] = safeJson(child, depth + 1);
        } else {
            result[key] = safeJson(child, depth + 1);
        }
    }
    return result;
}

export function stableStringify(value: JsonValue | undefined): string {
    return JSON.stringify(value === undefined ? null : safeJson(value));
}

export function sha256(value: JsonValue | string): string {
    const text = typeof value === 'string' ? value : stableStringify(value);
    return `sha256:${createHash('sha256').update(text).digest('hex')}`;
}

export function jsonEqual(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
    return stableStringify(left) === stableStringify(right);
}

export function asStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    const seen = new Map<string, string>();
    for (const entry of value) {
        if (typeof entry !== 'string') continue;
        const normalized = normalizeText(entry, 512);
        const prior = seen.get(normalized);
        if (prior !== undefined && prior !== entry) throw new Error('String array values collide after NFC normalization or truncation');
        seen.set(normalized, entry);
    }
    return [...seen.keys()].sort();
}
