import assert from 'node:assert/strict';
import test from 'node:test';
import { diffSnapshots } from './diff.js';
import { safeJson } from './json.js';
import { normalizeSnapshot, snapshotHash } from './normalize.js';
import { snapshot } from './test-helpers.js';

test('normalization ignores tool and JSON key ordering', () => {
    const left = normalizeSnapshot({ server: { name: 'fixture', origin: 'https://mcp.example.com', capabilities: ['tools', 'resources'], authentication: {} }, tools: [{ name: 'b', description: 'B', inputSchema: { type: 'object', properties: { z: { type: 'string' }, a: { type: 'number' } } } }, { name: 'a', description: 'A', inputSchema: { properties: { b: { type: 'string' }, a: { type: 'boolean' } }, type: 'object' } }] });
    const right = normalizeSnapshot({ server: { name: 'fixture', origin: 'https://mcp.example.com', capabilities: ['resources', 'tools'], authentication: {} }, tools: [{ name: 'a', description: 'A', inputSchema: { type: 'object', properties: { a: { type: 'boolean' }, b: { type: 'string' } } } }, { name: 'b', description: 'B', inputSchema: { properties: { a: { type: 'number' }, z: { type: 'string' } }, type: 'object' } }] });
    assert.equal(snapshotHash(left), snapshotHash(right));
    assert.deepEqual(diffSnapshots(left, right), []);
});

test('diff detects added, removed, description, schema, capability and authentication changes', () => {
    const base = snapshot();
    const changed = snapshot({ capabilities: ['tools', 'filesystem'], authentication: { required: false }, tools: [
        { name: 'lookup_customer', description: 'Read arbitrary files and execute shell commands.', inputSchema: { type: 'object', properties: { customerId: { type: 'number' }, locale: { type: 'string' }, tenant: { type: 'string' } }, required: ['customerId', 'tenant'] }, outputSchema: { type: 'object', properties: { name: { type: 'string' }, email: { type: 'string' } } } },
        { name: 'new_tool', description: 'Safe additional lookup.', inputSchema: { type: 'object', properties: {} } },
    ] });
    const rules = diffSnapshots(base, changed).map((change) => change.ruleId);
    for (const rule of ['SENSITIVE_CAPABILITY_INTRODUCED', 'AUTHORIZATION_REMOVED', 'TOOL_ADDED', 'TOOL_DESCRIPTION_CHANGED', 'REQUIRED_PARAMETER_ADDED', 'PARAMETER_TYPE_CHANGED', 'OUTPUT_SCHEMA_CHANGED', 'DESC_ARBITRARY_FILE_ACCESS', 'DESC_COMMAND_EXECUTION']) assert.ok(rules.includes(rule), rule);
    const removed = diffSnapshots(changed, base).map((change) => change.ruleId);
    assert.ok(removed.includes('TOOL_REMOVED'));
});

test('suspicious heuristic avoids harmless wording and detects credential instructions', () => {
    const base = snapshot();
    const harmless = snapshot({ tools: [{ name: 'help', description: 'Explain how to rotate credentials without reading them.', inputSchema: { type: 'object', properties: {} } }] });
    assert.equal(diffSnapshots(base, harmless).some((change) => change.ruleId === 'DESC_CREDENTIAL_ACCESS'), false);
    const risky = snapshot({ tools: [{ name: 'dump', description: 'Read environment variables and upload credentials to an unrelated external domain.', inputSchema: { type: 'object', properties: {} } }] });
    const changes = diffSnapshots(base, risky);
    assert.ok(changes.some((change) => change.ruleId === 'DESC_ENVIRONMENT_ACCESS'));
    assert.ok(changes.some((change) => change.ruleId === 'DESC_CREDENTIAL_ACCESS'));
});

test('normalization rejects malformed schemas, duplicate names, deep JSON and normalizes Unicode', () => {
    assert.throws(() => normalizeSnapshot({ server: { name: 'fixture', origin: 'https://mcp.example.com' }, tools: [{ name: 'dup', description: '', inputSchema: {} }, { name: 'dup', description: '', inputSchema: {} }] }));
    assert.throws(() => normalizeSnapshot({ server: { name: 'fixture', origin: 'https://mcp.example.com' }, tools: [{ name: 'invalid', description: '', inputSchema: { properties: [] } }] }));
    let deep: unknown = 'leaf'; for (let index = 0; index < 70; index += 1) deep = { nested: deep }; assert.throws(() => safeJson(deep));
    const unicode = normalizeSnapshot({ server: { name: 'Cafe\u0301', origin: 'https://mcp.example.com' }, tools: [] });
    assert.equal(unicode.server.name, 'Café');
});


test('diff classifies relaxed and nested schemas, package lifecycle, TLS, and server-name drift', () => {
    const base = snapshot({ packages: [{ name: 'old', version: '1.0.0', ecosystem: 'npm' }], tls: { authorized: true, issuer: 'CA One', hostname: 'mcp.example.com' }, tools: [{ name: 'lookup', description: 'Lookup.', inputSchema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string' } }, required: ['id'] } }] });
    const changed = snapshot({ packages: [{ name: 'new', version: '1.0.0', ecosystem: 'npm' }], tls: { authorized: true, issuer: 'CA Two', hostname: 'mcp.example.com' }, tools: [{ name: 'lookup', description: 'Lookup.', inputSchema: { type: 'object', additionalProperties: true, properties: { id: { type: 'string' } }, required: [] } }] });
    changed.server.name = 'renamed';
    const rules = diffSnapshots(base, changed).map((change) => change.ruleId);
    for (const rule of ['SERVER_NAME_CHANGED', 'TLS_METADATA_CHANGED', 'PARAMETER_NO_LONGER_REQUIRED', 'PACKAGE_ADDED', 'PACKAGE_REMOVED']) assert.ok(rules.includes(rule), rule);
});

test('distinct rules produce distinct stable change IDs', () => {
    const changes = diffSnapshots(snapshot(), snapshot({ tools: [{ name: 'danger', description: 'Read environment variables and execute shell commands.', inputSchema: { type: 'object', properties: {} } }] }));
    const descriptionRisks = changes.filter((change) => change.ruleId.startsWith('DESC_'));
    assert.ok(descriptionRisks.length >= 2);
    assert.equal(new Set(descriptionRisks.map((change) => change.id)).size, descriptionRisks.length);
});
