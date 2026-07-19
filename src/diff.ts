import { findDescriptionRisks } from './description-rules.js';
import { jsonEqual, sha256, stableStringify } from './json.js';
import { toolFingerprint } from './normalize.js';
import { redactMetadataText, redactString, redactValue } from './redaction.js';
import type { AuthMetadata, Change, JsonObject, JsonValue, NormalizedSnapshot, PromptDefinition, ResourceDefinition, Severity, ToolDefinition } from './types.js';

const scoreBySeverity: Record<Severity, number> = { informational: 0, low: 5, medium: 15, high: 30, critical: 50 };

interface ChangeSpec {
    category: string; entityType: Change['entityType']; entityName: string; jsonPath?: string;
    previousValue?: JsonValue; currentValue?: JsonValue; severity: Severity; ruleId: string;
    explanation: string; recommendedAction: string; evidence: string[]; confidence?: Change['confidence']; score?: number;
}

export function createChange(spec: ChangeSpec): Change {
    const redactedPrevious = redactValue(spec.previousValue);
    const redactedCurrent = redactValue(spec.currentValue);
    return {
        id: sha256(stableStringify({ ruleId: spec.ruleId, category: spec.category, entityType: spec.entityType, entityName: spec.entityName, jsonPath: spec.jsonPath, previousValue: redactedPrevious, currentValue: redactedCurrent } as JsonObject)),
        category: spec.category,
        entityType: spec.entityType,
        entityName: redactMetadataText(spec.entityName, 512),
        ...(spec.jsonPath ? { jsonPath: spec.jsonPath } : {}),
        ...(redactedPrevious === undefined ? {} : { previousValue: redactedPrevious }),
        ...(redactedCurrent === undefined ? {} : { currentValue: redactedCurrent }),
        severity: spec.severity,
        riskScoreContribution: spec.score ?? scoreBySeverity[spec.severity],
        ruleId: spec.ruleId,
        explanation: redactString(spec.explanation),
        recommendedAction: redactString(spec.recommendedAction),
        evidence: spec.evidence.map((item) => String(redactValue(item))),
        confidence: spec.confidence ?? 'high',
    };
}

export function diffSnapshots(previous: NormalizedSnapshot, current: NormalizedSnapshot): Change[] {
    const changes: Change[] = [];
    diffServer(previous, current, changes);
    diffTools(previous.tools, current.tools, changes);
    diffResources(previous.resources, current.resources, changes);
    diffPrompts(previous.prompts, current.prompts, changes);
    diffPackages(previous, current, changes);
    return changes.sort((left, right) => left.id.localeCompare(right.id));
}

function diffServer(previous: NormalizedSnapshot, current: NormalizedSnapshot, changes: Change[]): void {
    const fields: Array<[keyof NormalizedSnapshot['server'], string, Severity, string, string]> = [
        ['name', 'SERVER_NAME_CHANGED', 'high', 'Server name changed.', 'Verify the server identity before approving this change.'],
        ['identity', 'SERVER_IDENTITY_CHANGED', 'critical', 'Server identity changed.', 'Verify the expected server identity and origin before approval.'],
        ['origin', 'SERVER_ORIGIN_CHANGED', 'critical', 'Server origin changed.', 'Investigate the redirect or configuration change before updating the baseline.'],
        ['version', 'SERVER_VERSION_CHANGED', 'low', 'Server version changed without an automatic security conclusion.', 'Review release notes and related schema changes.'],
        ['protocolVersion', 'PROTOCOL_VERSION_CHANGED', 'medium', 'MCP protocol version changed.', 'Review protocol compatibility and security behavior.'],
        ['contentType', 'CONTENT_TYPE_CHANGED', 'medium', 'Metadata response content type changed.', 'Confirm the endpoint still exposes the expected MCP metadata.'],
    ];
    for (const [field, ruleId, severity, explanation, action] of fields) {
        const prior = previous.server[field] as JsonValue | undefined;
        const now = current.server[field] as JsonValue | undefined;
        if (!jsonEqual(prior, now)) changes.push(createChange({ category: 'server', entityType: 'server', entityName: current.server.name, jsonPath: `/server/${field}`, previousValue: prior, currentValue: now, severity, ruleId, explanation, recommendedAction: action, evidence: [`${String(prior)} -> ${String(now)}`] }));
    }
    const removedCapabilities = previous.server.capabilities.filter((entry) => !current.server.capabilities.includes(entry));
    const addedCapabilities = current.server.capabilities.filter((entry) => !previous.server.capabilities.includes(entry));
    for (const capability of addedCapabilities) changes.push(createChange({ category: 'capability', entityType: 'server', entityName: current.server.name, jsonPath: '/server/capabilities', currentValue: capability, severity: sensitive(capability) ? 'critical' : 'medium', ruleId: sensitive(capability) ? 'SENSITIVE_CAPABILITY_INTRODUCED' : 'CAPABILITY_ADDED', explanation: `Capability added: ${capability}.`, recommendedAction: 'Review the new capability and least-privilege implications.', evidence: [capability] }));
    for (const capability of removedCapabilities) changes.push(createChange({ category: 'capability', entityType: 'server', entityName: current.server.name, jsonPath: '/server/capabilities', previousValue: capability, severity: 'low', ruleId: 'CAPABILITY_REMOVED', explanation: `Capability removed: ${capability}.`, recommendedAction: 'Confirm the removal is expected.', evidence: [capability] }));
    diffAuth(previous.server.authentication, current.server.authentication, current.server.name, changes);
    diffTls(previous, current, changes);
}

function diffTls(previous: NormalizedSnapshot, current: NormalizedSnapshot, changes: Change[]): void {
    const prior = previous.tls;
    const now = current.tls;
    const fields = ['protocol', 'validFrom', 'validTo', 'authorized', 'authorizationError', 'subject', 'issuer', 'hostname'] as const;
    for (const field of fields) {
        if (!jsonEqual(prior?.[field] as JsonValue | undefined, now?.[field] as JsonValue | undefined)) changes.push(createChange({
            category: 'tls', entityType: 'tls', entityName: now?.hostname ?? prior?.hostname ?? current.server.origin,
            jsonPath: `/tls/${field}`, previousValue: prior?.[field] as JsonValue | undefined, currentValue: now?.[field] as JsonValue | undefined,
            severity: field === 'authorized' || field === 'subject' || field === 'issuer' || field === 'hostname' ? 'high' : 'medium',
            ruleId: 'TLS_METADATA_CHANGED', explanation: `TLS ${field} changed.`, recommendedAction: 'Verify the certificate and endpoint identity before approving the baseline.', evidence: [field],
        }));
    }
}

function diffAuth(previous: AuthMetadata, current: AuthMetadata, serverName: string, changes: Change[]): void {
    if (jsonEqual(previous as unknown as JsonValue, current as unknown as JsonValue)) return;
    const authRemoved = previous.required === true && current.required === false;
    changes.push(createChange({ category: 'authentication', entityType: 'server', entityName: serverName, jsonPath: '/server/authentication', previousValue: previous as unknown as JsonValue, currentValue: current as unknown as JsonValue, severity: authRemoved ? 'critical' : 'high', ruleId: authRemoved ? 'AUTHORIZATION_REMOVED' : 'AUTHENTICATION_CHANGED', explanation: authRemoved ? 'Authentication appears to have been removed from a previously protected server.' : 'Authentication, scopes, permissions, or declared access capability changed.', recommendedAction: 'Verify authorization requirements and least-privilege scopes before approving.', evidence: [stableStringify(previous as unknown as JsonValue), stableStringify(current as unknown as JsonValue)] }));
}

function diffTools(previous: ToolDefinition[], current: ToolDefinition[], changes: Change[]): void {
    const previousByName = new Map(previous.map((tool) => [tool.name, tool]));
    const currentByName = new Map(current.map((tool) => [tool.name, tool]));
    const removed = previous.filter((tool) => !currentByName.has(tool.name));
    const added = current.filter((tool) => !previousByName.has(tool.name));
    const pairedAdded = new Set<string>();
    const pairedRemoved = new Set<string>();
    for (const prior of removed) {
        const renamed = added.find((next) => !pairedAdded.has(next.name) && toolFingerprint(prior) === toolFingerprint(next));
        if (renamed) {
            pairedRemoved.add(prior.name); pairedAdded.add(renamed.name);
            changes.push(createChange({ category: 'tool', entityType: 'tool', entityName: renamed.name, jsonPath: '/tools', previousValue: prior.name, currentValue: renamed.name, severity: 'high', ruleId: 'TOOL_RENAMED', explanation: `Tool appears to have been renamed from ${prior.name} to ${renamed.name}.`, recommendedAction: 'Review caller compatibility and confirm the rename was intentional.', evidence: [prior.name, renamed.name] }));
        }
    }
    for (const tool of added.filter((entry) => !pairedAdded.has(entry.name))) {
        changes.push(createChange({ category: 'tool', entityType: 'tool', entityName: tool.name, jsonPath: `/tools/${escapePath(tool.name)}`, currentValue: tool as unknown as JsonValue, severity: 'medium', ruleId: 'TOOL_ADDED', explanation: `New tool exposed: ${tool.name}.`, recommendedAction: 'Review the tool definition and approve only if needed.', evidence: [tool.name] }));
        addDescriptionRisks(tool, changes, true);
        const shadow = current.find((other) => other.name !== tool.name && other.name.toLocaleLowerCase() === tool.name.toLocaleLowerCase());
        if (shadow) changes.push(createChange({ category: 'tool', entityType: 'tool', entityName: tool.name, severity: 'high', ruleId: 'TOOL_SHADOWS_OTHER', explanation: `Tool ${tool.name} differs only by case from ${shadow.name}, which may shadow callers.`, recommendedAction: 'Resolve ambiguous tool names before trusting the update.', evidence: [tool.name, shadow.name] }));
    }
    for (const tool of removed.filter((entry) => !pairedRemoved.has(entry.name))) changes.push(createChange({ category: 'tool', entityType: 'tool', entityName: tool.name, jsonPath: `/tools/${escapePath(tool.name)}`, previousValue: tool as unknown as JsonValue, severity: 'high', ruleId: 'TOOL_REMOVED', explanation: `Previously trusted tool was removed: ${tool.name}.`, recommendedAction: 'Confirm the removal and review dependent integrations.', evidence: [tool.name] }));
    for (const [name, prior] of previousByName) {
        const now = currentByName.get(name);
        if (!now) continue;
        if (prior.description !== now.description) {
            changes.push(createChange({ category: 'tool_description', entityType: 'tool', entityName: name, jsonPath: `/tools/${escapePath(name)}/description`, previousValue: prior.description, currentValue: now.description, severity: 'medium', ruleId: 'TOOL_DESCRIPTION_CHANGED', explanation: `Tool description changed for ${name}.`, recommendedAction: 'Review wording for changed permissions or data handling.', evidence: [prior.description, now.description] }));
            addDescriptionRisks(now, changes, false);
        }
        diffInputSchema(name, prior.inputSchema, now.inputSchema, changes);
        if (!jsonEqual(prior.outputSchema, now.outputSchema)) changes.push(createChange({ category: 'output_schema', entityType: 'tool', entityName: name, jsonPath: `/tools/${escapePath(name)}/outputSchema`, previousValue: prior.outputSchema, currentValue: now.outputSchema, severity: 'medium', ruleId: 'OUTPUT_SCHEMA_CHANGED', explanation: `Output schema changed for ${name}.`, recommendedAction: 'Review consumers for changed output contracts and exposed data.', evidence: ['Output schema differs'] }));
        if (!jsonEqual(prior.annotations, now.annotations)) changes.push(createChange({ category: 'tool_annotations', entityType: 'tool', entityName: name, jsonPath: `/tools/${escapePath(name)}/annotations`, previousValue: prior.annotations, currentValue: now.annotations, severity: 'medium', ruleId: 'TOOL_CAPABILITY_ANNOTATIONS_CHANGED', explanation: `Tool annotations changed for ${name}.`, recommendedAction: 'Review declared behavior and capability annotations.', evidence: ['Annotations differ'] }));
    }
}

function addDescriptionRisks(tool: ToolDefinition, changes: Change[], added: boolean): void {
    for (const rule of findDescriptionRisks(tool.description)) changes.push(createChange({ category: 'suspicious_description', entityType: 'tool', entityName: tool.name, jsonPath: `/tools/${escapePath(tool.name)}/description`, currentValue: tool.description, severity: rule.severity, ruleId: rule.id, explanation: `${added ? 'New tool' : 'Changed tool description'}: ${rule.explanation}`, recommendedAction: rule.action, evidence: [tool.description], score: rule.score }));
}

function addPromptRisks(prompt: PromptDefinition, changes: Change[], added: boolean): void {
    const text = `${prompt.description ?? ''}\n${prompt.text ?? ''}`.trim();
    for (const rule of findDescriptionRisks(text)) changes.push(createChange({ category: 'suspicious_prompt', entityType: 'prompt', entityName: prompt.name, currentValue: text, severity: rule.severity, ruleId: rule.id, explanation: `${added ? 'New prompt' : 'Changed prompt'}: ${rule.explanation}`, recommendedAction: rule.action, evidence: [text], score: rule.score }));
}

function diffInputSchema(toolName: string, previous: JsonObject, current: JsonObject, changes: Change[]): void {
    const priorProperties = objectAt(previous, 'properties');
    const currentProperties = objectAt(current, 'properties');
    const priorRequired = stringSet(previous.required);
    const currentRequired = stringSet(current.required);
    for (const name of Object.keys(currentProperties)) {
        if (!Object.hasOwn(priorProperties, name)) {
            const required = currentRequired.has(name);
            changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(name)}`, currentValue: currentProperties[name], severity: required ? 'high' : 'medium', ruleId: required ? 'REQUIRED_PARAMETER_ADDED' : 'OPTIONAL_PARAMETER_ADDED', explanation: `${required ? 'Required' : 'Optional'} input parameter added: ${name}.`, recommendedAction: 'Review API compatibility and whether the new input broadens access.', evidence: [name] }));
        }
    }
    for (const name of Object.keys(priorProperties)) if (!Object.hasOwn(currentProperties, name)) changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(name)}`, previousValue: priorProperties[name], severity: 'high', ruleId: 'PARAMETER_REMOVED', explanation: `Input parameter removed: ${name}.`, recommendedAction: 'Review caller compatibility and validate that controls were not removed.', evidence: [name] }));
    for (const name of Object.keys(currentProperties)) {
        if (!Object.hasOwn(priorProperties, name)) continue;
        const prior = asObject(priorProperties[name]); const now = asObject(currentProperties[name]);
        if (!jsonEqual(prior.type, now.type)) changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(name)}/type`, previousValue: prior.type, currentValue: now.type, severity: 'high', ruleId: 'PARAMETER_TYPE_CHANGED', explanation: `Input parameter type changed: ${name}.`, recommendedAction: 'Review validation and security implications before approval.', evidence: [name] }));
        if (!jsonEqual(prior.enum, now.enum)) {
            const priorValues = stringSet(prior.enum); const nowValues = stringSet(now.enum);
            const restricted = [...priorValues].some((entry) => !nowValues.has(entry));
            changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(name)}/enum`, previousValue: prior.enum, currentValue: now.enum, severity: restricted ? 'high' : 'medium', ruleId: restricted ? 'PARAMETER_ENUM_RESTRICTED' : 'PARAMETER_ENUM_EXPANDED', explanation: `Allowed enum values ${restricted ? 'were restricted' : 'were expanded'} for ${name}.`, recommendedAction: 'Review accepted input scope and caller compatibility.', evidence: [name] }));
        }
        if (!jsonEqual(prior.default, now.default)) changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(name)}/default`, previousValue: prior.default, currentValue: now.default, severity: 'low', ruleId: 'PARAMETER_DEFAULT_CHANGED', explanation: `Default value changed for ${name}.`, recommendedAction: 'Confirm the new default does not expand sensitive behavior.', evidence: [name] }));
        diffConstraints(toolName, name, prior, now, changes);
    }
    for (const name of currentRequired) if (!priorRequired.has(name) && Object.hasOwn(priorProperties, name)) changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/required`, currentValue: name, severity: 'high', ruleId: 'EXISTING_PARAMETER_NOW_REQUIRED', explanation: `Existing parameter became required: ${name}.`, recommendedAction: 'Review compatibility and required data collection.', evidence: [name] }));
    for (const name of priorRequired) if (!currentRequired.has(name) && Object.hasOwn(currentProperties, name)) changes.push(createChange({ category: 'input_schema_constraint', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/required`, previousValue: name, severity: 'medium', ruleId: 'PARAMETER_NO_LONGER_REQUIRED', explanation: `Required-input constraint was removed for ${name}.`, recommendedAction: 'Review whether relaxing this validation changes authorization or safety assumptions.', evidence: [name] }));
    diffAdditionalProperties(toolName, undefined, previous, current, changes);
    if (!jsonEqual(previous, current)) changes.push(createChange({ category: 'input_schema', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema`, previousValue: previous, currentValue: current, severity: 'medium', ruleId: 'INPUT_SCHEMA_CHANGED', explanation: `Input schema changed for ${toolName}, including nested or object-level constraints.`, recommendedAction: 'Review the complete schema change for validation and access-scope impact.', evidence: ['Canonical input schema differs'] }));
}

function diffConstraints(toolName: string, parameter: string, previous: JsonObject, current: JsonObject, changes: Change[]): void {
    const limits: Array<[string, 'min' | 'max']> = [['minimum', 'min'], ['minLength', 'min'], ['minItems', 'min'], ['maximum', 'max'], ['maxLength', 'max'], ['maxItems', 'max']];
    for (const [field, direction] of limits) {
        if (jsonEqual(previous[field], current[field])) continue;
        const prior = previous[field]; const now = current[field];
        let weakened = false;
        if (typeof prior === 'number' && typeof now === 'number') weakened = direction === 'min' ? now < prior : now > prior;
        else weakened = now === undefined;
        changes.push(createChange({ category: 'input_schema_constraint', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(parameter)}/${field}`, previousValue: prior, currentValue: now, severity: weakened ? 'medium' : 'low', ruleId: weakened ? 'INPUT_CONSTRAINT_WEAKENED' : 'INPUT_CONSTRAINT_STRENGTHENED', explanation: `Input constraint ${field} was ${weakened ? 'weakened' : 'strengthened'} for ${parameter}.`, recommendedAction: 'Review validation scope and compatibility.', evidence: [parameter, field] }));
    }
    if (!jsonEqual(previous.pattern, current.pattern)) changes.push(createChange({ category: 'input_schema_constraint', entityType: 'tool', entityName: toolName, jsonPath: `/tools/${escapePath(toolName)}/inputSchema/properties/${escapePath(parameter)}/pattern`, previousValue: previous.pattern, currentValue: current.pattern, severity: 'medium', ruleId: 'INPUT_PATTERN_CHANGED', explanation: `Input regex pattern changed for ${parameter}; arbitrary pattern changes cannot be classified as stronger or weaker automatically.`, recommendedAction: 'Review the complete regular expression and accepted input set.', evidence: [parameter, 'pattern'] }));
    diffAdditionalProperties(toolName, parameter, previous, current, changes);
}

function diffAdditionalProperties(toolName: string, parameter: string | undefined, previous: JsonObject, current: JsonObject, changes: Change[]): void {
    if (jsonEqual(previous.additionalProperties, current.additionalProperties)) return;
    const enabled = previous.additionalProperties === false && current.additionalProperties === true;
    const basePath = `/tools/${escapePath(toolName)}/inputSchema${parameter ? `/properties/${escapePath(parameter)}` : ''}/additionalProperties`;
    changes.push(createChange({ category: 'input_schema_constraint', entityType: 'tool', entityName: toolName, jsonPath: basePath, previousValue: previous.additionalProperties, currentValue: current.additionalProperties, severity: enabled ? 'high' : 'medium', ruleId: enabled ? 'ADDITIONAL_PROPERTIES_ENABLED' : 'ADDITIONAL_PROPERTIES_CHANGED', explanation: enabled ? 'additionalProperties changed from false to true, weakening object validation.' : 'The additionalProperties policy changed; review the resulting accepted object shape.', recommendedAction: 'Review whether undeclared fields can expand behavior or bypass validation.', evidence: [parameter ?? 'root', 'additionalProperties'] }));
}

function diffResources(previous: ResourceDefinition[], current: ResourceDefinition[], changes: Change[]): void {
    diffNamed(previous, current, 'resource', changes, (resource) => stableStringify(resource as unknown as JsonValue));
}
function diffPrompts(previous: PromptDefinition[], current: PromptDefinition[], changes: Change[]): void {
    diffNamed(previous, current, 'prompt', changes, (prompt) => stableStringify(prompt as unknown as JsonValue));
}
function diffNamed<T extends { name: string }>(previous: T[], current: T[], type: 'resource' | 'prompt', changes: Change[], stringify: (value: T) => string): void {
    const priorMap = new Map(previous.map((entry) => [entry.name, entry])); const currentMap = new Map(current.map((entry) => [entry.name, entry]));
    for (const item of current) if (!priorMap.has(item.name)) {
        changes.push(createChange({ category: type, entityType: type, entityName: item.name, currentValue: item as unknown as JsonValue, severity: 'medium', ruleId: `${type.toUpperCase()}_ADDED`, explanation: `New ${type} exposed: ${item.name}.`, recommendedAction: `Review the new ${type} before approving the baseline.`, evidence: [item.name] }));
        if (type === 'prompt') addPromptRisks(item as PromptDefinition, changes, true);
    }
    for (const item of previous) if (!currentMap.has(item.name)) changes.push(createChange({ category: type, entityType: type, entityName: item.name, previousValue: item as unknown as JsonValue, severity: 'medium', ruleId: `${type.toUpperCase()}_REMOVED`, explanation: `Previously trusted ${type} removed: ${item.name}.`, recommendedAction: `Confirm the ${type} removal is expected.`, evidence: [item.name] }));
    for (const item of current) {
        const prior = priorMap.get(item.name);
        if (prior && stringify(prior) !== stringify(item)) {
            changes.push(createChange({ category: type, entityType: type, entityName: item.name, previousValue: prior as unknown as JsonValue, currentValue: item as unknown as JsonValue, severity: type === 'prompt' ? 'high' : 'medium', ruleId: type === 'prompt' ? 'PROMPT_TEXT_CHANGED' : 'RESOURCE_DEFINITION_CHANGED', explanation: `${type === 'prompt' ? 'Prompt text or arguments materially changed' : 'Resource URI pattern or metadata changed'}: ${item.name}.`, recommendedAction: `Review the changed ${type} definition for data-access impact.`, evidence: [item.name] }));
            if (type === 'prompt') addPromptRisks(item as PromptDefinition, changes, false);
        }
    }
}

function diffPackages(previous: NormalizedSnapshot, current: NormalizedSnapshot, changes: Change[]): void {
    const prior = new Map(previous.packages.map((item) => [`${item.ecosystem ?? ''}:${item.name}`, item]));
    const now = new Map(current.packages.map((item) => [`${item.ecosystem ?? ''}:${item.name}`, item]));
    for (const item of current.packages) {
        const old = prior.get(`${item.ecosystem ?? ''}:${item.name}`);
        if (!old) changes.push(createChange({ category: 'package', entityType: 'package', entityName: item.name, currentValue: item as unknown as JsonValue, severity: 'medium', ruleId: 'PACKAGE_ADDED', explanation: `Referenced package was added: ${item.name}@${item.version}.`, recommendedAction: 'Verify package identity and review vulnerability results.', evidence: [item.name, item.version] }));
        else if (old.version !== item.version) changes.push(createChange({ category: 'package', entityType: 'package', entityName: item.name, previousValue: old.version, currentValue: item.version, severity: 'low', ruleId: 'PACKAGE_VERSION_CHANGED', explanation: `Referenced package version changed: ${item.name}.`, recommendedAction: 'Review release notes and vulnerability results.', evidence: [old.version, item.version] }));
    }
    for (const item of previous.packages) if (!now.has(`${item.ecosystem ?? ''}:${item.name}`)) changes.push(createChange({ category: 'package', entityType: 'package', entityName: item.name, previousValue: item as unknown as JsonValue, severity: 'medium', ruleId: 'PACKAGE_REMOVED', explanation: `Referenced package was removed: ${item.name}@${item.version}.`, recommendedAction: 'Confirm the package metadata removal is expected.', evidence: [item.name, item.version] }));
}

function objectAt(value: JsonObject, key: string): JsonObject { return asObject(value[key]); }
function asObject(value: JsonValue | undefined): JsonObject { return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {}; }
function stringSet(value: JsonValue | undefined): Set<string> { return new Set(Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []); }
function sensitive(capability: string): boolean { return /filesystem|secret|credential|email|message|payment|transfer|delete|shell|command|admin/i.test(capability); }
function escapePath(value: string): string { return value.replace(/~/g, '~0').replace(/\//g, '~1'); }
