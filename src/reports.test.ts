import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { resolve } from 'node:path';
import { buildExecutiveSummary, CSV_REPORT_CONTENT_TYPE, gateDecision, generateCsvReport, generateMarkdownReport, MARKDOWN_REPORT_CONTENT_TYPE } from './reports.js';
import type { Report } from './types.js';

function report(overrides: Partial<Report> = {}): Report {
    return {
        serverName: 'Production MCP',
        serverUrl: 'https://mcp.example.com/mcp',
        status: 'success_no_change',
        reachable: true,
        transport: 'streamable_http',
        baselineFound: true,
        overallSeverity: 'informational',
        riskScore: 0,
        changeCount: 0,
        changesBySeverity: { informational: 0, low: 0, medium: 0, high: 0, critical: 0 },
        changes: [],
        vulnerabilities: [],
        recommendedAction: 'Continue monitoring.',
        baselineUpdated: false,
        candidateBaselineStored: false,
        inspectedAt: '2026-10-11T00:00:00.000Z',
        checkedAt: '2026-10-11T00:00:00.000Z',
        ...overrides,
    };
}

test('trust gate allows only a verified unchanged baseline', () => {
    assert.equal(gateDecision(report()), 'ALLOW');
    assert.equal(gateDecision(report({ status: 'baseline_missing', baselineFound: false })), 'REVIEW');
    assert.equal(gateDecision(report({ status: 'success_changed', overallSeverity: 'high', riskScore: 70, changeCount: 1 })), 'BLOCK');
});

test('executive summary selects the strictest decision', () => {
    const summary = buildExecutiveSummary([
        report(),
        report({ serverName: 'Needs review', status: 'baseline_missing', baselineFound: false }),
        report({ serverName: 'Blocked', status: 'success_changed', overallSeverity: 'critical', riskScore: 100, changeCount: 1 }),
    ], '2026-10-11T00:00:00.000Z');
    assert.equal(summary.decision, 'BLOCK');
    assert.deepEqual(summary.decisions, { ALLOW: 1, REVIEW: 1, BLOCK: 1 });
    assert.equal(summary.maximumRiskScore, 100);
});

test('CSV evidence report is formula-safe and preserves quotes', () => {
    const csv = generateCsvReport([report({
        serverName: '=HYPERLINK("https://evil.example")',
        recommendedAction: '+review "carefully"',
    })]);
    assert.equal(csv.includes('"\'=HYPERLINK(""https://evil.example"")"'), true);
    assert.equal(csv.includes('"\'+review ""carefully"""'), true);
});

test('Markdown report contains decisions and removes raw HTML markers', () => {
    const reports = [report({ serverName: '<script>alert(1)</script>' })];
    const markdown = generateMarkdownReport(buildExecutiveSummary(reports), reports);
    assert.equal(markdown.includes('Decision: ALLOW'), true);
    assert.equal(markdown.includes('<script>'), false);
});

test('report MIME types match the Apify key-value store schema', () => {
    const schema = JSON.parse(readFileSync(resolve('.actor/key_value_store_schema.json'), 'utf8')) as {
        collections: { markdownReport: { contentTypes: string[] }; csvReport: { contentTypes: string[] } };
    };
    assert.equal(schema.collections.markdownReport.contentTypes.includes(MARKDOWN_REPORT_CONTENT_TYPE), true);
    assert.equal(schema.collections.csvReport.contentTypes.includes(CSV_REPORT_CONTENT_TYPE), true);
});

test('Actor input schema excludes removed Apify pattern keywords', () => {
    const inputSchema = readFileSync(resolve('INPUT_SCHEMA.json'), 'utf8');
    assert.equal(inputSchema.includes('"patternKey"'), false);
    assert.equal(inputSchema.includes('"patternValue"'), false);
});
