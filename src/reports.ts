import type { Report, Severity } from './types.js';

export type GateDecision = 'ALLOW' | 'REVIEW' | 'BLOCK';

export interface ExecutiveSummary {
    generatedAt: string;
    decision: GateDecision;
    servers: number;
    reachable: number;
    changed: number;
    baselineMissing: number;
    failed: number;
    maximumRiskScore: number;
    overallSeverity: Severity;
    decisions: Record<GateDecision, number>;
    artifacts?: {
        datasetId: string;
        jsonSummaryUrl: string;
        markdownReportUrl?: string;
        csvReportUrl?: string;
    };
}

export const MARKDOWN_REPORT_CONTENT_TYPE = 'text/markdown';
export const CSV_REPORT_CONTENT_TYPE = 'text/csv';

const severityRank: Record<Severity, number> = {
    informational: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};

export function gateDecision(report: Report): GateDecision {
    if (report.overallSeverity === 'high' || report.overallSeverity === 'critical' || report.riskScore >= 60) return 'BLOCK';
    if (report.status === 'success_no_change'
        && report.reachable
        && report.baselineFound
        && report.changeCount === 0
        && !report.error) return 'ALLOW';
    return 'REVIEW';
}

export function buildExecutiveSummary(reports: readonly Report[], generatedAt = new Date().toISOString()): ExecutiveSummary {
    const decisions: Record<GateDecision, number> = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };
    let overallSeverity: Severity = 'informational';
    let maximumRiskScore = 0;
    for (const report of reports) {
        decisions[gateDecision(report)] += 1;
        if (severityRank[report.overallSeverity] > severityRank[overallSeverity]) overallSeverity = report.overallSeverity;
        maximumRiskScore = Math.max(maximumRiskScore, report.riskScore);
    }
    const decision: GateDecision = decisions.BLOCK > 0 ? 'BLOCK' : decisions.REVIEW > 0 ? 'REVIEW' : 'ALLOW';
    return {
        generatedAt,
        decision,
        servers: reports.length,
        reachable: reports.filter((report) => report.reachable).length,
        changed: reports.filter((report) => report.status === 'success_changed' || report.changeCount > 0).length,
        baselineMissing: reports.filter((report) => report.status === 'baseline_missing').length,
        failed: reports.filter((report) => !report.reachable || Boolean(report.error)).length,
        maximumRiskScore,
        overallSeverity,
        decisions,
    };
}

export function generateMarkdownReport(summary: ExecutiveSummary, reports: readonly Report[]): string {
    const rows = reports.map((report) => [
        gateDecision(report),
        markdownCell(report.serverName),
        markdownCell(report.status),
        markdownCell(report.overallSeverity),
        String(report.riskScore),
        String(report.changeCount),
        report.baselineFound ? 'yes' : 'no',
        markdownCell(report.recommendedAction),
    ].join(' | '));
    const findings = reports.flatMap((report) => report.changes.slice(0, 5).map((change) =>
        `- **${markdownText(report.serverName)} — ${markdownText(change.ruleId)} (${change.severity}):** ${markdownText(change.explanation)} Action: ${markdownText(change.recommendedAction)}`));
    return `# MCP Security Gate Report

**Decision: ${summary.decision}**  
Generated: ${summary.generatedAt}  
Servers: ${summary.servers} | Reachable: ${summary.reachable} | Changed: ${summary.changed} | Failed: ${summary.failed}  
Verdicts: ${summary.decisions.ALLOW} ALLOW | ${summary.decisions.REVIEW} REVIEW | ${summary.decisions.BLOCK} BLOCK  
Maximum risk score: ${summary.maximumRiskScore}/100 | Highest severity: ${summary.overallSeverity}

## Server decisions

Decision | Server | Status | Severity | Risk | Changes | Baseline | Recommended action
--- | --- | --- | --- | ---: | ---: | --- | ---
${rows.join('\n')}

## Priority findings

${findings.length ? findings.join('\n') : '- No classified changes were reported.'}

> Decision-support only. Review evidence and organizational policy before trusting, blocking, or changing an MCP server.
`;
}

export function generateCsvReport(reports: readonly Report[]): string {
    const header = [
        'decision', 'serverName', 'serverUrl', 'status', 'severity', 'riskScore', 'baselineFound',
        'ruleId', 'category', 'entityType', 'entityName', 'explanation', 'recommendedAction', 'confidence', 'inspectedAt',
    ];
    const rows: string[] = [];
    for (const report of reports) {
        const changes = report.changes.length ? report.changes : [undefined];
        for (const change of changes) {
            rows.push([
                gateDecision(report), report.serverName, report.serverUrl, report.status, report.overallSeverity,
                report.riskScore, report.baselineFound, change?.ruleId, change?.category, change?.entityType,
                change?.entityName, change?.explanation, change?.recommendedAction ?? report.recommendedAction,
                change?.confidence, report.inspectedAt,
            ].map(csvCell).join(','));
        }
    }
    return `${header.join(',')}\n${rows.join('\n')}${rows.length ? '\n' : ''}`;
}

function csvCell(value: unknown): string {
    let text = String(value ?? '').replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    if (/^\s*[=+@-]/.test(text)) text = `'${text}`;
    return `"${text.replaceAll('"', '""')}"`;
}

function markdownCell(value: unknown): string {
    return markdownText(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function markdownText(value: unknown): string {
    return String(value ?? '').replaceAll('\r\n', '\n').replaceAll('\r', '\n').replace(/[<>]/g, '');
}
