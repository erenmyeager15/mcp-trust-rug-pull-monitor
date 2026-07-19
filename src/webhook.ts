import { safeFetch } from './network.js';
import { redactString, redactUrl, redactValue } from './redaction.js';
import { assertSafeTarget } from './safety.js';
import type { Change, Report, Severity } from './types.js';

export interface WebhookResult { attempted: boolean; delivered: boolean; status?: number; error?: string; }
export interface WebhookDependencies {
    validateTarget?: (url: string) => Promise<unknown>;
    request?: typeof safeFetch;
}
const severityRank: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

export async function deliverWebhook(webhookUrl: string, report: Report, runUrl: string | undefined, timeoutMs: number, dependencies: WebhookDependencies = {}): Promise<WebhookResult> {
    try {
        await (dependencies.validateTarget ?? ((url: string) => assertSafeTarget(url, false)))(webhookUrl);
        const topChanges = report.changes
            .filter((change) => severityRank[change.severity] >= severityRank.medium)
            .sort(compareChanges)
            .slice(0, 5)
            .map((change) => ({ id: change.id, severity: change.severity, ruleId: change.ruleId, explanation: change.explanation, recommendedAction: change.recommendedAction }));
        const payload = redactValue({
            type: 'mcp-trust-monitor.alert',
            actorRunUrl: runUrl ? redactUrl(runUrl) : undefined,
            server: { name: report.serverName, url: redactUrl(report.serverUrl) },
            overallSeverity: report.overallSeverity,
            riskScore: report.riskScore,
            status: report.status,
            changeCount: report.changeCount,
            topChanges,
            timestamp: report.checkedAt,
        }) as object;
        const response = await (dependencies.request ?? safeFetch)(webhookUrl, { method: 'POST', body: JSON.stringify(payload), headers: { 'content-type': 'application/json', 'user-agent': 'Apify-MCP-Trust-Monitor/1.0' }, timeoutMs, maxResponseBytes: 65_536, allowHttp: false });
        return response.status >= 200 && response.status < 300
            ? { attempted: true, delivered: true, status: response.status }
            : { attempted: true, delivered: false, status: response.status, error: `Webhook returned HTTP ${response.status}` };
    } catch (error) {
        return { attempted: true, delivered: false, error: redactString(error instanceof Error ? error.message : 'Webhook delivery failed') };
    }
}

function compareChanges(left: Change, right: Change): number {
    return severityRank[right.severity] - severityRank[left.severity]
        || right.riskScoreContribution - left.riskScoreContribution
        || left.id.localeCompare(right.id);
}
