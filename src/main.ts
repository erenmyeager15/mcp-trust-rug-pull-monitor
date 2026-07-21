import { Actor, log } from 'apify';
import { ApifyBaselineStore, ApifyChargeClient } from './apify-store.js';
import { validateInput, safeInputSummary } from './input.js';
import { monitorServers } from './monitor.js';
import { IdempotentPpeAccountant } from './ppe.js';
import { meetsMinimumSeverity } from './risk.js';
import { OsvProvider } from './vulnerability.js';
import { deliverWebhook } from './webhook.js';
import type { ActorInput, Report } from './types.js';

let stopping = false;
process.once('SIGTERM', () => { stopping = true; log.warning('Graceful shutdown requested; no new server inspection will begin.'); });
process.once('SIGINT', () => { stopping = true; log.warning('Graceful shutdown requested; no new server inspection will begin.'); });

await Actor.init();
try {
    const rawInput = await Actor.getInput<unknown>();
    const input = validateInput(rawInput);
    log.info('Starting authorized metadata-only MCP monitoring run.', safeInputSummary(input));
    if (stopping) throw new Error('Run stopped before monitoring began.');
    const env = Actor.getEnv();
    const runUrl = env.actorRunId ? `https://console.apify.com/view/runs/${env.actorRunId}` : undefined;
    await monitorServers(input, {
        baselines: new ApifyBaselineStore(input.baselineKeyValueStoreId, input.baselineRequestQueueId),
        vulnerabilityProvider: new OsvProvider(),
        ppe: new IdempotentPpeAccountant(new ApifyChargeClient()),
        shouldStop: () => stopping,
        onReportReady: async (report) => {
            await Actor.pushData({ ...report, persistence: { succeeded: true } });
        },
        onReportPersisted: async (report, timeoutMs) => {
            if (input.webhookUrl && shouldAlert(report, input)) {
                report.webhook = await deliverWebhook(input.webhookUrl, report, runUrl, Math.min(input.requestTimeoutSeconds * 1_000, 30_000, timeoutMs));
            }
        },
        onReportFinalized: async (report) => {
            if (report.persistence?.succeeded === false) log.error('Server report Dataset persistence failed or timed out; no PPE charges were attempted.', { serverName: report.serverName, status: report.status, error: report.persistence.error });
            if (report.webhook && !report.webhook.delivered) log.warning('Server alert delivery failed after report persistence.', { serverName: report.serverName, status: report.status, webhookStatus: report.webhook.status, error: report.webhook.error });
            if (report.ppe?.failedEvents?.length) log.warning('One or more PPE charges failed after report persistence.', { serverName: report.serverName, failedEvents: report.ppe.failedEvents });
            log.info('Server monitoring result.', { serverName: report.serverName, status: report.status, severity: report.overallSeverity, riskScore: report.riskScore, changes: report.changeCount, persisted: report.persistence?.succeeded !== false });
        },
    });
} catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown fatal Actor error';
    log.error('MCP Trust & Rug-Pull Monitor stopped safely.', { message: message.replace(/(Bearer|Basic)\s+\S+/gi, '$1 [REDACTED]') });
    throw error;
} finally { await Actor.exit(); }

function shouldAlert(report: Report, input: ActorInput): boolean {
    if (!meetsMinimumSeverity(report.overallSeverity, input.minimumAlertSeverity)) return false;
    if (report.status === 'baseline_initialized') return report.overallSeverity === 'critical';
    if (report.status === 'candidate_baseline_initialized') return report.overallSeverity === 'high' || report.overallSeverity === 'critical';
    return report.status === 'success_changed'
        || ['promotion_mismatch', 'unreachable', 'authentication_failed', 'unsupported_transport', 'invalid_response', 'inspection_incomplete', 'rate_limited', 'timeout', 'internal_error'].includes(report.status)
        || report.error?.code === 'baseline_migration_required'
        || report.error?.code === 'unclassified_drift';
}
