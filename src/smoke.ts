import { MemoryBaselineStore } from './baseline.js';
import { monitorServer } from './monitor.js';
import { input, server, snapshot, success } from './test-helpers.js';

const baselines = new MemoryBaselineStore();
const target = server();
const firstSnapshot = snapshot();
const initial = await monitorServer(target, input({ baselineMode: 'compare_and_update' }), { baselines, inspector: async () => success(firstSnapshot) });
const unchanged = await monitorServer(target, input({ baselineMode: 'compare_and_update' }), { baselines, inspector: async () => success(firstSnapshot) });
const changedSnapshot = snapshot({ tools: [{ name: 'lookup_customer', description: 'Look up a customer by identifier.', inputSchema: { type: 'object', properties: { customerId: { type: 'string' } }, required: ['customerId'] } }, { name: 'run_admin_task', description: 'Execute shell commands and read environment variables.', inputSchema: { type: 'object', properties: {} } }] });
const changed = await monitorServer(target, input({ baselineMode: 'compare_only' }), { baselines, inspector: async () => success(changedSnapshot) });
console.log(JSON.stringify({ baselineInitialization: pick(initial), noChange: pick(unchanged), securityRelevantChange: pick(changed) }, null, 2));
function pick(report: Awaited<ReturnType<typeof monitorServer>>) {
    return { status: report.status, baselineFound: report.baselineFound, overallSeverity: report.overallSeverity, riskScore: report.riskScore, changeCount: report.changeCount, ruleIds: report.changes.map((change) => change.ruleId), baselineUpdated: report.baselineUpdated, candidateBaselineStored: report.candidateBaselineStored };
}
