import { randomUUID } from 'node:crypto';
import { baselineLeaseKey, candidateBaselineKey, createBaseline, endpointIdentityHash, trustedBaselineKey, usableBaseline } from './baseline.js';
import { MAX_SERVER_WALL_CLOCK_MS } from './constants.js';
import { createChange, diffSnapshots } from './diff.js';
import { inspectTls } from './network.js';
import { IdempotentPpeAccountant } from './ppe.js';
import { snapshotHash } from './normalize.js';
import { redactMetadataText, redactString, redactUrl } from './redaction.js';
import { summarizeRisk } from './risk.js';
import { inspectMcpServer } from './transport.js';
import type { ActorInput, BaselineLease, BaselineStore, Change, InspectionResult, NormalizedSnapshot, PromotionMismatchReason, Report, ServerInput, Severity, StoredBaseline, TlsMetadata, VulnerabilityLookupResult, VulnerabilityMatch } from './types.js';
import type { VulnerabilityProvider } from './vulnerability.js';

const BILLABLE_EVENTS = ['server-inspection', 'baseline-comparison', 'vulnerability-lookup', 'risk-report-generated'] as const;
type BillableEvent = typeof BILLABLE_EVENTS[number];
interface ChargePlan { key: string; events: BillableEvent[]; }
const chargePlans = new WeakMap<Report, ChargePlan>();
const BASELINE_LOCK_TTL_MS = MAX_SERVER_WALL_CLOCK_MS + 300_000;

export interface MonitorDependencies {
    baselines: BaselineStore;
    inspector?: (server: ServerInput, input: ActorInput, tls?: TlsMetadata) => Promise<InspectionResult>;
    tlsInspector?: (url: string, timeoutMs: number, allowHttp: boolean) => Promise<TlsMetadata>;
    vulnerabilityProvider?: VulnerabilityProvider;
    ppe?: IdempotentPpeAccountant;
    now?: () => Date;
    shouldStop?: () => boolean;
    onReportReady?: (report: Report) => Promise<void>;
    onReportPersisted?: (report: Report, timeoutMs: number) => Promise<void>;
    onReportFinalized?: (report: Report) => Promise<void>;
    deadlineAt?: number;
}

export async function monitorServer(server: ServerInput, input: ActorInput, dependencies: MonitorDependencies): Promise<Report> {
    const checkedAt = (dependencies.now?.() ?? new Date()).toISOString();
    const deadlineAt = dependencies.deadlineAt ?? serverDeadlineAt(input);
    const trustedKey = trustedBaselineKey(server.name, server.url);
    const candidateKey = candidateBaselineKey(server.name, server.url);
    const leaseKey = baselineLeaseKey(server.name, server.url);
    const identityHash = endpointIdentityHash(server.name, server.url);
    let tls: TlsMetadata | undefined;
    if (input.checkTls) {
        try {
            tls = sanitizeTls(await beforeDeadline(
                () => (dependencies.tlsInspector ?? inspectTls)(server.url, Math.min(input.requestTimeoutSeconds * 1_000, remaining(deadlineAt)), input.allowHttp),
                deadlineAt,
            ));
        } catch (error) {
            tls = { authorized: false, authorizationError: safeError(error, 'TLS inspection failed'), hostname: new URL(server.url).hostname };
        }
    }
    const inspector = dependencies.inspector ?? ((target, settings, tlsResult) => inspectMcpServer(target, {
        timeoutMs: settings.requestTimeoutSeconds * 1_000,
        maxResponseBytes: settings.maxResponseBytes,
        maxRetries: settings.maxRetries,
        allowHttp: settings.allowHttp,
        checkTls: settings.checkTls,
        deadlineAt,
        ...(tlsResult ? { tls: tlsResult } : {}),
    }));
    let inspected: InspectionResult;
    try { inspected = await beforeDeadline(() => inspector(server, input, tls), deadlineAt); }
    catch (error) {
        if (!(error instanceof ServerDeadlineError)) throw error;
        inspected = { ok: false, status: 'timeout', message: 'Per-server wall-clock deadline exceeded.', transport: server.transport, responseReceived: false };
    }
    if (!inspected.ok) {
        return failureReport(server, inspected, checkedAt, tls, await baselineExists(dependencies.baselines, trustedKey, deadlineAt));
    }
    const snapshot = inspected.snapshot;
    if (!hasMeaningfulMetadata(snapshot)) {
        return incompleteSnapshotReport(server, inspected, checkedAt, tls, await baselineExists(dependencies.baselines, trustedKey, deadlineAt));
    }
    const hash = snapshotHash(snapshot);
    const mutationRequested = !input.dryRun && (input.baselineMode !== 'compare_only' || input.promoteCandidateBaseline);
    let lease: BaselineLease | undefined;
    if (mutationRequested) {
        const proposed = { owner: randomUUID(), expiresAt: new Date(Date.now() + BASELINE_LOCK_TTL_MS).toISOString() };
        const acquisition = await settleByDeadline(() => dependencies.baselines.acquireLock(leaseKey, proposed), deadlineAt);
        if (acquisition.ok && acquisition.value) lease = acquisition.value;
        if (acquisition.timedOut && lease) {
            await releaseLease(dependencies.baselines, leaseKey, lease);
            lease = undefined;
        }
        if (!acquisition.ok || acquisition.timedOut || !lease) {
            return lockUnavailableReport(server, inspected, hash, checkedAt, tls, await baselineExists(dependencies.baselines, trustedKey, deadlineAt));
        }
    }

    try {
        return await monitorSnapshot({ server, input, dependencies, inspected, snapshot, hash, checkedAt, tls, trustedKey, candidateKey, leaseKey, lease, identityHash, deadlineAt });
    } catch (error) {
        const stored = await baselineExists(dependencies.baselines, trustedKey, deadlineAt);
        if (error instanceof LeaseLostError) return lockUnavailableReport(server, inspected, hash, checkedAt, tls, stored);
        if (error instanceof ServerDeadlineError) return deadlineExceededReport(server, inspected, hash, checkedAt, tls, stored);
        return internalErrorReport(server, safeError(error, 'Post-inspection monitoring failure'), stored, true, inspected);
    } finally {
        if (lease) await releaseLease(dependencies.baselines, leaseKey, lease);
    }
}

interface SnapshotContext {
    server: ServerInput; input: ActorInput; dependencies: MonitorDependencies; inspected: Extract<InspectionResult, { ok: true }>;
    snapshot: NormalizedSnapshot; hash: string; checkedAt: string; tls?: TlsMetadata; trustedKey: string; candidateKey: string;
    leaseKey: string; lease?: BaselineLease; identityHash: string; deadlineAt: number;
}

async function monitorSnapshot(context: SnapshotContext): Promise<Report> {
    const { server, input, dependencies, inspected, snapshot, hash, checkedAt, tls, trustedKey, candidateKey, leaseKey, lease, identityHash, deadlineAt } = context;
    const storedTrusted = await beforeDeadline(() => dependencies.baselines.get(trustedKey), deadlineAt);
    if (storedTrusted && !usableBaseline(storedTrusted)) {
        if (input.promoteCandidateBaseline) return promotionMismatchReport(server, inspected, hash, checkedAt, tls, false, 'trusted_baseline_incompatible');
        return invalidBaselineReport(server, inspected, checkedAt, tls, true);
    }
    const baseline = storedTrusted;
    const baselineFound = usableBaseline(baseline);
    const classifiedDrift = baselineFound && baseline ? diffSnapshots(baseline.snapshot, snapshot) : highRiskInitializationFindings(snapshot);
    if (baselineFound && baseline && baseline.snapshotHash !== hash && classifiedDrift.length === 0) {
        let candidateStored = false;
        if (!input.promoteCandidateBaseline && !input.dryRun && (input.baselineMode === 'compare_and_update' || input.baselineMode === 'manual_approval')) {
            await guardedSet(dependencies.baselines, leaseKey, lease, candidateKey, createBaseline(snapshot, hash, 'inspection_incomplete', checkedAt, undefined, identityHash, baseline.snapshotHash), deadlineAt);
            candidateStored = true;
        }
        return unclassifiedDriftReport(server, inspected, baseline.snapshotHash, hash, checkedAt, tls, candidateStored);
    }

    let baselineUpdated = false;
    let candidateBaselineStored = false;
    let promoted = false;
    if (input.promoteCandidateBaseline) {
        const candidate = await beforeDeadline(() => dependencies.baselines.get(candidateKey), deadlineAt);
        const validation = validatePromotion(candidate, storedTrusted, identityHash, hash);
        if (validation.mismatch) return promotionMismatchReport(server, inspected, hash, checkedAt, tls, baselineFound, validation.mismatch, baseline?.snapshotHash);
        if (input.dryRun) return promotionMismatchReport(server, inspected, hash, checkedAt, tls, baselineFound, 'dry_run', baseline?.snapshotHash);
        if (!validation.alreadyApplied) {
            const preparedCandidate: StoredBaseline = { ...candidate!, promotionTargetSnapshotHash: candidate!.snapshotHash };
            await guardedSet(dependencies.baselines, leaseKey, lease, candidateKey, preparedCandidate, deadlineAt);
            await guardedSet(dependencies.baselines, leaseKey, lease, trustedKey, createBaseline(snapshot, hash, 'success_no_change', checkedAt, baseline, identityHash), deadlineAt);
            baselineUpdated = true;
        }
        await guardedDelete(dependencies.baselines, leaseKey, lease, candidateKey, deadlineAt);
        promoted = true;
    }

    const changes = [...classifiedDrift];
    addRuntimeFindings(changes, snapshot.tls, inspected.redirectOrigins, new URL(server.url).origin);
    let vulnerabilityResult: VulnerabilityLookupResult = { matches: [], attempted: 0, completed: 0 };
    if (input.checkVulnerabilities && snapshot.packages.length && dependencies.vulnerabilityProvider) {
        try {
            const result = await beforeDeadline(() => dependencies.vulnerabilityProvider!.lookup(snapshot.packages, Math.max(1, remaining(deadlineAt))), deadlineAt);
            vulnerabilityResult = sanitizeVulnerabilityResult(result);
        } catch {
            vulnerabilityResult = { matches: [], attempted: snapshot.packages.filter((entry) => entry.ecosystem).length, completed: 0 };
        }
        for (const vulnerability of vulnerabilityResult.matches.filter((entry) => entry.affected && !entry.unavailable)) changes.push(createChange({
            category: 'vulnerability', entityType: 'package', entityName: vulnerability.package.name,
            jsonPath: `/packages/${vulnerability.package.name}`, currentValue: vulnerability.id, severity: vulnerability.severity,
            ruleId: `OSV_${vulnerability.severity.toUpperCase()}_MATCH`,
            explanation: `Known vulnerability match ${vulnerability.id} reported by OSV for ${vulnerability.package.name}@${vulnerability.package.version}.`,
            recommendedAction: 'Review the OSV advisory and update, mitigate, or remove the affected package.',
            evidence: [vulnerability.id, vulnerability.source], confidence: 'medium',
            score: vulnerability.severity === 'critical' ? 50 : vulnerability.severity === 'high' ? 30 : 15,
        }));
    }

    const risk = summarizeRisk(changes);
    const dangerousFindings = changes.some((change) => change.severity === 'high' || change.severity === 'critical');
    let status: Report['status'];
    if (!baselineFound) {
        if (promoted) {
            status = 'baseline_initialized';
        } else if (input.baselineMode === 'compare_only') {
            status = 'baseline_missing';
        } else if (input.baselineMode === 'manual_approval' || (input.baselineMode === 'compare_and_update' && dangerousFindings)) {
            status = 'candidate_baseline_initialized';
            if (!input.dryRun) {
                await guardedSet(dependencies.baselines, leaseKey, lease, candidateKey, createBaseline(snapshot, hash, status, checkedAt, undefined, identityHash, null), deadlineAt);
                candidateBaselineStored = true;
            }
        } else {
            status = 'baseline_initialized';
            if (!input.dryRun) {
                await guardedSet(dependencies.baselines, leaseKey, lease, trustedKey, createBaseline(snapshot, hash, status, checkedAt, undefined, identityHash), deadlineAt);
                baselineUpdated = true;
            }
        }
    } else {
        status = changes.length ? 'success_changed' : 'success_no_change';
        if (!promoted && !input.dryRun && (input.baselineMode === 'manual_approval' || (input.baselineMode === 'compare_and_update' && dangerousFindings))) {
            await guardedSet(dependencies.baselines, leaseKey, lease, candidateKey, createBaseline(snapshot, hash, status, checkedAt, undefined, identityHash, baseline!.snapshotHash), deadlineAt);
            candidateBaselineStored = true;
        } else if (!promoted && !input.dryRun && input.baselineMode === 'compare_and_update') {
            await guardedSet(dependencies.baselines, leaseKey, lease, trustedKey, createBaseline(snapshot, hash, status, checkedAt, baseline, identityHash), deadlineAt);
            baselineUpdated = true;
        }
    }

    const persistedBaselineFound = baselineFound || promoted;
    const report: Report = {
        serverName: redactMetadataText(server.name, 128),
        serverUrl: redactUrl(server.url),
        status,
        reachable: true,
        transport: inspected.transport,
        baselineFound: persistedBaselineFound,
        ...(baselineFound && baseline ? { previousSnapshotHash: baseline.snapshotHash } : {}),
        currentSnapshotHash: hash,
        overallSeverity: risk.severity,
        riskScore: risk.score,
        changeCount: changes.length,
        changesBySeverity: risk.counts,
        changes,
        vulnerabilities: vulnerabilityResult.matches,
        ...(snapshot.tls ? { tls: snapshot.tls } : {}),
        recommendedAction: recommendation(status, persistedBaselineFound, risk.recommendedAction),
        baselineUpdated,
        candidateBaselineStored,
        inspectedAt: checkedAt,
        checkedAt,
        ...(input.includeRawNormalizedSnapshot ? { rawNormalizedSnapshot: snapshot } : {}),
        inspection: { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins },
    };
    const events: BillableEvent[] = ['server-inspection', 'risk-report-generated'];
    if (baselineFound) events.push('baseline-comparison');
    if (vulnerabilityResult.completed > 0) events.push('vulnerability-lookup');
    const plan = { key: `${trustedKey}:${hash}`, events };
    chargePlans.set(report, plan);
    if (dependencies.ppe) await applyCharges(report, dependencies.ppe, plan, deadlineAt);
    return report;
}

export async function monitorServers(input: ActorInput, dependencies: MonitorDependencies): Promise<Report[]> {
    const enabled = input.servers.filter((server) => server.enabled !== false);
    const reports: Report[] = [];
    let next = 0;
    const workers = Array.from({ length: Math.min(input.concurrency, enabled.length) }, async () => {
        while (next < enabled.length) {
            const index = next;
            next += 1;
            const target = enabled[index] as ServerInput;
            const deadlineAt = serverDeadlineAt(input);
            let report: Report;
            if (dependencies.shouldStop?.()) {
                const stored = await baselineExists(dependencies.baselines, trustedBaselineKey(target.name, target.url), deadlineAt);
                report = internalErrorReport(target, 'Run is shutting down; inspection was not started.', stored);
            } else {
                try {
                    const monitorDependencies = dependencies.onReportReady
                        ? { ...dependencies, ppe: undefined, onReportReady: undefined, onReportPersisted: undefined, onReportFinalized: undefined, deadlineAt }
                        : { ...dependencies, deadlineAt };
                    report = await monitorServer(target, input, monitorDependencies);
                } catch (error) {
                    const stored = await baselineExists(dependencies.baselines, trustedBaselineKey(target.name, target.url), deadlineAt);
                    report = internalErrorReport(target, safeError(error, 'Unexpected server monitoring failure'), stored);
                }
            }
            reports[index] = report;
            let persisted = !dependencies.onReportReady;
            if (dependencies.onReportReady) {
                const outcome = await boundedByDeadline(() => dependencies.onReportReady!(report), deadlineAt);
                if (!outcome.ok) {
                    report.persistence = {
                        succeeded: false,
                        error: outcome.timedOut
                            ? 'Dataset persistence did not complete successfully before the per-server deadline; PPE charging was suppressed.'
                            : safeError(outcome.error, 'Dataset persistence failed'),
                    };
                } else {
                    persisted = true;
                    report.persistence = { succeeded: true };
                }
            }
            if (persisted && dependencies.onReportPersisted) {
                const timeoutMs = remaining(deadlineAt);
                if (timeoutMs > 0) await boundedByDeadline(() => dependencies.onReportPersisted!(report, timeoutMs), deadlineAt);
            }
            if (persisted) {
                const plan = chargePlans.get(report);
                if (dependencies.ppe && plan && remaining(deadlineAt) > 0) await applyCharges(report, dependencies.ppe, plan, deadlineAt);
            }
            if (dependencies.onReportFinalized) {
                await boundedByDeadline(() => dependencies.onReportFinalized!(report), deadlineAt);
            }
        }
    });
    await Promise.all(workers);
    return reports;
}

async function applyCharges(report: Report, ppe: IdempotentPpeAccountant, plan: ChargePlan, deadlineAt: number): Promise<void> {
    const chargedEvents: string[] = [];
    const failedEvents: Array<{ eventName: string; error: string }> = [];
    for (const event of plan.events) {
        const outcome = await boundedByDeadline(() => ppe.charge(event, plan.key), deadlineAt);
        if (!outcome.ok) {
            failedEvents.push({
                eventName: event,
                error: outcome.timedOut
                    ? 'PPE charge was not completed successfully before the per-server deadline.'
                    : safeError(outcome.error, 'PPE charge failed'),
            });
        } else if (outcome.value) {
            chargedEvents.push(event);
        }
        if (outcome.timedOut) break;
    }
    if (chargedEvents.length || failedEvents.length) report.ppe = { chargedEvents, ...(failedEvents.length ? { failedEvents } : {}) };
}

interface PromotionValidation { mismatch?: PromotionMismatchReason; alreadyApplied: boolean; }
function validatePromotion(candidate: StoredBaseline | undefined, trusted: StoredBaseline | undefined, identityHash: string, currentHash: string): PromotionValidation {
    if (!candidate) return { mismatch: 'candidate_missing', alreadyApplied: false };
    if (!usableBaseline(candidate) || candidate.trustedParentSnapshotHash === undefined) return { mismatch: 'candidate_incompatible', alreadyApplied: false };
    if (candidate.endpointIdentityHash !== identityHash) return { mismatch: 'endpoint_identity_mismatch', alreadyApplied: false };
    if (candidate.snapshotHash !== currentHash) return { mismatch: 'current_snapshot_mismatch', alreadyApplied: false };
    if (candidate.trustedParentSnapshotHash === (trusted?.snapshotHash ?? null)) return { alreadyApplied: false };
    if (candidate.promotionTargetSnapshotHash === candidate.snapshotHash && trusted?.snapshotHash === candidate.snapshotHash) return { alreadyApplied: true };
    return { mismatch: 'trusted_parent_mismatch', alreadyApplied: false };
}

async function guardedSet(store: BaselineStore, lockKey: string, lease: BaselineLease | undefined, key: string, value: StoredBaseline, deadlineAt: number): Promise<void> {
    await guardedMutation(store, lockKey, lease, () => store.set(key, value), deadlineAt);
}
async function guardedDelete(store: BaselineStore, lockKey: string, lease: BaselineLease | undefined, key: string, deadlineAt: number): Promise<void> {
    await guardedMutation(store, lockKey, lease, () => store.delete(key), deadlineAt);
}
async function guardedMutation(store: BaselineStore, lockKey: string, lease: BaselineLease | undefined, operation: () => Promise<void>, deadlineAt: number): Promise<void> {
    await verifyOwnership(store, lockKey, lease, deadlineAt);
    const pending: Promise<OperationOutcome<void>> = operation().then(
        () => ({ ok: true, value: undefined, timedOut: false }),
        (error: unknown) => ({ ok: false, error, timedOut: false }),
    );
    let timedOut = false;
    let ownershipLost = false;
    while (true) {
        const pulse = Symbol('lock-heartbeat');
        const waitMs = timedOut ? 60_000 : Math.max(1, Math.min(60_000, remaining(deadlineAt)));
        let heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
        const first = await Promise.race([pending, new Promise<typeof pulse>((resolve) => { heartbeatTimer = setTimeout(() => resolve(pulse), waitMs); })]);
        if (heartbeatTimer) clearTimeout(heartbeatTimer);
        if (first !== pulse) {
            if (timedOut) throw new ServerDeadlineError();
            if (ownershipLost) throw new LeaseLostError();
            if (!first.ok) throw first.error;
            return;
        }
        if (remaining(deadlineAt) <= 0) timedOut = true;
        try {
            if (!lease || !await store.verifyLock(lockKey, lease)) ownershipLost = true;
        } catch { ownershipLost = true; }
    }
}
async function verifyOwnership(store: BaselineStore, key: string, lease: BaselineLease | undefined, deadlineAt: number): Promise<void> {
    if (!lease) throw new LeaseLostError();
    const outcome = await settleByDeadline(() => store.verifyLock(key, lease), deadlineAt);
    if (outcome.timedOut) throw new ServerDeadlineError();
    if (!outcome.ok || !outcome.value) throw new LeaseLostError();
}
async function releaseLease(store: BaselineStore, key: string, lease: BaselineLease): Promise<void> {
    try { await store.releaseLock(key, lease); } catch { /* Native lock expiry safely releases an unavailable lock service. */ }
}
class LeaseLostError extends Error {}
class ServerDeadlineError extends Error {}
function remaining(deadlineAt: number): number { return Math.max(0, deadlineAt - Date.now()); }
function serverDeadlineAt(input: ActorInput): number {
    return Date.now() + Math.min(MAX_SERVER_WALL_CLOCK_MS, Math.max(input.requestTimeoutSeconds * 1_000, input.requestTimeoutSeconds * 3_000));
}
async function beforeDeadline<T>(operation: () => Promise<T>, deadlineAt: number): Promise<T> {
    const timeoutMs = remaining(deadlineAt);
    if (timeoutMs <= 0) throw new ServerDeadlineError();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([operation(), new Promise<T>((_resolve, reject) => { timer = setTimeout(() => reject(new ServerDeadlineError()), timeoutMs); })]);
    } finally { if (timer) clearTimeout(timer); }
}
type OperationOutcome<T> = { ok: true; value: T; timedOut: boolean } | { ok: false; error: unknown; timedOut: boolean };
async function settleByDeadline<T>(operation: () => Promise<T>, deadlineAt: number): Promise<OperationOutcome<T>> {
    const timeoutMs = remaining(deadlineAt);
    if (timeoutMs <= 0) return { ok: false, error: new ServerDeadlineError(), timedOut: true };
    const pending: Promise<OperationOutcome<T>> = operation().then(
        (value) => ({ ok: true, value, timedOut: false }),
        (error: unknown) => ({ ok: false, error, timedOut: false }),
    );
    const timeout = Symbol('deadline');
    let timer: ReturnType<typeof setTimeout> | undefined;
    const first = await Promise.race([pending, new Promise<typeof timeout>((resolve) => { timer = setTimeout(() => resolve(timeout), timeoutMs); })]);
    if (timer) clearTimeout(timer);
    if (first !== timeout) return first;
    const settled = await pending;
    return { ...settled, timedOut: true };
}
async function boundedByDeadline<T>(operation: () => Promise<T>, deadlineAt: number): Promise<OperationOutcome<T>> {
    const timeoutMs = remaining(deadlineAt);
    if (timeoutMs <= 0) return { ok: false, error: new ServerDeadlineError(), timedOut: true };
    const pending: Promise<OperationOutcome<T>> = operation().then(
        (value) => ({ ok: true, value, timedOut: false }),
        (error: unknown) => ({ ok: false, error, timedOut: false }),
    );
    const timeout = Symbol('deadline');
    let timer: ReturnType<typeof setTimeout> | undefined;
    const first = await Promise.race([pending, new Promise<typeof timeout>((resolve) => { timer = setTimeout(() => resolve(timeout), timeoutMs); })]);
    if (timer) clearTimeout(timer);
    if (first !== timeout) return first;
    const settled = await pending;
    return { ...settled, timedOut: true };
}

function highRiskInitializationFindings(snapshot: NormalizedSnapshot): Change[] {
    const empty = structuredClone(snapshot);
    empty.server.capabilities = [];
    empty.tools = [];
    empty.resources = [];
    empty.prompts = [];
    empty.packages = [];
    return diffSnapshots(empty, snapshot).filter((change) => change.severity === 'high' || change.severity === 'critical');
}
function sanitizeVulnerabilityResult(result: VulnerabilityLookupResult): VulnerabilityLookupResult {
    return {
        attempted: Math.max(0, Math.floor(result.attempted)),
        completed: Math.max(0, Math.floor(result.completed)),
        matches: result.matches.slice(0, 1_000).map(sanitizeVulnerability),
    };
}
function sanitizeVulnerability(value: VulnerabilityMatch): VulnerabilityMatch {
    const severity: Severity = ['informational', 'low', 'medium', 'high', 'critical'].includes(value.severity) ? value.severity : 'informational';
    return {
        package: {
            name: redactMetadataText(value.package.name, 256),
            version: redactMetadataText(value.package.version, 128),
            ...(value.package.ecosystem ? { ecosystem: redactMetadataText(value.package.ecosystem, 128) } : {}),
        },
        id: redactMetadataText(value.id, 256),
        ...(value.summary ? { summary: redactMetadataText(value.summary, 1_000) } : {}),
        severity,
        source: 'OSV',
        lookupTimestamp: redactMetadataText(value.lookupTimestamp, 128),
        affected: value.affected === true,
        ...(value.unavailable ? { unavailable: true } : {}),
    };
}
function recommendation(status: Report['status'], baselineFound: boolean, riskRecommendation: string): string {
    if (status === 'promotion_mismatch') return 'The candidate was not promoted because it did not exactly match the current endpoint, snapshot, and trusted-parent lineage; both records were preserved.';
    if (status === 'candidate_baseline_initialized') return 'A candidate baseline was stored, but no trusted baseline was initialized; review and explicitly promote the exact candidate in a later authorized run.';
    if (status === 'baseline_initialized') return 'A trusted baseline was initialized; review it before relying on future comparisons.';
    if (!baselineFound) return 'No trusted baseline exists; initialize one after human review before interpreting drift.';
    return riskRecommendation;
}
function addRuntimeFindings(changes: Change[], tls: TlsMetadata | undefined, redirects: string[], origin: string): void {
    if (tls && tls.authorized === false) changes.push(createChange({ category: 'tls', entityType: 'tls', entityName: tls.hostname ?? origin, severity: 'high', ruleId: 'TLS_CERTIFICATE_PROBLEM', explanation: `TLS certificate validation problem: ${tls.authorizationError ?? 'unknown error'}.`, recommendedAction: 'Investigate certificate validity and hostname configuration before approval.', evidence: [tls.authorizationError ?? 'certificate validation failed'], confidence: 'high' }));
    if (tls?.daysRemaining !== undefined && tls.daysRemaining >= 0 && tls.daysRemaining <= 30) changes.push(createChange({ category: 'tls', entityType: 'tls', entityName: tls.hostname ?? origin, severity: 'medium', ruleId: 'TLS_CERTIFICATE_NEARING_EXPIRY', explanation: `TLS certificate expires in ${tls.daysRemaining} days.`, recommendedAction: 'Renew and validate the certificate before expiration.', evidence: [`daysRemaining=${tls.daysRemaining}`], confidence: 'high' }));
    for (const redirectOrigin of new Set(redirects)) if (redirectOrigin !== origin) changes.push(createChange({ category: 'redirect', entityType: 'server', entityName: origin, severity: 'high', ruleId: 'REDIRECT_ORIGIN_CHANGED', explanation: `Metadata request redirected from ${origin} to ${redirectOrigin}.`, recommendedAction: 'Verify the redirect target is authorized before approving.', evidence: [origin, redirectOrigin] }));
}

function failureReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: false }>, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean): Report {
    const reachable = inspected.responseReceived === true || inspected.httpStatus !== undefined;
    return baseFailure(server, inspected.status, inspected.message, checkedAt, reachable, baselineFound, tls, inspected.transport && inspected.transport !== 'auto' ? inspected.transport : undefined, inspectionFromFailure(inspected));
}
function internalErrorReport(server: ServerInput, message: string, baselineFound: boolean, reachable = false, inspected?: Extract<InspectionResult, { ok: true }>): Report {
    return baseFailure(server, 'internal_error', message, new Date().toISOString(), reachable, baselineFound, undefined, inspected?.transport, inspected ? { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins } : undefined);
}
function baseFailure(server: ServerInput, status: Report['status'], message: string, checkedAt: string, reachable: boolean, baselineFound: boolean, tls?: TlsMetadata, transport?: Report['transport'], inspection?: Report['inspection']): Report {
    const severity = failureSeverity(status);
    const score = severity === 'high' ? 50 : severity === 'medium' ? 20 : severity === 'low' ? 1 : 0;
    return { serverName: redactMetadataText(server.name, 128), serverUrl: redactUrl(server.url), status, reachable, ...(transport ? { transport } : {}), baselineFound, overallSeverity: severity, riskScore: score, changeCount: 0, changesBySeverity: { informational: 0, low: 0, medium: 0, high: 0, critical: 0 }, changes: [], vulnerabilities: [], ...(tls ? { tls } : {}), recommendedAction: 'Resolve the inspection failure and retry; the trusted baseline was not modified.', baselineUpdated: false, candidateBaselineStored: false, inspectedAt: checkedAt, checkedAt, ...(inspection ? { inspection } : {}), error: { code: status, message: redactString(message) } };
}
function failureSeverity(status: Report['status']): Severity {
    if (['unreachable', 'authentication_failed', 'invalid_response', 'timeout', 'internal_error'].includes(status)) return 'high';
    if (['unsupported_transport', 'inspection_incomplete', 'rate_limited', 'baseline_missing', 'promotion_mismatch'].includes(status)) return 'medium';
    return 'informational';
}
function inspectionFromFailure(inspected: Extract<InspectionResult, { ok: false }>): Report['inspection'] | undefined {
    if (inspected.httpStatus === undefined && inspected.latencyMs === undefined && inspected.responseContentType === undefined && inspected.redirectOrigins === undefined) return undefined;
    return { ...(inspected.httpStatus === undefined ? {} : { httpStatus: inspected.httpStatus }), ...(inspected.latencyMs === undefined ? {} : { latencyMs: inspected.latencyMs }), ...(inspected.responseContentType === undefined ? {} : { contentType: redactMetadataText(inspected.responseContentType, 256) }), ...(inspected.redirectOrigins === undefined ? {} : { redirectOrigins: inspected.redirectOrigins }) };
}
function hasMeaningfulMetadata(snapshot: Extract<InspectionResult, { ok: true }>['snapshot']): boolean {
    return snapshot.tools.length > 0 || snapshot.resources.length > 0 || snapshot.prompts.length > 0 || snapshot.packages.length > 0 || snapshot.server.capabilities.length > 0 || !!snapshot.server.identity || !!snapshot.server.version || !!snapshot.server.protocolVersion;
}
function incompleteSnapshotReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean): Report {
    return { ...baseFailure(server, 'inspection_incomplete', 'Inspection returned no security-relevant MCP metadata.', checkedAt, true, baselineFound, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), recommendedAction: 'The metadata snapshot was empty; no trusted baseline was changed.', error: { code: 'empty_snapshot', message: 'Inspection returned no security-relevant MCP metadata.' } };
}
function invalidBaselineReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean): Report {
    return { ...baseFailure(server, 'inspection_incomplete', 'Stored baseline failed current version or integrity validation.', checkedAt, true, baselineFound, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), currentSnapshotHash: snapshotHash(inspected.snapshot), overallSeverity: 'medium', riskScore: 20, recommendedAction: 'Trusted baseline is incompatible or corrupt; migrate or explicitly reinitialize it after human review.', error: { code: 'baseline_migration_required', message: 'Stored baseline failed current version or integrity validation and was preserved unchanged.' } };
}
function unclassifiedDriftReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, previousHash: string, currentHash: string, checkedAt: string, tls: TlsMetadata | undefined, candidateStored: boolean): Report {
    return { ...baseFailure(server, 'inspection_incomplete', 'Snapshot hash changed without a classified difference.', checkedAt, true, true, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), previousSnapshotHash: previousHash, currentSnapshotHash: currentHash, overallSeverity: 'medium', riskScore: 20, candidateBaselineStored: candidateStored, recommendedAction: candidateStored ? 'Review the safely stored candidate snapshot and update the diff rules before explicit promotion.' : 'Review the normalized snapshots and update the diff rules before approving this baseline.', error: { code: 'unclassified_drift', message: 'Snapshot hash changed without a classified difference; trusted baseline was preserved.' } };
}
function lockUnavailableReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, currentHash: string, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean): Report {
    return { ...baseFailure(server, 'inspection_incomplete', 'Atomic baseline lock could not be acquired or ownership was lost.', checkedAt, true, baselineFound, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), currentSnapshotHash: currentHash, overallSeverity: 'medium', riskScore: 20, recommendedAction: 'Retry after checking persistent storage access and allowing any concurrent baseline update to finish; no unowned baseline write was attempted.', error: { code: 'baseline_lock_unavailable', message: 'Atomic baseline lock ownership could not be verified; trusted and candidate state were not modified by this operation.' } };
}
function deadlineExceededReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, currentHash: string, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean): Report {
    return { ...baseFailure(server, 'timeout', 'Per-server deadline expired during baseline handling.', checkedAt, true, baselineFound, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), currentSnapshotHash: currentHash, recommendedAction: 'Retry after reviewing storage latency; no success was reported or charged for the timed-out mutation.', error: { code: 'baseline_operation_timeout', message: 'A baseline operation settled after the per-server deadline; lock ownership was retained until it settled.' } };
}
function promotionMismatchReport(server: ServerInput, inspected: Extract<InspectionResult, { ok: true }>, currentHash: string, checkedAt: string, tls: TlsMetadata | undefined, baselineFound: boolean, reason: PromotionMismatchReason, previousHash?: string): Report {
    return { ...baseFailure(server, 'promotion_mismatch', `Candidate promotion rejected: ${reason}.`, checkedAt, true, baselineFound, tls, inspected.transport, { httpStatus: inspected.responseStatus, latencyMs: inspected.latencyMs, contentType: redactMetadataText(inspected.responseContentType, 256), redirectOrigins: inspected.redirectOrigins }), ...(previousHash ? { previousSnapshotHash: previousHash } : {}), currentSnapshotHash: currentHash, overallSeverity: 'medium', riskScore: 20, recommendedAction: 'Re-inspect and create a new candidate from the current trusted parent before attempting promotion again; existing records were preserved.', error: { code: 'promotion_mismatch', reason, message: `Candidate promotion rejected because ${reason.replaceAll('_', ' ')}; trusted and candidate state were preserved.` } };
}
async function baselineExists(store: BaselineStore, key: string, deadlineAt: number): Promise<boolean> {
    try { return (await beforeDeadline(() => store.get(key), deadlineAt)) !== undefined; } catch { return false; }
}
function sanitizeTls(value: TlsMetadata): TlsMetadata {
    return {
        ...(value.protocol ? { protocol: redactMetadataText(value.protocol, 64) } : {}),
        ...(value.validFrom ? { validFrom: redactMetadataText(value.validFrom, 128) } : {}),
        ...(value.validTo ? { validTo: redactMetadataText(value.validTo, 128) } : {}),
        ...(typeof value.daysRemaining === 'number' && Number.isFinite(value.daysRemaining) ? { daysRemaining: Math.floor(value.daysRemaining) } : {}),
        ...(typeof value.authorized === 'boolean' ? { authorized: value.authorized } : {}),
        ...(value.authorizationError ? { authorizationError: redactMetadataText(value.authorizationError, 512) } : {}),
        ...(value.subject ? { subject: redactMetadataText(value.subject, 512) } : {}),
        ...(value.issuer ? { issuer: redactMetadataText(value.issuer, 512) } : {}),
        ...(value.hostname ? { hostname: redactMetadataText(value.hostname, 512) } : {}),
    };
}
function safeError(error: unknown, fallback: string): string { return redactString(error instanceof Error ? error.message : fallback); }
