import { NORMALIZER_VERSION, RISK_RULES_VERSION } from './constants.js';
import { sha256 } from './json.js';
import { snapshotHash } from './normalize.js';
import type { BaselineLease, BaselineStore, NormalizedSnapshot, StoredBaseline } from './types.js';

export function canonicalEndpointIdentity(rawUrl: string): string {
    const url = new URL(rawUrl);
    url.hash = '';
    const sorted = [...url.searchParams.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) => compareText(leftKey, rightKey) || compareText(leftValue, rightValue));
    url.search = '';
    for (const [key, value] of sorted) url.searchParams.append(key, value);
    return url.toString();
}

function compareText(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function baselineIdentity(serverName: string, endpointUrl: string): string { return `${serverName.normalize('NFC')}\u0000${canonicalEndpointIdentity(endpointUrl)}`; }

export function endpointIdentityHash(serverName: string, endpointUrl: string): string { return sha256(baselineIdentity(serverName, endpointUrl)); }
export function trustedBaselineKey(serverName: string, endpointUrl: string): string { return `trusted-baseline-v1-${endpointIdentityHash(serverName, endpointUrl).slice(7, 39)}`; }
export function candidateBaselineKey(serverName: string, endpointUrl: string): string { return `candidate-baseline-v1-${endpointIdentityHash(serverName, endpointUrl).slice(7, 39)}`; }
export function baselineLeaseKey(serverName: string, endpointUrl: string): string { return `baseline-lock-v1-${endpointIdentityHash(serverName, endpointUrl).slice(7, 39)}`; }

export class MemoryBaselineStore implements BaselineStore {
    private readonly values = new Map<string, StoredBaseline>();
    private readonly leases = new Map<string, BaselineLease>();
    private readonly leaseDurations = new Map<string, number>();

    async get(key: string): Promise<StoredBaseline | undefined> { const value = this.values.get(key); return value ? structuredClone(value) : undefined; }
    async set(key: string, value: StoredBaseline): Promise<void> { this.values.set(key, structuredClone(value)); }
    async delete(key: string): Promise<void> { this.values.delete(key); }
    async acquireLock(key: string, proposed: BaselineLease): Promise<BaselineLease | undefined> {
        const current = this.leases.get(key);
        if (current && Date.parse(current.expiresAt) > Date.now() && current.owner !== proposed.owner) return undefined;
        this.leases.set(key, structuredClone(proposed));
        this.leaseDurations.set(key, Math.max(1, Date.parse(proposed.expiresAt) - Date.now()));
        return structuredClone(proposed);
    }
    async verifyLock(key: string, lease: BaselineLease): Promise<boolean> {
        const current = this.leases.get(key);
        if (current?.owner !== lease.owner || Date.parse(current.expiresAt) <= Date.now()) return false;
        const duration = this.leaseDurations.get(key) ?? 1;
        current.expiresAt = new Date(Date.now() + duration).toISOString();
        return true;
    }
    async releaseLock(key: string, lease: BaselineLease): Promise<void> {
        if (this.leases.get(key)?.owner === lease.owner) {
            this.leases.delete(key);
            this.leaseDurations.delete(key);
        }
    }
}

export function createBaseline(
    snapshot: NormalizedSnapshot,
    hash: string,
    status: StoredBaseline['lastResultStatus'],
    now: string,
    prior?: StoredBaseline,
    identityHash?: string,
    trustedParentSnapshotHash?: string | null,
): StoredBaseline {
    return {
        storageSchemaVersion: 1,
        normalizerVersion: NORMALIZER_VERSION,
        riskRulesVersion: RISK_RULES_VERSION,
        createdAt: prior?.createdAt ?? now,
        ...(prior ? { lastSuccessfulComparisonAt: now } : {}),
        lastResultStatus: status,
        snapshotHash: hash,
        ...(identityHash ?? prior?.endpointIdentityHash ? { endpointIdentityHash: identityHash ?? prior?.endpointIdentityHash } : {}),
        ...(trustedParentSnapshotHash !== undefined ? { trustedParentSnapshotHash } : {}),
        snapshot,
    };
}

export function usableBaseline(value: StoredBaseline | undefined): value is StoredBaseline {
    return !!value
        && value.storageSchemaVersion === 1
        && value.snapshot.schemaVersion === 1
        && value.normalizerVersion === NORMALIZER_VERSION
        && value.snapshot.normalizerVersion === NORMALIZER_VERSION
        && value.riskRulesVersion === RISK_RULES_VERSION
        && value.snapshotHash === snapshotHash(value.snapshot);
}
