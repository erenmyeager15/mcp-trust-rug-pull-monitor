import { Actor } from 'apify';
import type { KeyValueStoreClient, RequestQueueClient, RequestQueueClientRequestSchema } from 'apify-client';
import { MAX_SERVER_WALL_CLOCK_MS } from './constants.js';
import { sha256 } from './json.js';
import type { BaselineLease, BaselineStore, ChargeClient, StoredBaseline } from './types.js';

const LOCK_TTL_SECONDS = Math.ceil((MAX_SERVER_WALL_CLOCK_MS + 300_000) / 1_000);
const STORAGE_CLIENT_TIMEOUT_SECONDS = 30;
interface LockHandle { client: RequestQueueClient; requestId: string; uniqueKey: string; url: string; lease: BaselineLease; }
interface LockUserData { owner?: unknown; expiresAt?: unknown; baselineIdentity?: unknown; }

export class ApifyBaselineStore implements BaselineStore {
    private readonly heldLocks = new Map<string, LockHandle>();

    constructor(
        private readonly keyValueStoreId?: string,
        private readonly requestQueueId?: string,
    ) {}

    async get(key: string): Promise<StoredBaseline | undefined> {
        const store = this.cloudStore();
        if (!store) return (await Actor.getValue<StoredBaseline>(key)) ?? undefined;
        return (await store.getRecord(key))?.value as StoredBaseline | undefined;
    }
    async set(key: string, value: StoredBaseline): Promise<void> {
        const store = this.requiredCloudStore();
        await store.setRecord({ key, value: value as never, contentType: 'application/json; charset=utf-8' }, { timeoutSecs: STORAGE_CLIENT_TIMEOUT_SECONDS, doNotRetryTimeouts: true });
    }
    async delete(key: string): Promise<void> { await this.requiredCloudStore().deleteRecord(key); }

    async acquireLock(key: string, proposed: BaselineLease): Promise<BaselineLease | undefined> {
        const api = Actor.newClient({ maxRetries: 0, timeoutSecs: STORAGE_CLIENT_TIMEOUT_SECONDS });
        const queueId = this.requestQueueId ?? Actor.getEnv().defaultRequestQueueId;
        if (!queueId) throw new Error('Atomic baseline mutation requires an Apify Cloud Key-Value Store and Request Queue.');
        const client = api.requestQueue(queueId, { clientKey: proposed.owner, timeoutSecs: STORAGE_CLIENT_TIMEOUT_SECONDS });
        const uniqueKey = key;
        const url = `https://mcp-baseline-lock.invalid/${sha256(key).slice(7)}`;
        const lease: BaselineLease = { owner: proposed.owner, expiresAt: new Date(Date.now() + LOCK_TTL_SECONDS * 1_000).toISOString() };
        const added = await client.addRequest({ url, uniqueKey, method: 'GET', userData: { baselineIdentity: key, owner: lease.owner, expiresAt: lease.expiresAt } });
        let nativeLockAcquired = false;
        try {
            const locked = await client.listAndLockHead({ limit: 1, lockSecs: LOCK_TTL_SECONDS });
            if (!locked.items.some((item) => item.id === added.requestId)) return undefined;
            nativeLockAcquired = true;
            await client.prolongRequestLock(added.requestId, { lockSecs: LOCK_TTL_SECONDS });
            const current = await client.getRequest(added.requestId) as (RequestQueueClientRequestSchema & { userData?: LockUserData }) | undefined;
            if (!hasOwner(current?.userData, lease)) {
                await client.deleteRequestLock(added.requestId);
                return undefined;
            }
            this.heldLocks.set(key, { client, requestId: added.requestId, uniqueKey, url, lease });
            return lease;
        } catch (error) {
            if (nativeLockAcquired) {
                try { await client.deleteRequestLock(added.requestId); } catch { /* Native expiry safely releases an interrupted acquisition. */ }
            }
            throw error;
        }
    }

    async verifyLock(key: string, lease: BaselineLease): Promise<boolean> {
        const handle = this.heldLocks.get(key);
        if (!handle || handle.lease.owner !== lease.owner || Date.parse(handle.lease.expiresAt) <= Date.now()) return false;
        try {
            const prolonged = await handle.client.prolongRequestLock(handle.requestId, { lockSecs: LOCK_TTL_SECONDS });
            const current = await handle.client.getRequest(handle.requestId) as (RequestQueueClientRequestSchema & { userData?: LockUserData }) | undefined;
            if (current?.userData?.owner !== lease.owner) return false;
            const refreshed = { ...lease, expiresAt: prolonged.lockExpiresAt.toISOString() };
            handle.lease = refreshed;
            return true;
        } catch { return false; }
    }

    async releaseLock(key: string, lease: BaselineLease): Promise<void> {
        const handle = this.heldLocks.get(key);
        if (!handle || handle.lease.owner !== lease.owner) return;
        try {
            const current = await handle.client.getRequest(handle.requestId) as (RequestQueueClientRequestSchema & { userData?: LockUserData }) | undefined;
            if (current?.userData?.owner === lease.owner) {
                try { await handle.client.deleteRequest(handle.requestId); }
                catch { await handle.client.deleteRequestLock(handle.requestId); }
            }
        } finally { this.heldLocks.delete(key); }
    }

    private cloudStore(): KeyValueStoreClient | undefined {
        const id = this.keyValueStoreId ?? Actor.getEnv().defaultKeyValueStoreId;
        return id ? Actor.newClient({ maxRetries: 0, timeoutSecs: STORAGE_CLIENT_TIMEOUT_SECONDS }).keyValueStore(id) : undefined;
    }
    private requiredCloudStore(): KeyValueStoreClient {
        const store = this.cloudStore();
        if (!store) throw new Error('Atomic baseline mutation requires an Apify Cloud Key-Value Store and Request Queue.');
        return store;
    }
}

function hasOwner(userData: LockUserData | undefined, lease: BaselineLease): boolean {
    return userData?.owner === lease.owner
        && typeof userData.expiresAt === 'string'
        && Date.parse(userData.expiresAt) > Date.now();
}

export class ApifyChargeClient implements ChargeClient {
    async charge(eventName: string, _idempotencyKey: string): Promise<void> { await Actor.charge({ eventName }); }
}
