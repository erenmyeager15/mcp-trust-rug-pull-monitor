import type { ChargeClient } from './types.js';

export class IdempotentPpeAccountant {
    private readonly charged = new Set<string>();
    private readonly inFlight = new Map<string, Promise<void>>();
    constructor(private readonly client: ChargeClient) {}

    async charge(eventName: 'server-inspection' | 'baseline-comparison' | 'vulnerability-lookup' | 'risk-report-generated', idempotencyKey: string): Promise<boolean> {
        const key = `${eventName}:${idempotencyKey}`;
        if (this.charged.has(key)) return false;
        const existing = this.inFlight.get(key);
        if (existing) { await existing; return false; }
        const pending = this.client.charge(eventName, key);
        this.inFlight.set(key, pending);
        try {
            await pending;
            this.charged.add(key);
            return true;
        } finally {
            this.inFlight.delete(key);
        }
    }
}

export class NoopChargeClient implements ChargeClient { async charge(): Promise<void> {} }
