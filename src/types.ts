export type BaselineMode = 'initialize_only' | 'compare_only' | 'compare_and_update' | 'manual_approval';
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type RunStatus =
    | 'success_no_change' | 'success_changed' | 'baseline_initialized' | 'candidate_baseline_initialized' | 'baseline_missing' | 'promotion_mismatch' | 'authorization_required'
    | 'unreachable' | 'authentication_failed' | 'unsupported_transport' | 'invalid_response'
    | 'inspection_incomplete' | 'rate_limited' | 'timeout' | 'internal_error';
export type TransportName = 'auto' | 'streamable_http' | 'http_sse' | 'static_json';
export type PromotionMismatchReason =
    | 'candidate_missing' | 'candidate_incompatible' | 'current_snapshot_mismatch' | 'endpoint_identity_mismatch'
    | 'trusted_parent_mismatch' | 'trusted_baseline_incompatible' | 'dry_run';

export interface ServerInput {
    name: string;
    url: string;
    transport?: TransportName;
    headers?: Record<string, string>;
    enabled?: boolean;
    tags?: string[];
}

export interface ActorInput {
    servers: ServerInput[];
    authorizedUseConfirmed: boolean;
    baselineKeyValueStoreId?: string;
    baselineRequestQueueId?: string;
    baselineMode: BaselineMode;
    minimumAlertSeverity: Severity;
    webhookUrl?: string;
    checkVulnerabilities: boolean;
    checkTls: boolean;
    includeRawNormalizedSnapshot: boolean;
    requestTimeoutSeconds: number;
    maxRetries: number;
    concurrency: number;
    dryRun: boolean;
    promoteCandidateBaseline: boolean;
    allowHttp: boolean;
    allowPrivateNetwork: boolean;
    maxResponseBytes: number;
}

export interface PackageReference { name: string; version: string; ecosystem?: string; }
export interface ToolDefinition {
    name: string;
    description: string;
    inputSchema: JsonObject;
    outputSchema?: JsonObject;
    annotations?: JsonObject;
}
export interface ResourceDefinition { uriTemplate?: string; uri?: string; name: string; description?: string; mimeType?: string; }
export interface PromptDefinition { name: string; description?: string; text?: string; arguments?: JsonValue; }
export interface AuthMetadata { required?: boolean; schemes?: string[]; scopes?: string[]; permissions?: string[]; capabilities?: string[]; }

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject { [key: string]: JsonValue | undefined; }

export interface NormalizedSnapshot {
    schemaVersion: 1;
    normalizerVersion: string;
    server: {
        name: string;
        origin: string;
        identity?: string;
        version?: string;
        protocolVersion?: string;
        capabilities: string[];
        authentication: AuthMetadata;
        contentType?: string;
    };
    tools: ToolDefinition[];
    resources: ResourceDefinition[];
    prompts: PromptDefinition[];
    packages: PackageReference[];
    tls?: TlsMetadata;
}

export interface TlsMetadata {
    protocol?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    authorized?: boolean;
    authorizationError?: string;
    subject?: string;
    issuer?: string;
    hostname?: string;
}

export interface InspectionSuccess {
    ok: true;
    transport: Exclude<TransportName, 'auto'>;
    snapshot: NormalizedSnapshot;
    responseStatus: number;
    responseContentType: string;
    latencyMs: number;
    redirectOrigins: string[];
}
export interface InspectionFailure {
    ok: false;
    status: Exclude<RunStatus, 'success_no_change' | 'success_changed' | 'baseline_initialized' | 'candidate_baseline_initialized' | 'promotion_mismatch' | 'authorization_required'>;
    message: string;
    transport?: TransportName;
    httpStatus?: number;
    latencyMs?: number;
    responseContentType?: string;
    redirectOrigins?: string[];
    responseReceived?: boolean;
}
export type InspectionResult = InspectionSuccess | InspectionFailure;

export interface StoredBaseline {
    storageSchemaVersion: 1;
    normalizerVersion: string;
    riskRulesVersion: string;
    createdAt: string;
    lastSuccessfulComparisonAt?: string;
    lastResultStatus: RunStatus;
    snapshotHash: string;
    endpointIdentityHash?: string;
    /** Candidate-only lineage. Null means the candidate was generated with no trusted parent. */
    trustedParentSnapshotHash?: string | null;
    /** Candidate-only durable marker used to finish a previously authorized partial promotion. */
    promotionTargetSnapshotHash?: string;
    snapshot: NormalizedSnapshot;
}

export interface Change {
    id: string;
    category: string;
    entityType: 'server' | 'tool' | 'resource' | 'prompt' | 'package' | 'tls';
    entityName: string;
    jsonPath?: string;
    previousValue?: JsonValue;
    currentValue?: JsonValue;
    severity: Severity;
    riskScoreContribution: number;
    ruleId: string;
    explanation: string;
    recommendedAction: string;
    evidence: string[];
    confidence: 'low' | 'medium' | 'high';
}

export interface VulnerabilityMatch {
    package: PackageReference;
    id: string;
    summary?: string;
    severity: Severity;
    source: 'OSV';
    lookupTimestamp: string;
    affected: boolean;
    unavailable?: boolean;
}
export interface VulnerabilityLookupResult {
    matches: VulnerabilityMatch[];
    attempted: number;
    completed: number;
}

export interface Report {
    serverName: string;
    serverUrl: string;
    status: RunStatus;
    reachable: boolean;
    transport?: Exclude<TransportName, 'auto'>;
    baselineFound: boolean;
    previousSnapshotHash?: string;
    currentSnapshotHash?: string;
    overallSeverity: Severity;
    riskScore: number;
    changeCount: number;
    changesBySeverity: Record<Severity, number>;
    changes: Change[];
    vulnerabilities: VulnerabilityMatch[];
    tls?: TlsMetadata;
    recommendedAction: string;
    baselineUpdated: boolean;
    candidateBaselineStored: boolean;
    inspectedAt: string;
    checkedAt: string;
    rawNormalizedSnapshot?: NormalizedSnapshot;
    inspection?: { httpStatus?: number; latencyMs?: number; contentType?: string; redirectOrigins?: string[] };
    webhook?: { attempted: boolean; delivered: boolean; status?: number; error?: string };
    ppe?: { chargedEvents: string[]; failedEvents?: Array<{ eventName: string; error: string }> };
    persistence?: { succeeded: boolean; error?: string };
    error?: { code: string; message: string; reason?: PromotionMismatchReason };
}

export interface BaselineLease { owner: string; expiresAt: string; }
export interface BaselineStore {
    get(key: string): Promise<StoredBaseline | undefined>;
    set(key: string, value: StoredBaseline): Promise<void>;
    delete(key: string): Promise<void>;
    acquireLock(key: string, proposed: BaselineLease): Promise<BaselineLease | undefined>;
    verifyLock(key: string, lease: BaselineLease): Promise<boolean>;
    releaseLock(key: string, lease: BaselineLease): Promise<void>;
}

export interface ChargeClient { charge(eventName: string, idempotencyKey: string): Promise<void>; }
export interface Logger { info(message: string, data?: JsonObject): void; warning(message: string, data?: JsonObject): void; error(message: string, data?: JsonObject): void; }
