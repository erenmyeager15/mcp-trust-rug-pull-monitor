import type { Change, Severity } from './types.js';

const rank: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
const scoreFloor: Array<[Severity, number]> = [['critical', 80], ['high', 50], ['medium', 20], ['low', 1], ['informational', 0]];

export function summarizeRisk(changes: Change[]): { score: number; severity: Severity; recommendedAction: string; counts: Record<Severity, number> } {
    const counts: Record<Severity, number> = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const change of changes) counts[change.severity] += 1;
    const contribution = changes.reduce((total, change) => total + change.riskScoreContribution, 0);
    const highest = changes.reduce<Severity>((current, change) => rank[change.severity] > rank[current] ? change.severity : current, 'informational');
    const score = Math.min(100, Math.max(contribution, scoreFloor.find(([severity]) => severity === highest)?.[1] ?? 0));
    const severity = severityFrom(score, highest);
    const top = [...changes].sort((left, right) => right.riskScoreContribution - left.riskScoreContribution || left.id.localeCompare(right.id))[0];
    return { score, severity, counts, recommendedAction: top ? top.recommendedAction : 'No security-relevant drift detected; keep the trusted baseline under periodic review.' };
}

export function severityFrom(score: number, highest: Severity = 'informational'): Severity {
    if (highest === 'critical' || score >= 80) return 'critical';
    if (highest === 'high' || score >= 50) return 'high';
    if (highest === 'medium' || score >= 20) return 'medium';
    if (highest === 'low' || score > 0) return 'low';
    return 'informational';
}

export function meetsMinimumSeverity(actual: Severity, minimum: Severity): boolean { return rank[actual] >= rank[minimum]; }
