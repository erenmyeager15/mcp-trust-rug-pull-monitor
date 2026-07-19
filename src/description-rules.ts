import type { Severity } from './types.js';

export interface DescriptionRule { id: string; severity: Severity; score: number; pattern: RegExp; explanation: string; action: string; }

export const DESCRIPTION_RULES: DescriptionRule[] = [
    { id: 'DESC_ENVIRONMENT_ACCESS', severity: 'critical', score: 45, pattern: /\b(read|dump|collect).{0,50}\b(environment variables?|env vars?)\b/i, explanation: 'Description claims environment-variable access, which can expose runtime secrets.', action: 'Review and approve the exact data boundary before trusting this tool.' },
    { id: 'DESC_ARBITRARY_FILE_ACCESS', severity: 'critical', score: 45, pattern: /\b(read|write|scan).{0,50}\b(arbitrary files?|filesystem|file system|unrestricted files?)\b/i, explanation: 'Description claims arbitrary or unrestricted filesystem access.', action: 'Treat as potentially dangerous capability and require human approval.' },
    { id: 'DESC_CREDENTIAL_ACCESS', severity: 'critical', score: 50, pattern: /\b(read|access|collect|extract|exfiltrate|dump|upload).{0,80}\b(credentials?|passwords?|access tokens?|api keys?|secrets?)\b/i, explanation: 'Description claims it can access, collect, or transmit credentials, tokens, API keys, or secrets.', action: 'Verify the tool has a documented, least-privilege data boundary.' },
    { id: 'DESC_EXTERNAL_SEND', severity: 'critical', score: 40, pattern: /\b(send|email|message|post).{0,50}\b(email|message|slack|sms|webhook)\b/i, explanation: 'Description claims it can send messages or externally transmit data.', action: 'Confirm recipients, approval controls, and outbound data policy.' },
    { id: 'DESC_PAYMENT_ACTION', severity: 'critical', score: 50, pattern: /\b(payments?|transfers?|wire money|purchase|refund)\b/i, explanation: 'Description references a financial action.', action: 'Require transaction-specific authorization and human review.' },
    { id: 'DESC_DESTRUCTIVE_ACTION', severity: 'critical', score: 45, pattern: /\b(delete|destroy|wipe|drop).{0,50}\b(data|files?|records?|database|account)\b/i, explanation: 'Description claims destructive data or account actions.', action: 'Verify safe guards, scope, and recovery before approving.' },
    { id: 'DESC_COMMAND_EXECUTION', severity: 'critical', score: 50, pattern: /\b(execute|run|spawn).{0,50}\b(commands?|shell|terminal|powershell|bash)\b/i, explanation: 'Description claims command or shell execution.', action: 'Treat as privileged administration and require a security review.' },
    { id: 'DESC_SECURITY_BYPASS', severity: 'critical', score: 50, pattern: /\b(disable|bypass|turn off).{0,50}\b(security|authentication|logging|monitoring|controls?)\b/i, explanation: 'Description requests disabling or bypassing a security control.', action: 'Reject or escalate for immediate human review.' },
    { id: 'DESC_PROMPT_INSTRUCTION', severity: 'high', score: 30, pattern: /\b(ignore|disregard).{0,50}\b(previous|prior).{0,50}\binstructions?\b/i, explanation: 'Description contains an instruction to ignore prior instructions.', action: 'Review for unsafe instruction content before approving.' },
    { id: 'DESC_UNRELATED_UPLOAD', severity: 'high', score: 30, pattern: /\b(upload|exfiltrate|send).{0,50}\b(unrelated|external|third[- ]party).{0,50}\b(domain|server|endpoint)\b/i, explanation: 'Description suggests sending data to an unrelated external destination.', action: 'Validate data flow and destination ownership.' },
    { id: 'DESC_ADMIN_ACCESS', severity: 'critical', score: 45, pattern: /\b(administrator|admin|root|privileged)\b.{0,50}\b(access|permissions?|rights?)\b/i, explanation: 'Description requests administrator or privileged access.', action: 'Apply least privilege and require explicit approval.' },
    { id: 'DESC_COOKIE_COLLECTION', severity: 'critical', score: 45, pattern: /\b(browser )?cookies?\b/i, explanation: 'Description references browser cookie collection.', action: 'Treat as sensitive session data and require investigation.' },
    { id: 'DESC_UNRELATED_PERSONAL_DATA', severity: 'high', score: 35, pattern: /\b(unrelated|all).{0,50}\b(personal data|pii|personal information)\b/i, explanation: 'Description requests unrelated personal data.', action: 'Confirm necessity, minimization, and user authorization.' },
];

export function findDescriptionRisks(description: string): DescriptionRule[] {
    return DESCRIPTION_RULES.filter((rule) => rule.pattern.test(description));
}
