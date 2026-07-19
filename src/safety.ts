import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { PRIVATE_NETWORK_MESSAGE } from './constants.js';

const CLOUD_METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata', 'instance-data', 'instance-data.ec2.internal']);

export interface ResolvedPublicTarget {
    url: URL;
    address: string;
    family: 4 | 6;
}

export function isBlockedIp(address: string): boolean {
    const normalized = address.toLowerCase().split('%')[0] ?? '';
    const family = isIP(normalized);
    if (family === 4) {
        const [first = Number.NaN, second = Number.NaN, third = Number.NaN] = normalized.split('.').map(Number);
        return first === 0
            || first === 10
            || first === 127
            || (first === 100 && second >= 64 && second <= 127)
            || (first === 169 && second === 254)
            || (first === 172 && second >= 16 && second <= 31)
            || (first === 192 && ((second === 0 && (third === 0 || third === 2)) || (second === 88 && third === 99) || second === 168))
            || (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100)))
            || (first === 203 && second === 0 && third === 113)
            || first >= 224;
    }
    if (family !== 6) return true;
    if (normalized === '::' || normalized === '::1' || normalized.startsWith('::ffff:')) return true;
    if (/^f[cd]/.test(normalized) || /^fe[89a-f]/.test(normalized) || normalized.startsWith('ff')) return true;
    // Block transition ranges that can tunnel an embedded private IPv4 destination.
    if (normalized.startsWith('64:ff9b:') || normalized === '2001::' || normalized.startsWith('2001:0:') || normalized.startsWith('2001:db8:') || normalized.startsWith('2002:')) return true;
    return false;
}

export function assertPublicUrl(raw: string, allowHttp: boolean): URL {
    let url: URL;
    try { url = new URL(raw); } catch { throw new Error('Target URL must be an absolute URL.'); }
    if (!['https:', 'http:'].includes(url.protocol)) throw new Error(PRIVATE_NETWORK_MESSAGE);
    if (url.protocol === 'http:' && !allowHttp) throw new Error('Plain HTTP target rejected. HTTPS is required unless allowHttp is explicitly true.');
    if (url.username || url.password || !url.hostname) throw new Error('Target URL must not contain credentials and must include a hostname.');
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost') || CLOUD_METADATA_HOSTS.has(host) || (isIP(host) !== 0 && isBlockedIp(host))) throw new Error(PRIVATE_NETWORK_MESSAGE);
    return url;
}

export async function resolvePublicTarget(raw: string, allowHttp: boolean): Promise<ResolvedPublicTarget> {
    const url = assertPublicUrl(raw, allowHttp);
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const literalFamily = isIP(host);
    if (literalFamily) return { url, address: host, family: literalFamily as 4 | 6 };
    let records: Awaited<ReturnType<typeof lookup>>[];
    try { records = await lookup(host, { all: true, verbatim: true }); } catch { throw new Error(`DNS resolution failed for ${host}`); }
    if (!records.length || records.some((record) => isBlockedIp(record.address))) throw new Error(PRIVATE_NETWORK_MESSAGE);
    const selected = [...records].sort((left, right) => left.family - right.family || left.address.localeCompare(right.address))[0];
    if (!selected || (selected.family !== 4 && selected.family !== 6)) throw new Error(`DNS resolution returned no supported address for ${host}`);
    return { url, address: selected.address, family: selected.family };
}

export async function assertPublicResolution(url: URL): Promise<void> {
    await resolvePublicTarget(url.toString(), url.protocol === 'http:');
}

export async function assertSafeTarget(raw: string, allowHttp: boolean): Promise<URL> {
    return (await resolvePublicTarget(raw, allowHttp)).url;
}

export function sameOrigin(left: string, right: string): boolean {
    return new URL(left).origin === new URL(right).origin;
}
