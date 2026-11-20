/**
 * JudgeIP IPv4/IPv6 validation, normalization, and special-range classification.
 */

export type IpVersion = 4 | 6;

export interface ParsedIp {
  raw: string;
  normalized: string;
  version: IpVersion;
  isBogon: boolean;
  bogonReason?: string;
}

const IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function inCidrV4(ipInt: number, base: string, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (ipv4ToInt(base) & mask);
}

const IPV4_BOGON_RANGES: Array<[string, number, string]> = [
  ['0.0.0.0', 8, 'RFC 1122 "This host on this network"'],
  ['10.0.0.0', 8, 'RFC 1918 Private Network'],
  ['100.64.0.0', 10, 'RFC 6598 Carrier-Grade NAT (CGNAT)'],
  ['127.0.0.0', 8, 'RFC 1122 Loopback'],
  ['169.254.0.0', 16, 'RFC 3927 Link-Local'],
  ['172.16.0.0', 12, 'RFC 1918 Private Network'],
  ['192.0.0.0', 24, 'RFC 6890 IETF Protocol Assignments'],
  ['192.0.2.0', 24, 'RFC 5737 Documentation (TEST-NET-1)'],
  ['192.168.0.0', 16, 'RFC 1918 Private Network'],
  ['198.18.0.0', 15, 'RFC 2544 Benchmarking'],
  ['198.51.100.0', 24, 'RFC 5737 Documentation (TEST-NET-2)'],
  ['203.0.113.0', 24, 'RFC 5737 Documentation (TEST-NET-3)'],
  ['224.0.0.0', 4, 'RFC 5771 Multicast'],
  ['240.0.0.0', 4, 'RFC 1112 Reserved for Future Use'],
];

export function isValidIpv6(input: string): boolean {
  if (!input.includes(':')) return false;
  // Reject zone index or port brackets
  if (input.includes('%') || input.includes('[') || input.includes(']')) return false;
  const doubleColonCount = input.split('::').length - 1;
  if (doubleColonCount > 1) return false;

  // Handle IPv4-mapped suffix like ::ffff:192.0.2.1
  let working = input;
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':');
    const v4Part = working.slice(lastColon + 1);
    if (!IPV4_REGEX.test(v4Part)) return false;
    working = working.slice(0, lastColon + 1) + '0:0';
  }

  const [left, right] = working.split('::');
  const leftGroups = left ? left.split(':') : [];
  const rightGroups = right ? right.split(':') : [];
  const hexGroup = /^[0-9a-fA-F]{1,4}$/;

  if (!leftGroups.every((g) => hexGroup.test(g)) || !rightGroups.every((g) => hexGroup.test(g))) {
    return false;
  }

  if (doubleColonCount === 1) {
    return leftGroups.length + rightGroups.length < 8;
  }
  return leftGroups.length === 8;
}

export function parseIp(rawInput: string | null | undefined): ParsedIp | null {
  if (!rawInput) return null;
  const cleaned = rawInput.trim().replace(/^\[|\]$/g, '');
  if (!cleaned || cleaned.length > 45) return null;

  if (IPV4_REGEX.test(cleaned)) {
    const ipInt = ipv4ToInt(cleaned);
    for (const [base, prefix, reason] of IPV4_BOGON_RANGES) {
      if (inCidrV4(ipInt, base, prefix)) {
        return {
          raw: rawInput,
          normalized: cleaned,
          version: 4,
          isBogon: true,
          bogonReason: reason,
        };
      }
    }
    return {
      raw: rawInput,
      normalized: cleaned,
      version: 4,
      isBogon: false,
    };
  }

  const lower = cleaned.toLowerCase();
  if (isValidIpv6(lower)) {
    let isBogon = false;
    let bogonReason: string | undefined;
    if (lower === '::1' || lower === '::') {
      isBogon = true;
      bogonReason = 'IPv6 Loopback / Unspecified';
    } else if (lower.startsWith('fe80:')) {
      isBogon = true;
      bogonReason = 'RFC 4291 IPv6 Link-Local';
    } else if (lower.startsWith('fc') || lower.startsWith('fd')) {
      isBogon = true;
      bogonReason = 'RFC 4193 IPv6 Unique Local Address (ULA)';
    } else if (lower.startsWith('2001:db8:')) {
      isBogon = true;
      bogonReason = 'RFC 3849 IPv6 Documentation Prefix';
    }
    return {
      raw: rawInput,
      normalized: lower,
      version: 6,
      isBogon,
      bogonReason,
    };
  }

  return null;
}

export function extractVisitorIp(request: Request): string {
  const candidates = [
    request.headers.get('cf-connecting-ip'),
    request.headers.get('x-real-ip'),
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim(),
  ];
  for (const candidate of candidates) {
    const parsed = parseIp(candidate);
    if (parsed && !parsed.isBogon) {
      return parsed.normalized;
    }
  }
  // Fallback in local dev when hitting 127.0.0.1 without edge headers:
  // inspect a well-known public resolver or return the local address if explicitly local
  for (const candidate of candidates) {
    const parsed = parseIp(candidate);
    if (parsed) return parsed.normalized;
  }
  return '1.1.1.1';
}
