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

export function ipv6Groups(input: string): number[] | null {
  if (!input.includes(':')) return null;
  if (input.includes('%') || input.includes('[') || input.includes(']')) return null;
  const doubleColonCount = input.split('::').length - 1;
  if (doubleColonCount > 1) return null;

  let working = input;
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':');
    const v4Part = working.slice(lastColon + 1);
    if (!IPV4_REGEX.test(v4Part)) return null;
    const bytes = v4Part.split('.').map(Number);
    working = working.slice(0, lastColon + 1) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
  }

  const [left, right] = working.split('::');
  const head = left ? left.split(':') : [];
  const tail = right ? right.split(':') : [];
  const hexGroup = /^[0-9a-fA-F]{1,4}$/;
  if (!head.every((g) => hexGroup.test(g)) || !tail.every((g) => hexGroup.test(g))) return null;
  const count = head.length + tail.length;
  if (doubleColonCount ? count >= 8 : count !== 8) return null;
  return [...head.map((g) => parseInt(g, 16)), ...Array(doubleColonCount ? 8 - count : 0).fill(0), ...tail.map((g) => parseInt(g, 16))];
}

export function isValidIpv6(input: string): boolean {
  return ipv6Groups(input) !== null;
}

export function normalizeIpv6(groups: number[]): string {
  let start = -1;
  let length = 1;
  for (let i = 0; i < groups.length;) {
    if (groups[i] !== 0) { i++; continue; }
    let end = i;
    while (end < groups.length && groups[end] === 0) end++;
    if (end - i > length) { start = i; length = end - i; }
    i = end;
  }
  const hex = groups.map((g) => g.toString(16));
  return start < 0 ? hex.join(':') : hex.slice(0, start).join(':') + '::' + hex.slice(start + length).join(':');
}

export function parseCidr(input: string): { ip: ParsedIp; prefix: number | null } | null {
  const parts = input.trim().split('/');
  if (parts.length > 2) return null;
  const ip = parseIp(parts[0]);
  if (!ip) return null;
  if (parts.length === 1) return { ip, prefix: null };
  if (!/^(0|[1-9]\d{0,2})$/.test(parts[1])) return null;
  const prefix = Number(parts[1]);
  return prefix <= (ip.version === 4 ? 32 : 128) ? { ip, prefix } : null;
}

export function parseIp(rawInput: string | null | undefined): ParsedIp | null {
  if (!rawInput) return null;
  const input = rawInput.trim();
  const cleaned = input.startsWith('[') && input.endsWith(']') ? input.slice(1, -1) : input;
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

  const groups = ipv6Groups(cleaned);
  if (groups) {
    let bogonReason: string | undefined;
    const mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
    if (mapped) {
      const v4 = [groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255].join('.');
      bogonReason = parseIp(v4)?.bogonReason;
    } else if (groups.slice(0, 6).every((g) => g === 0)) {
      bogonReason = groups[6] === 0 && groups[7] <= 1 ? 'IPv6 Loopback / Unspecified' : 'Deprecated IPv4-compatible IPv6';
    } else if ((groups[0] & 0xffc0) === 0xfe80) {
      bogonReason = 'RFC 4291 IPv6 Link-Local';
    } else if ((groups[0] & 0xfe00) === 0xfc00) {
      bogonReason = 'RFC 4193 IPv6 Unique Local Address (ULA)';
    } else if ((groups[0] & 0xff00) === 0xff00) {
      bogonReason = 'RFC 4291 IPv6 Multicast';
    } else if (groups[0] === 0x2001 && groups[1] === 0xdb8) {
      bogonReason = 'RFC 3849 IPv6 Documentation Prefix';
    } else if (groups[0] === 0x3fff && (groups[1] & 0xf000) === 0) {
      bogonReason = 'RFC 9637 IPv6 Documentation Prefix';
    } else if (groups[0] === 0x100 && groups.slice(1, 4).every((g) => g === 0)) {
      bogonReason = 'RFC 6666 IPv6 Discard-Only';
    } else if ((groups[0] & 0xffc0) === 0xfec0) {
      bogonReason = 'Deprecated IPv6 Site-Local';
    }
    const isBogon = Boolean(bogonReason);
    return {
      raw: rawInput,
      normalized: normalizeIpv6(groups),
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
