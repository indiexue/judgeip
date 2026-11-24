/**
 * 按网段发布的免费名单（VPN 出口段、Spamhaus DROP、FireHOL level1），构建期编译成排好序、已合并的 IPv4 区间表。
 * 文件格式：'IPRG' + 更新时间（float64）+ 区间数（uint32），之后每段 8 字节：起始、结束地址（uint32，含两端）。
 */
import type { ReputationCheck } from './reputation-feeds';

export interface RangeFeed {
  id: string;
  source: string;
  url: string;
  license: string;
  /* vpn：命中按 VPN 出口计；abuse：命中按信誉名单计 */
  kind: 'vpn' | 'abuse';
  /* 少于这个段数就当作下载不完整，不发布 */
  minRanges: number;
}

export const RANGE_FEEDS: RangeFeed[] = [
  { id: 'x4b-vpn', source: 'X4BNet VPN ranges', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt', license: 'MIT', kind: 'vpn', minRanges: 2000 },
  { id: 'spamhaus-drop', source: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop_v4.json', license: 'Spamhaus DROP terms', kind: 'abuse', minRanges: 300 },
  { id: 'firehol-l1', source: 'FireHOL level1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', license: 'per upstream list', kind: 'abuse', minRanges: 1000 },
];

const MAGIC = 0x49505247;
const MAX_AGE_MS = 8 * 24 * 3600 * 1000;

function ipv4ToInt(ip: string): number | null {
  const octets = ip.split('.');
  if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || String(Number(part)) !== part || Number(part) > 255)) return null;
  return octets.reduce((n, part) => n * 256 + Number(part), 0);
}

/* 每行一个 IPv4 地址或 CIDR；也认 Spamhaus 的逐行 JSON（{"cidr": ...}）。注释、IPv6 和私有格式跳过 */
export function parseRangeList(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const raw of text.split('\n')) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (line.startsWith('{')) {
      try { line = String(JSON.parse(line).cidr || ''); } catch { continue; }
    }
    const [addr, bits = '32'] = line.split(/\s/)[0].split('/');
    const start = ipv4ToInt(addr);
    const prefix = Number(bits);
    if (start === null || !Number.isInteger(prefix) || prefix < 8 || prefix > 32) continue;
    const size = 2 ** (32 - prefix);
    const base = start - (start % size);
    ranges.push([base, base + size - 1]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

export function compileRangeIndex(ranges: Array<[number, number]>, updatedAt: number): Uint8Array {
  const out = new Uint8Array(16 + ranges.length * 8);
  const view = new DataView(out.buffer);
  view.setUint32(0, MAGIC);
  view.setFloat64(4, updatedAt);
  view.setUint32(12, ranges.length);
  ranges.forEach(([start, end], i) => {
    view.setUint32(16 + i * 8, start);
    view.setUint32(20 + i * 8, end);
  });
  return out;
}

interface RangeIndex { view: DataView; count: number; updatedAt: string }

export function parseRangeIndex(data: ArrayBuffer, now = Date.now()): RangeIndex | null {
  if (data.byteLength < 16 || data.byteLength > 4 * 1024 * 1024) return null;
  const view = new DataView(data);
  if (view.getUint32(0) !== MAGIC) return null;
  const timestamp = view.getFloat64(4);
  const count = view.getUint32(12);
  if (!Number.isFinite(timestamp) || timestamp > now + 24 * 3600 * 1000 || now - timestamp > MAX_AGE_MS) return null;
  if (count < 1 || data.byteLength !== 16 + count * 8) return null;
  return { view, count, updatedAt: new Date(timestamp).toISOString() };
}

/* 命中返回所在网段（CIDR 不一定还原得出，返回起止地址），未命中返回 undefined，地址格式不对返回 null */
export function lookupRangeIndex(index: RangeIndex, ip: string): string | undefined | null {
  const value = ipv4ToInt(ip);
  if (value === null) return null;
  let lo = 0, hi = index.count - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const start = index.view.getUint32(16 + mid * 8);
    const end = index.view.getUint32(20 + mid * 8);
    if (value < start) hi = mid - 1;
    else if (value > end) lo = mid + 1;
    else return `${intToIpv4(start)} – ${intToIpv4(end)}`;
  }
  return undefined;
}

function intToIpv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/* 和 IPsum 一样经 ASSETS 绑定读静态文件：每个 isolate 读一次，失败后 60 秒内不重试 */
const loaders = new Map<string, () => Promise<RangeIndex | null>>();

function loaderFor(id: string): () => Promise<RangeIndex | null> {
  const existing = loaders.get(id);
  if (existing) return existing;
  let cached: RangeIndex | null = null;
  let pending: Promise<RangeIndex | null> | null = null;
  let retryAt = 0;
  const load = () => {
    if (cached && Date.now() - Date.parse(cached.updatedAt) <= MAX_AGE_MS) return Promise.resolve(cached);
    if (pending) return pending;
    if (Date.now() < retryAt) return Promise.resolve(null);
    pending = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1200);
      try {
        let readAsset: typeof fetch;
        try {
          const { env } = await import('cloudflare:workers');
          const assets = (env as { ASSETS?: { fetch: typeof fetch } }).ASSETS;
          if (!assets) return null;
          readAsset = assets.fetch.bind(assets);
        } catch {
          readAsset = fetch;
        }
        const response = await readAsset(`https://judgeip.com/assets/data/ranges-${id}.bin`, { signal: controller.signal });
        cached = response.ok ? parseRangeIndex(await response.arrayBuffer()) : null;
      } catch {
        cached = null;
      } finally {
        clearTimeout(timer);
      }
      if (!cached) retryAt = Date.now() + 60_000;
      return cached;
    })().finally(() => { pending = null; });
    return pending;
  };
  loaders.set(id, load);
  return load;
}

export interface RangeCheck extends ReputationCheck {
  kind: RangeFeed['kind'];
  range?: string;
}

export async function checkRangeFeeds(ip: string): Promise<RangeCheck[]> {
  const checkedAt = new Date().toISOString();
  const ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip);
  return Promise.all(RANGE_FEEDS.map(async (feed): Promise<RangeCheck> => {
    const base = { source: feed.source, kind: feed.kind, checkedAt, url: feed.url };
    if (!ipv4) return { ...base, status: 'unavailable' };
    const index = await loaderFor(feed.id)();
    const hit = index ? lookupRangeIndex(index, ip) : null;
    if (!index || hit === null) return { ...base, status: 'unavailable' };
    return { ...base, updatedAt: index.updatedAt, status: hit ? 'listed' : 'not_listed', ...(hit ? { range: hit } : {}) };
  }));
}
