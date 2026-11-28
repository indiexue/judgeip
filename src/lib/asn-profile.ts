import type { D1Database } from '@cloudflare/workers-types';
import { KNOWN_ASN_PROFILES, type AsnProfile, type UsageType } from './asn-intelligence';

/* ASN 落地页数据层：聚合 RDAP 注册信息、PeeringDB 画像、RIPEstat BGP 统计与本站评分样本。
   每个上游都独立降级：任何一路失败只隐藏对应板块，页面其余部分照常渲染。 */

export interface AsnLiveStats {
  sampleCount: number;
  avgScore: number | null;
  minScore: number | null;
  maxScore: number | null;
}

export interface AsnBgpStats {
  v4Prefixes: number | null;
  v6Prefixes: number | null;
}

export interface AsnPageData {
  asn: number;
  profile: AsnProfile | null;
  type: UsageType;
  displayName: string;
  registeredCountry: string;
  rir: string;
  registeredAt: string | null;
  peeringdb: {
    name: string;
    infoType: string;
    trafficRatio: string;
    trafficVolume: string;
    prefixes4: number | null;
    prefixes6: number | null;
    website: string;
  } | null;
  bgp: AsnBgpStats | null;
  stats: AsnLiveStats | null;
}

const memCache = new Map<number, { exp: number; data: AsnPageData | null }>();
const CACHE_MS = 30 * 60 * 1000;
const CACHE_NEG_MS = 5 * 60 * 1000;

async function fetchJson<T>(url: string, timeoutMs: number): Promise<T | null> {
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': 'JudgeIP/1.0 (+https://judgeip.com)', Accept: 'application/json' },
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

interface RdapAutnum {
  name?: string;
  country?: string;
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  links?: Array<{ rel?: string; href?: string }>;
  entities?: Array<{
    roles?: string[];
    country?: string;
    vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
  }>;
}

/* RDAP 入口（RIPE）会把请求转给负责该 ASN 的 RIR。self 链接的域名暴露真实归属：
   ARIN→美洲、RIPE→欧洲中东、APNIC→亚太、LACNIC→拉美、AFRINIC→非洲。
   国家粒度拿不到时，至少能给出注册局区域，而且这比猜 ISO 国家更诚实。 */
const RIR_BY_HOST: Array<[string, string, string]> = [
  ['arin.net', 'ARIN', 'US'],
  ['ripe.net', 'RIPE NCC', ''],
  ['apnic.net', 'APNIC', ''],
  ['lacnic.net', 'LACNIC', ''],
  ['afrinic.net', 'AFRINIC', ''],
];

function rirFromLinks(links: Array<{ rel?: string; href?: string }> | undefined): { rir: string; country: string } {
  const self = (links || []).find((l) => l.rel === 'self')?.href || '';
  for (const [host, rir, country] of RIR_BY_HOST) {
    if (self.includes(host)) return { rir, country };
  }
  return { rir: '', country: '' };
}

function rdapHolder(rdap: RdapAutnum): { name: string; country: string } {
  for (const entity of rdap.entities || []) {
    if (!entity.roles?.includes('registrant')) continue;
    const vcard = entity.vcardArray?.[1];
    const fn = vcard?.find((row) => row[0] === 'fn')?.[3];
    let country = vcard?.find((row) => row[0] === 'country-name')?.[3];
    if (!country) {
      // ARIN 等注册机构常把国家放在 adr 行（vcard 'adr' 数组第 7 项是国家）
      const adr = vcard?.find((row) => row[0] === 'adr')?.[3];
      if (Array.isArray(adr) && typeof adr[6] === 'string') country = adr[6];
    }
    if (typeof fn === 'string' && fn) {
      return { name: fn, country: typeof country === 'string' ? country : (entity.country || rdap.country || '') };
    }
  }
  return { name: rdap.name || '', country: rdap.country || '' };
}

function rdapRegisteredAt(rdap: RdapAutnum): string | null {
  const event = (rdap.events || []).find((e) => e.eventAction === 'registration');
  return event?.eventDate?.slice(0, 10) || null;
}

interface PeeringDbNet {
  data?: Array<{
    name?: string;
    info_type?: string;
    traffic_ratio?: string;
    traffic_volume?: string;
    info_prefixes4?: number;
    info_prefixes6?: number;
    website?: string;
  }>;
}

interface RipestatPrefixCount {
  data?: {
    prefixes?: Array<{ prefix?: string }>;
  };
}

async function fetchLiveStats(asn: number): Promise<AsnLiveStats | null> {
  try {
    const { env } = await import('cloudflare:workers');
    const db = (env as { RANKINGS_DB?: D1Database }).RANKINGS_DB;
    if (!db) return null;
    // ranking_counts 按 scope=ASN 保存了当前评分规则版本的分数桶。
    // 版本字符串与排名一致，从最近的 ranked_ips 行里取，避免硬编码。
    const versionRow = await db.prepare('SELECT scoring_version FROM ranked_ips ORDER BY updated_at DESC LIMIT 1').first<{ scoring_version: string }>();
    if (!versionRow) return null;
    const rows = await db.prepare(
      'SELECT score, count FROM ranking_counts WHERE scope = ? AND scoring_version = ?',
    ).bind(asn, versionRow.scoring_version).all<{ score: number; count: number }>();
    const buckets = rows.results || [];
    const sampleCount = buckets.reduce((sum, row) => sum + row.count, 0);
    if (sampleCount < 1) return null;
    let weighted = 0;
    let minScore: number | null = null;
    let maxScore: number | null = null;
    for (const row of buckets) {
      weighted += row.score * row.count;
      minScore = minScore === null ? row.score : Math.min(minScore, row.score);
      maxScore = maxScore === null ? row.score : Math.max(maxScore, row.score);
    }
    return { sampleCount, avgScore: Math.round(weighted / sampleCount * 10) / 10, minScore, maxScore };
  } catch {
    return null;
  }
}

async function buildAsnData(asn: number): Promise<AsnPageData | null> {
  const profile = KNOWN_ASN_PROFILES[asn] || null;

  const rdapPromise = fetchJson<RdapAutnum>(`https://rdap.db.ripe.net/autnum/${asn}`, 8000);
  const pdbPromise = fetchJson<PeeringDbNet>(`https://www.peeringdb.com/api/net?asn=${asn}&depth=0`, 2500);
  const ripePromise = fetchJson<RipestatPrefixCount>(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, 12000);
  const statsPromise = fetchLiveStats(asn);

  const [rdap, pdb, ripe, stats] = await Promise.all([rdapPromise, pdbPromise, ripePromise, statsPromise]);

  const holder = rdap ? rdapHolder(rdap) : { name: '', country: '' };
  const displayName = profile?.name || holder.name || pdb?.data?.[0]?.name || '';
  // 什么都没查到说明这个 ASN 根本不存在或未分配——返回 null 让页面 404
  if (!profile && !displayName && !rdap) return null;

  const net = pdb?.data?.[0];
  const registeredAt = rdap ? rdapRegisteredAt(rdap) : null;

  const rirInfo = rdap ? rirFromLinks(rdap.links) : { rir: '', country: '' };

  return {
    asn,
    profile,
    type: profile?.type || typeFromPeeringDb(net?.info_type),
    displayName: displayName || `AS${asn}`,
    registeredCountry: profile?.registeredCountry || normalizeCountry(holder.country) || rirInfo.country || '',
    rir: rirInfo.rir,
    registeredAt,
    peeringdb: net ? {
      name: String(net.name || ''),
      infoType: String(net.info_type || ''),
      trafficRatio: String(net.traffic_ratio || ''),
      trafficVolume: String(net.traffic_volume || ''),
      prefixes4: typeof net.info_prefixes4 === 'number' ? net.info_prefixes4 : null,
      prefixes6: typeof net.info_prefixes6 === 'number' ? net.info_prefixes6 : null,
      website: typeof net.website === 'string' && net.website.startsWith('http') ? net.website : '',
    } : null,
    bgp: ripe?.data?.prefixes ? {
      v4Prefixes: ripe.data.prefixes.filter((p) => p.prefix && !p.prefix.includes(':')).length,
      v6Prefixes: ripe.data.prefixes.filter((p) => p.prefix?.includes(':')).length,
    } : null,
    stats,
  };
}

function typeFromPeeringDb(infoType: string | undefined): UsageType {
  const t = (infoType || '').toLowerCase();
  if (t.includes('cable') || t.includes('dsl') || t.includes('isp')) return 'residential';
  if (t.includes('content')) return 'cdn';
  if (t.includes('education')) return 'education';
  if (t.includes('enterprise') || t.includes('nsp')) return 'business';
  return 'business';
}

function normalizeCountry(raw: string): string {
  const v = raw.trim();
  if (/^[A-Z]{2}$/i.test(v)) return v.toUpperCase();
  const upper = v.toUpperCase();
  const map: Record<string, string> = {
    'UNITED STATES': 'US', USA: 'US', 'UNITED KINGDOM': 'GB', CHINA: 'CN', JAPAN: 'JP',
    GERMANY: 'DE', CANADA: 'CA', AUSTRALIA: 'AU', NETHERLANDS: 'NL', SINGAPORE: 'SG',
    'HONG KONG': 'HK', KOREA: 'KR', 'SOUTH KOREA': 'KR', INDIA: 'IN', BRAZIL: 'BR', FRANCE: 'FR',
  };
  return map[upper] || '';
}

export async function getAsnPageData(asn: number): Promise<AsnPageData | null> {
  const hit = memCache.get(asn);
  if (hit && hit.exp > Date.now()) return hit.data;
  const data = await buildAsnData(asn);
  memCache.set(asn, { exp: Date.now() + (data ? CACHE_MS : CACHE_NEG_MS), data });
  if (memCache.size > 300) {
    const first = memCache.keys().next().value;
    if (first !== undefined) memCache.delete(first);
  }
  return data;
}
