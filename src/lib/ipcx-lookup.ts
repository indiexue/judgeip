import { classifyIspAndAsn, detectDualIsp, KNOWN_ASN_PROFILES, type UsageType } from './asn-intelligence';
import { parseIp } from './ip-utils';
import { rateLimit } from './rate-limit';
import { checkPublicReputation, checkReputationHistory, type ReputationCheck } from './reputation-feeds';
import { checkRangeFeeds } from './range-feeds';
import { CACHE_COMPLETE_MINUTES, CACHE_PARTIAL_SECONDS, CACHE_MAX_ENTRIES } from './data-sources';
import {
  SCORE_BASE,
  SCORE_DELTAS,
  SCORE_GRADES,
  MANY_PORTS_THRESHOLD,
  COVERAGE_CAPS,
  REPUTATION_CAPS,
  type ReputationCoverage,
  clampScore,
  type ScoreConfidence,
  type ScoreFactorKey,
} from './score-rules';

export interface SceneFitItem {
  key: string;
  label: string;
  status: string;
  tone: 'ok' | 'warn' | 'leak';
  note: string;
}

export interface RiskCheckItem {
  label: string;
  status: string;
  tone: 'ok' | 'warn' | 'leak' | 'muted';
  detail?: string;
}

export interface DnsblCheck {
  name: string;
  status: 'listed' | 'not_listed' | 'unknown';
  query?: string; // 实际查询的域名
  answer?: string; // 解析器的原始应答
}

export interface FactorEvidence {
  source: string;
  field: string;
  value: string;
}

export interface ScoreFactor {
  key: ScoreFactorKey;
  label: string;
  status: string;
  delta: number;
  tone: 'ok' | 'warn' | 'leak' | 'muted';
  evidence: FactorEvidence[];
}

export interface OptionalIntelKeys {
  ipapiIsKey?: string;
  abuseIpdbKey?: string;
  proxycheckKey?: string;
  radarToken?: string;
}

export interface LookupSourceEvent {
  id: string;
  label: string;
  status: 'ok' | 'skip' | 'fail';
  /* 失败原因，例如 HTTP 429、timeout、cooldown 或上游返回的错误信息 */
  detail?: string;
}

export interface LookupStreamOptions {
  bypassCache?: boolean;
  onSource?: (event: LookupSourceEvent) => void;
  /* 发起查询的访客 IP。设置后，未命中缓存的全量查询计入该访客的 lookup 预算，超出时只返回基础信息 */
  visitorIp?: string;
}

export interface HomeIpLookupResult {
  ip: string;
  version: 4 | 6;
  isBogon: boolean;
  bogonReason?: string;

  // Network Attributes
  ipTypeLabel: string;
  ipTypeTone: 'green' | 'amber' | 'danger' | 'gray';
  /* 与语言无关的网络类型，平台检测和场景评分按它判断 */
  usageType: UsageType | 'unknown';
  /* 双 ISP：ASN 与地址段登记机构均为电信/宽带运营商，且无代理与机房标记 */
  isDualIsp: boolean;
  isp: string;
  org: string;
  asn: number | null;
  asnCode: string;
  domain: string;
  rirName: string;
  rirCountry: string;
  registrantCountry?: string;
  isNative: boolean | null;
  isDatacenter: boolean | null;
  hasThreat: boolean | null;
  threatLabel: string;
  isProxy: boolean | null;
  proxyLabel: string;
  score: number | null;
  grade: string; // A+ / A / B / C / D / F
  scoreTone: 'good' | 'warn' | 'bad' | 'muted';
  scoreConfidence: ScoreConfidence;
  reputationCoverage: ReputationCoverage;
  reputationChecks: ReputationCheck[];
  scoringVersion: string;
  /* limited：访客查询过于频繁，本次没有请求上游，只有基础信息 */
  lookupStatus: 'complete' | 'partial' | 'unavailable' | 'limited';
  /* lookupStatus 为 limited 时，距离可以重新查询的秒数 */
  retryAfter?: number;
  portsKnown: boolean;
  scoreBase: number;
  factors: ScoreFactor[];

  // Technical & Routing Indicators
  bgpPrefix: string;
  rpkiStatus: 'valid' | 'invalid' | 'not_found' | 'unknown';
  rpkiLabel: string;
  ptrRecord: string;
  /* found：有反向解析；none：权威应答为不存在；failed：没拿到应答 */
  ptrStatus: 'found' | 'none' | 'failed';
  openPorts: number[];
  proxyPorts: number[];
  vulnsCount: number;
  dnsblListed: string[];
  dnsblTotal: number;
  dnsblChecks: DnsblCheck[];
  abuseEmail: string;

  // Scene Fit & Risk Breakdown
  scenes: SceneFitItem[];
  riskChecks: RiskCheckItem[];

  // Geo Attributes
  countryCode: string;
  countryZh: string;
  flagEmoji: string;
  region: string;
  city: string;
  regionEn: string;
  cityEn: string;
  /* 邮编只取给出所显示城市的那个来源，免得城市和邮编对不上 */
  postalCode: string;
  /* 只有配置了 Cloudflare Radar 密钥才有；是整个 ASN 的流量占比 */
  asnTraffic: AsnTrafficShare | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string;
  localTimeHm: string;
  continentZh: string;
}

const SHORT_COUNTRY_ZH: Record<string, string> = {
  CN: '中国大陆',
  HK: '中国香港',
  MO: '中国澳门',
  TW: '中国台湾',
  US: '美国',
  JP: '日本',
  KR: '韩国',
  SG: '新加坡',
  GB: '英国',
  DE: '德国',
  FR: '法国',
  NL: '荷兰',
  CA: '加拿大',
  AU: '澳大利亚',
  RU: '俄罗斯',
  IN: '印度',
  MY: '马来西亚',
  TH: '泰国',
  VN: '越南',
  ID: '印尼',
  PH: '菲律宾',
  BR: '巴西',
};

const CONTINENT_ZH: Record<string, string> = {
  AS: '亚洲',
  NA: '北美洲',
  EU: '欧洲',
  SA: '南美洲',
  OC: '大洋洲',
  AF: '非洲',
  AN: '南极洲',
};

const DNSBL_ZONES: Array<{ zone: string; name: string }> = [
  { zone: 'bl.spamcop.net', name: 'SpamCop' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL' },
  { zone: 'b.barracudacentral.org', name: 'Barracuda' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT' },
];

const WHOIS_EVIDENCE_KEYS = new Set(['inetnum', 'inet6num', 'netrange', 'cidr', 'netname', 'country', 'org-name', 'orgname', 'organization', 'source']);

/* 只保留代理软件专用的默认端口；8080、8888、2053、2083、2087 等也是常见的网页和面板端口，单凭它们不能判为代理 */
const PROXY_PORTS_SET = new Set([1080, 1081, 3128, 8118, 8388, 9050, 10808]);

export function isoToFlag(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
  const up = cc.toUpperCase();
  return String.fromCodePoint(0x1f1e6 + up.charCodeAt(0) - 65, 0x1f1e6 + up.charCodeAt(1) - 65);
}

export function countryCodeToZh(cc: string, fallback = ''): string {
  const up = (cc || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(up)) return fallback || '未知';
  if (SHORT_COUNTRY_ZH[up]) return SHORT_COUNTRY_ZH[up];
  try {
    const dn = new Intl.DisplayNames(['zh-CN'], { type: 'region' });
    return dn.of(up) || fallback || up;
  } catch {
    return fallback || up;
  }
}

export function guessRirByContinentOrCountry(continentCode: string, countryCode: string): string {
  const cc = (countryCode || '').toUpperCase();
  const cont = (continentCode || '').toUpperCase();
  if (['US', 'CA'].includes(cc) || cont === 'NA') return 'ARIN';
  if (cont === 'EU' || ['RU', 'TR', 'IL', 'AE', 'SA', 'IR'].includes(cc)) return 'RIPE NCC';
  if (cont === 'SA') return 'LACNIC';
  if (cont === 'AF') return 'AFRINIC';
  return 'APNIC';
}

export function scoreToCleanGrade(score: number): string {
  return SCORE_GRADES.find((g) => score >= g.min)?.grade || 'F';
}

function formatLocalTime(tz: string): string {
  try {
    return new Intl.DateTimeFormat('zh-CN', {
      timeZone: tz || 'UTC',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(new Date());
  } catch {
    return '';
  }
}

async function resolveOptionalKeys(explicit?: OptionalIntelKeys | null): Promise<OptionalIntelKeys> {
  if (explicit) return explicit;
  try {
    const mod = await import('cloudflare:workers');
    const e = mod.env || {};
    return {
      ipapiIsKey: e.IPAPI_IS_KEY,
      abuseIpdbKey: e.ABUSEIPDB_KEY,
      proxycheckKey: e.PROXYCHECK_KEY,
      radarToken: e.CF_RADAR_TOKEN,
    };
  } catch {
    const p = typeof process !== 'undefined' && process.env ? process.env : {};
    return {
      ipapiIsKey: p.IPAPI_IS_KEY,
      abuseIpdbKey: p.ABUSEIPDB_KEY,
      proxycheckKey: p.PROXYCHECK_KEY,
      radarToken: p.CF_RADAR_TOKEN,
    };
  }
}

/*
 * 免费上游的失败冷却，按主机名、在当前边缘节点内存里记录。
 * 对方返回 429 时按 Retry-After 暂停（最长 5 分钟）；连续 3 次超时、401/403 或 5xx 暂停 1 分钟；额度用尽暂停 15 分钟。
 * 冷却期间直接当作没查到，页面显示该来源未获取，不再继续消耗对方额度。
 */
const upstreamHealth = new Map<string, { failures: number; coolUntil: number; reason: string }>();
const COOLDOWN_FAILURES = 3;
const COOLDOWN_MS = 60 * 1000;
const MAX_COOLDOWN_MS = 5 * 60 * 1000;
/* 免费额度用完（proxycheck 返回 denied、ipwho.is 返回 limit）时暂停更久，额度一般按天或按月恢复 */
const QUOTA_COOLDOWN_MS = 15 * 60 * 1000;

function upstreamCooling(host: string, now = Date.now()): boolean {
  return (upstreamHealth.get(host)?.coolUntil || 0) > now;
}

/* 401 / 403 / 429 / 5xx 和超时都算失败；其余 4xx（如 InternetDB 的 404）是正常答复 */
const FAILED_STATUS = new Set([401, 403, 429]);

function recordUpstream(host: string, res: Response | null, reason: string, now = Date.now()): void {
  if (res && !FAILED_STATUS.has(res.status) && res.status < 500) {
    upstreamHealth.delete(host);
    return;
  }
  const entry = upstreamHealth.get(host) || { failures: 0, coolUntil: 0, reason };
  entry.failures += 1;
  entry.reason = reason;
  if (res?.status === 429) {
    const retry = Number(res.headers.get('retry-after'));
    entry.coolUntil = now + Math.min(MAX_COOLDOWN_MS, Number.isFinite(retry) && retry > 0 ? retry * 1000 : COOLDOWN_MS);
  } else if (entry.failures >= COOLDOWN_FAILURES) {
    entry.coolUntil = now + COOLDOWN_MS;
    entry.failures = 0;
  }
  upstreamHealth.set(host, entry);
}

/* 上游以 200 返回额度用尽等错误时由调用方标记，按额度冷却处理 */
function pauseUpstream(url: string, reason: string, now = Date.now()): void {
  upstreamHealth.set(new URL(url).hostname, { failures: 0, coolUntil: now + QUOTA_COOLDOWN_MS, reason });
}

/* 最近一次失败的原因，冷却中会标明，供流式进度和排查使用 */
function upstreamFailure(url: string, now = Date.now()): string {
  const entry = upstreamHealth.get(new URL(url).hostname);
  if (!entry) return '';
  return entry.coolUntil > now ? `cooldown (${entry.reason})` : entry.reason;
}

const QUOTA_MESSAGE = /limit|exhaust|quota|denied|too many/i;

/* 带冷却的上游请求；冷却中或请求失败返回 null */
async function fetchUpstream(url: string, timeoutMs: number, extraHeaders?: Record<string, string>): Promise<Response | null> {
  const host = new URL(url).hostname;
  if (upstreamCooling(host)) return null;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let res: Response | null = null;
  let reason = 'timeout';
  try {
    res = await fetch(url, {
      signal: ctl.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'JudgeIP/1.0 (+https://judgeip.com)',
        ...(extraHeaders || {}),
      },
    });
    reason = `HTTP ${res.status}`;
    return res;
  } catch (err) {
    if (!ctl.signal.aborted) reason = `network: ${String((err as Error)?.message || err).slice(0, 80)}`;
    return null;
  } finally {
    clearTimeout(timer);
    recordUpstream(host, res, reason);
  }
}

async function fetchJson<T>(url: string, timeoutMs = 2400, extraHeaders?: Record<string, string>): Promise<T | null> {
  const res = await fetchUpstream(url, timeoutMs, extraHeaders);
  if (!res?.ok) return null;
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/* InternetDB 对没有扫描记录的 IP 返回 404，这是明确答复，按空记录处理；超时和其他状态码才算没查到 */
async function fetchShodan<T>(ipv4: string): Promise<T | null> {
  const res = await fetchUpstream(`https://internetdb.shodan.io/${encodeURIComponent(ipv4)}`, 2000);
  if (res?.status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], noRecord: true } as T;
  if (!res?.ok) return null;
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/* Cloudflare Radar：这个 ASN 发往 Cloudflare 的 HTTP 请求里人类与机器流量的占比（近 7 天）。
   这是整个 ASN 的统计，不是单个 IP 的数据；只在配置了 CF_RADAR_TOKEN 时查询，按 ASN 缓存 12 小时 */
export interface AsnTrafficShare { asn: number; human: number; bot: number; dateRange: string }
const radarCache = new Map<number, { exp: number; share: AsnTrafficShare | null }>();

async function fetchRadarBotShare(asn: number, token: string): Promise<AsnTrafficShare | null> {
  const hit = radarCache.get(asn);
  if (hit && hit.exp > Date.now()) return hit.share;
  const resp = await fetchJson<{ success?: boolean; result?: { summary_0?: { human?: string | number; bot?: string | number } } }>(
    `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${asn}&dateRange=7d&format=json`,
    2000,
    { Authorization: `Bearer ${token}` },
  );
  const human = Number(resp?.result?.summary_0?.human);
  const bot = Number(resp?.result?.summary_0?.bot);
  if (!resp?.success || !Number.isFinite(human) || !Number.isFinite(bot) || human < 0 || bot < 0 || Math.abs(human + bot - 100) > 1) return null;
  const share = { asn, human: Math.round(human * 10) / 10, bot: Math.round(bot * 10) / 10, dateRange: '7d' };
  if (radarCache.size > 600) {
    const first = radarCache.keys().next().value;
    if (first !== undefined) radarCache.delete(first);
  }
  radarCache.set(asn, { exp: Date.now() + 12 * 3600 * 1000, share });
  return share;
}

/* PeeringDB 按 ASN 缓存（节点内 6 小时有效，避免重复请求） */
type PeeringDbNetwork = { infoType: string; name: string } | 'not_listed';
const peeringDbCache = new Map<number, { exp: number; network: PeeringDbNetwork }>();

async function fetchPeeringDbType(asn: number): Promise<PeeringDbNetwork | null> {
  const hit = peeringDbCache.get(asn);
  if (hit && hit.exp > Date.now()) return hit.network;
  const res = await fetchUpstream(`https://www.peeringdb.com/api/net?asn=${asn}`, 1600);
  if (!res || (!res.ok && res.status !== 404)) return null;
  let body: { data?: Array<{ name?: string; info_type?: string }>; meta?: { error?: string } } | null;
  try {
    body = await res.json();
  } catch {
    return null;
  }
  if (!Array.isArray(body?.data)) return null;
  const net = body.data[0];
  const notListed = body.data.length === 0 && (res.ok || body.meta?.error === 'Entity not found');
  const network = notListed ? 'not_listed' : res.ok && net
    ? { infoType: String(net.info_type || '').trim(), name: String(net.name || '').trim() }
    : null;
  if (!network) return null;
  if (peeringDbCache.size > 600) {
    const first = peeringDbCache.keys().next().value;
    if (first !== undefined) peeringDbCache.delete(first);
  }
  peeringDbCache.set(asn, { exp: Date.now() + (network === 'not_listed' ? 1 : 6) * 3600 * 1000, network });
  return network;
}

/* ASN 的 RDAP 登记方与注册日期，按 ASN 缓存 6 小时。从 RIPE 入口查，别家的 ASN 会被转到对应 RIR */
const asnHolderCache = new Map<number, { exp: number; holder: AsnHolder | null }>();

export interface AsnHolder { name: string; country: string; registeredAt: string }

async function fetchAsnHolder(asn: number | null): Promise<AsnHolder | null> {
  if (!asn || KNOWN_ASN_PROFILES[asn]) return null;
  const hit = asnHolderCache.get(asn);
  if (hit && hit.exp > Date.now()) return hit.holder;
  const rdap = await fetchJson<{ entities?: RdapEntity[]; events?: Array<{ eventAction?: string; eventDate?: string }> }>(
    `https://rdap.db.ripe.net/autnum/${asn}`,
    2400,
  );
  if (!rdap) return null;
  const party = rdapRegistrant(rdap);
  const holder = party ? { ...party, registeredAt: rdapRegisteredAt(rdap) } : null;
  if (asnHolderCache.size > 600) {
    const first = asnHolderCache.keys().next().value;
    if (first !== undefined) asnHolderCache.delete(first);
  }
  asnHolderCache.set(asn, { exp: Date.now() + 6 * 3600 * 1000, holder });
  return holder;
}

const ARIN_COUNTRY_NAMES: Record<string, string> = {
  'UNITED STATES': 'US',
  USA: 'US',
  CANADA: 'CA',
  'PUERTO RICO': 'PR',
  'VIRGIN ISLANDS': 'VI',
  BERMUDA: 'BM',
  BAHAMAS: 'BS',
  JAMAICA: 'JM',
  'CAYMAN ISLANDS': 'KY',
  BARBADOS: 'BB',
};

function parseRdapFallback(rdap: {
  country?: string;
  port43?: string;
  name?: string;
  startAddress?: string;
  endAddress?: string;
  entities?: Array<{ vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>] }>;
} | null): { rirName: string; rirCountry: string; lines: FactorEvidence[] } {
  if (!rdap || typeof rdap !== 'object') return { rirName: '', rirCountry: '', lines: [] };
  const p43 = String(rdap.port43 || '').toLowerCase();
  const rirName = p43.includes('arin') ? 'ARIN'
    : p43.includes('apnic') ? 'APNIC'
      : p43.includes('ripe') ? 'RIPE NCC'
        : p43.includes('lacnic') ? 'LACNIC'
          : p43.includes('afrinic') ? 'AFRINIC' : '';

  let rirCountry = '';
  const topCountry = String(rdap.country || '').trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(topCountry) && topCountry !== 'EU') {
    rirCountry = topCountry;
  } else if (Array.isArray(rdap.entities)) {
    for (const ent of rdap.entities) {
      for (const prop of ent?.vcardArray?.[1] || []) {
        if (prop[0] !== 'adr') continue;
        const label = String((prop[1] as { label?: string })?.label || '').trim();
        const lastLine = label.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).pop()?.toUpperCase() || '';
        if (/^[A-Z]{2}$/.test(lastLine) && lastLine !== 'EU') {
          rirCountry = lastLine;
          break;
        }
        if (ARIN_COUNTRY_NAMES[lastLine]) {
          rirCountry = ARIN_COUNTRY_NAMES[lastLine];
          break;
        }
      }
      if (rirCountry) break;
    }
  }

  const lines: FactorEvidence[] = [];
  if (rdap.startAddress && rdap.endAddress) {
    lines.push({ source: 'RDAP', field: 'range', value: `${rdap.startAddress} - ${rdap.endAddress}` });
  }
  if (rdap.name) {
    lines.push({ source: 'RDAP', field: 'name', value: String(rdap.name).slice(0, 120) });
  }
  if (rirCountry) {
    lines.push({ source: 'RDAP', field: 'country', value: rirCountry });
  }
  return { rirName, rirCountry, lines };
}

/* 各 RIR 的 RDAP 入口；查到别家的资源时对方会 301/303 转过去，fetch 自动跟随 */
const RDAP_BASES: Record<string, string> = {
  'RIPE NCC': 'https://rdap.db.ripe.net',
  ARIN: 'https://rdap.arin.net/registry',
  APNIC: 'https://rdap.apnic.net',
  LACNIC: 'https://rdap.lacnic.net/rdap',
  AFRINIC: 'https://rdap.afrinic.net/rdap',
};

type RdapEntity = {
  roles?: string[];
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
};

export interface RegistryParty {
  name: string;
  country: string;
}

let regionNames: Intl.DisplayNames | null = null;
let countryNameIndex: Map<string, string> | null = null;

function isRegionCode(code: string): boolean {
  if (!/^[A-Z]{2}$/.test(code) || code === 'EU') return false;
  try {
    regionNames ||= new Intl.DisplayNames(['en'], { type: 'region' });
    return regionNames.of(code) !== code;
  } catch {
    return false;
  }
}

/* 英文国家名 → ISO 代码，用 Intl 现生成，不另外维护名单 */
function countryFromName(text: string): string {
  if (!countryNameIndex) {
    countryNameIndex = new Map(Object.entries(ARIN_COUNTRY_NAMES));
    for (let a = 65; a <= 90; a += 1) {
      for (let b = 65; b <= 90; b += 1) {
        const code = String.fromCharCode(a, b);
        if (isRegionCode(code)) countryNameIndex.set(String(regionNames?.of(code)).toUpperCase(), code);
      }
    }
    countryNameIndex.set('UNITED STATES OF AMERICA', 'US');
    countryNameIndex.set('RUSSIAN FEDERATION', 'RU');
    countryNameIndex.set('UK', 'GB');
  }
  return countryNameIndex.get(text.trim().toUpperCase()) || '';
}

/* 从 vCard 地址里认国家：cc 参数、最后一行的国家名或两位代码、欧洲常见的「LV-2010」式邮编前缀 */
function vcardCountry(entity: RdapEntity): string {
  for (const prop of entity.vcardArray?.[1] || []) {
    if (prop[0] !== 'adr') continue;
    const params = prop[1] || {};
    const cc = String(params.cc || '').trim().toUpperCase();
    if (isRegionCode(cc)) return cc;
    const label = String(params.label || '');
    const last = label.split(/\r?\n|,/).map((l) => l.trim()).filter(Boolean).pop() || '';
    if (isRegionCode(last.toUpperCase()) && last.length === 2) return last.toUpperCase();
    const byName = countryFromName(last);
    if (byName) return byName;
    const postal = label.match(/\b([A-Z]{2})-\d{3,6}\b/);
    if (postal && isRegionCode(postal[1])) return postal[1];
  }
  return '';
}

function vcardText(entity: RdapEntity, key: string): string {
  const prop = (entity.vcardArray?.[1] || []).find((p) => p[0] === key);
  return typeof prop?.[3] === 'string' ? prop[3].trim() : '';
}

/* 取 RDAP 对象的登记机构：优先 kind=org 的 registrant，名字取 fn */
export function rdapRegistrant(rdap: { entities?: RdapEntity[] } | null): RegistryParty | null {
  const registrants = (rdap?.entities || []).filter((e) => e?.roles?.includes('registrant') && vcardText(e, 'fn'));
  // RIPE 记录里 mnt-by 等维护者也挂在 registrant 下（kind=individual），只认机构；没有 kind 时按机构看
  const entity = registrants.find((e) => vcardText(e, 'kind') === 'org') || registrants.find((e) => !vcardText(e, 'kind'));
  if (!entity) return null;
  return { name: vcardText(entity, 'fn').slice(0, 120), country: vcardCountry(entity) };
}

function rdapRegisteredAt(rdap: { events?: Array<{ eventAction?: string; eventDate?: string }> } | null): string {
  const date = rdap?.events?.find((e) => e?.eventAction === 'registration')?.eventDate || '';
  return Number.isFinite(Date.parse(date)) ? new Date(date).toISOString().slice(0, 10) : '';
}

/* 机构名里不区分身份的通用词，比较地址段登记方和 ASN 持有方是否同一家时去掉 */
const GENERIC_ORG_WORDS = new Set([
  'inc', 'llc', 'ltd', 'limited', 'co', 'corp', 'corporation', 'company', 'gmbh', 'ag', 'sa', 'sas', 'srl', 'bv', 'oy', 'ab', 'as', 'sia', 'uab', 'ooo', 'plc', 'pte', 'pty', 'kk', 'the', 'of', 'and', 'de', 'la', 'le', 'du', 'del', 'di', 'da', 'und', 'et', 'y',
  'telecom', 'telecommunications', 'telecommunication', 'telekom', 'communications', 'communication', 'network', 'networks', 'net', 'internet', 'services', 'service', 'solutions', 'group', 'holding', 'holdings', 'global', 'international', 'technologies', 'technology', 'tech', 'digital', 'data', 'cloud', 'online', 'ip', 'isp', 'broadband', 'cable', 'systems', 'media', 'mobile', 'wireless',
]);

function orgTokens(name: string): Set<string> {
  return new Set(name.toLowerCase().replace(/[^a-z0-9\u00c0-\u024f]+/g, ' ').split(' ')
    .filter((w) => w.length >= 2 && !GENERIC_ORG_WORDS.has(w) && !/^as\d+$/.test(w)));
}

/* 两个机构名有共同的特征词即视为同一家；任一方没有特征词时无法判断，返回 null */
export function sameOrganization(a: string, b: string): boolean | null {
  const ta = orgTokens(a);
  const tb = orgTokens(b);
  if (!ta.size || !tb.size) return null;
  for (const w of ta) if (tb.has(w)) return true;
  return false;
}

async function fetchRirAndRouting(
  ip: string,
  onSource?: (ev: LookupSourceEvent) => void,
): Promise<{
  rirName?: string;
  rirCountry?: string;
  bgpPrefix?: string;
  bgpAsn?: number;
  originAsn?: number;
  rpkiStatus?: 'valid' | 'invalid' | 'not_found' | 'unknown';
  ptrRecord?: string;
  ptrStatus?: 'found' | 'none' | 'failed';
  abuseEmail?: string;
  registrant?: RegistryParty | null;
  whoisLines: FactorEvidence[];
}> {
  interface RipeWhois {
    data?: {
      authorities?: string[];
      records?: Array<Array<{ key?: string; value?: string }>>;
    };
  }
  interface RipeRir {
    data?: {
      rirs?: Array<{ rir?: string; country?: string; resource?: string }>;
    };
  }
  interface RipeNetInfo {
    data?: {
      asns?: string[];
      prefix?: string;
    };
  }
  interface RipeReverseDns {
    data?: {
      result?: string[] | null;
      error?: string;
    };
  }
  interface RipeRpki {
    data?: {
      status?: string;
    };
  }

  const [whoisResp, netResp, rdnsResp] = await Promise.all([
    fetchJson<RipeWhois>(`https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`, 3200),
    fetchJson<RipeNetInfo>(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, 2600).then((r) => {
      onSource?.({ id: 'bgp', label: 'RIPEstat BGP', status: r?.data ? 'ok' : 'fail' });
      return r;
    }),
    fetchJson<RipeReverseDns>(`https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${encodeURIComponent(ip)}`, 2200),
  ]);

  let rirName = '';
  const auth = whoisResp?.data?.authorities?.[0]?.toUpperCase() || '';
  if (auth === 'RIPE') rirName = 'RIPE NCC';
  else if (auth) rirName = auth;

  let rirCountry = '';
  let abuseEmail = '';
  const whoisLines: FactorEvidence[] = [];
  for (const group of whoisResp?.data?.records || []) {
    for (const item of group) {
      const k = (item.key || '').toLowerCase();
      const v = (item.value || '').trim();
      if (v && WHOIS_EVIDENCE_KEYS.has(k) && whoisLines.length < 10 && !whoisLines.some((l) => l.field === item.key && l.value === v)) {
        whoisLines.push({ source: 'RIPEstat whois', field: item.key || k, value: v.slice(0, 120) });
      }
      if (!rirCountry && k === 'country' && /^[a-zA-Z]{2}$/.test(v) && v.toUpperCase() !== 'EU') {
        rirCountry = v.toUpperCase();
      }
      if (!rirName && k === 'source' && v) {
        const up = v.toUpperCase();
        rirName = up === 'RIPE' ? 'RIPE NCC' : up;
      }
      if (!abuseEmail && (k === 'abuse-mailbox' || k === 'orgabuseemail' || k === 'e-mail') && v.includes('@')) {
        abuseEmail = v;
      }
    }
  }

  const bgpPrefix = netResp?.data?.prefix || '';
  const bgpAsns = [...new Set((netResp?.data?.asns || []).map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))];
  const bgpAsn = bgpAsns[0];
  const originAsn = bgpAsns.length === 1 ? bgpAsn : undefined;

  // 第二轮并发：地址段的 RDAP 记录（取登记机构和所在国家）与 RPKI。
  // RDAP 同时为 RIPEstat whois 没给 country 的情况兜底；RIPEstat RIR 分配表只在 RDAP 也没给国家时使用。
  const rdapBase = RDAP_BASES[rirName] || RDAP_BASES['RIPE NCC'];
  type RdapIp = Parameters<typeof parseRdapFallback>[0] & { entities?: RdapEntity[] };
  const [rdapRaw, rpkiResp] = await Promise.all([
    fetchJson<RdapIp>(`${rdapBase}/ip/${encodeURIComponent(ip)}`, 2600),
    bgpPrefix && bgpAsn
      ? fetchJson<RipeRpki>(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${bgpAsn}&prefix=${encodeURIComponent(bgpPrefix)}`, 1600)
      : Promise.resolve(null),
  ]);

  const registrant = rdapRegistrant(rdapRaw);
  if (registrant && whoisLines.length < 12) {
    whoisLines.push({ source: 'RDAP', field: 'registrant', value: `${registrant.name}${registrant.country ? ` (${registrant.country})` : ''}` });
  }

  if (!rirCountry) {
    const fromRdap = parseRdapFallback(rdapRaw);
    if (fromRdap.rirCountry) {
      rirCountry = fromRdap.rirCountry;
      if (!rirName && fromRdap.rirName) rirName = fromRdap.rirName;
      for (const line of fromRdap.lines) {
        if (whoisLines.length < 12) whoisLines.push(line);
      }
    } else {
      const rirAlloc = await fetchJson<RipeRir>(`https://stat.ripe.net/data/rir/data.json?resource=${encodeURIComponent(ip)}&lod=2`, 2200);
      const alloc = rirAlloc?.data?.rirs?.find((r) => r?.country && /^[a-zA-Z]{2}$/.test(r.country) && r.country.toUpperCase() !== 'EU');
      if (alloc?.country) {
        rirCountry = alloc.country.toUpperCase();
        if (!rirName && alloc.rir) rirName = alloc.rir === 'RIPE' ? 'RIPE NCC' : alloc.rir;
        if (alloc.resource && whoisLines.length < 12) {
          whoisLines.push({ source: 'RIPEstat rir', field: 'resource', value: alloc.resource });
        }
        if (whoisLines.length < 12) {
          whoisLines.push({ source: 'RIPEstat rir', field: 'country', value: rirCountry });
        }
      }
    }
  }
  onSource?.({ id: 'rir', label: 'RIR / RDAP', status: rirCountry || rirName ? 'ok' : 'fail' });

  const ptrRecord = rdnsResp?.data?.result?.[0] || '';
  // RIPEstat 把 DNS 应答码写在 error 里：NXDOMAIN 或无应答记录才算没设置，超时、SERVFAIL 等算查询失败
  const rdnsError = rdnsResp?.data?.error || '';
  const ptrStatus = ptrRecord ? 'found'
    : rdnsResp?.data && (/NXDOMAIN|no answer|does not contain an answer/i.test(rdnsError) || (!rdnsError && Array.isArray(rdnsResp.data.result))) ? 'none'
    : 'failed';

  let rpkiStatus: 'valid' | 'invalid' | 'not_found' | 'unknown' = 'unknown';
  if (bgpPrefix && bgpAsn) {
    const st = (rpkiResp?.data?.status || '').toLowerCase();
    if (st === 'valid') rpkiStatus = 'valid';
    else if (st.startsWith('invalid')) rpkiStatus = 'invalid';
    else if (st === 'unknown') rpkiStatus = 'not_found';
    onSource?.({ id: 'rpki', label: 'RPKI ROA', status: rpkiStatus !== 'unknown' ? 'ok' : 'fail' });
  } else {
    onSource?.({ id: 'rpki', label: 'RPKI ROA', status: 'skip' });
  }

  return { rirName, rirCountry, bgpPrefix, bgpAsn, originAsn, rpkiStatus, ptrRecord, ptrStatus, abuseEmail, registrant, whoisLines };
}

const DNS_RCODES: Record<number, string> = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

export async function checkIpv4Dnsbl(
  ipv4: string,
  onZone?: (name: string, status: 'listed' | 'not_listed' | 'unknown') => void,
): Promise<DnsblCheck[]> {
  const parsed = parseIp(ipv4);
  if (!parsed || parsed.version !== 4 || parsed.isBogon) {
    return DNSBL_ZONES.map(({ name }) => ({ name, status: 'unknown' }));
  }
  const reversed = parsed.normalized.split('.').reverse().join('.');
  return Promise.all(DNSBL_ZONES.map(async ({ zone, name }): Promise<DnsblCheck> => {
    const query = `${reversed}.${zone}`;
    const res = await fetchJson<{
      Status?: number;
      Answer?: Array<{ type?: number; data?: string }>;
      Authority?: Array<{ type?: number }>;
    }>(`https://1.1.1.1/dns-query?name=${encodeURIComponent(query)}&type=A`, 1600, { Accept: 'application/dns-json' });
    const answers = Array.isArray(res?.Answer) ? res.Answer.filter((a) => a?.type === 1).map((a) => String(a.data || '')) : [];
    const rcode = typeof res?.Status === 'number' ? DNS_RCODES[res.Status] || `RCODE ${res.Status}` : '';
    const answer = answers.length ? `A ${answers.slice(0, 4).join(', ')}` : rcode || undefined;
    // Public-resolver refusals and provider error codes are not clean results.
    if (res?.Status === 0 && answers.length) {
      const st = answers.some((a) => /^127\.0\.0\.[1-9]\d{0,2}$/.test(a)) ? 'listed' : 'unknown';
      onZone?.(name, st);
      return { name, status: st, query, answer };
    }
    if (res?.Answer && !Array.isArray(res.Answer)) {
      onZone?.(name, 'unknown');
      return { name, status: 'unknown', query, answer };
    }
    const authoritativeNegative = (res?.Status === 3 || res?.Status === 0)
      && answers.length === 0 && Array.isArray(res?.Authority) && res.Authority.some((a) => a?.type === 6);
    const finalSt = authoritativeNegative ? 'not_listed' : 'unknown';
    onZone?.(name, finalSt);
    return { name, status: finalSt, query, answer };
  }));
}

/* AI 服务官方不支持的地区（以 OpenAI、Anthropic 公布的支持地区为准取交集） */
const AI_UNSUPPORTED = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'SY', 'CU']);

interface SceneInput {
  usage: UsageType | 'unknown';
  isTor: boolean;
  isVpn: boolean;
  isProxy: boolean | null;
  isNative: boolean | null;
  reputationSeverity: 'none' | 'mild' | 'moderate' | 'severe';
  reputationComplete: boolean;
  countryCode: string;
}

type SceneTone = SceneFitItem['tone'];
const SCENE_STATUS: Record<SceneTone, string> = { ok: '适合', warn: '需注意', leak: '不建议' };

/*
 * 按已查到的网络类型、代理、原生 IP 与信誉记录逐场景给出参考结论。每张卡只写最主要的一条依据；
 * 规则是对常见平台风控做法的归纳，不是平台实测或成功率。
 */
function buildSceneFitMatrix(input: SceneInput): SceneFitItem[] {
  const { usage, isTor, isVpn, isProxy, isNative, reputationSeverity, reputationComplete, countryCode } = input;
  const hosting = usage === 'hosting' || usage === 'cdn';
  const consumer = usage === 'residential' || usage === 'mobile' || usage === 'education';
  const proxied = isProxy === true;

  const judge = (key: string): [SceneTone, string] => {
    if (isTor) return ['leak', 'Tor 出口普遍被拦截或要求验证'];
    if (reputationSeverity === 'severe') return ['leak', '有较重的滥用记录'];
    const strict = key === 'ecommerce' || key === 'payment' || key === 'ads' || key === 'social';
    if (reputationSeverity === 'moderate') return strict ? ['leak', '有滥用或扫描记录'] : ['warn', '有滥用或扫描记录'];
    if (key === 'ai' && AI_UNSUPPORTED.has(countryCode)) return ['leak', '所在地区不在官方支持范围'];

    let verdict: [SceneTone, string];
    if (usage === 'unknown') verdict = ['warn', '网络类型未知'];
    else if (key === 'gaming') verdict = isVpn ? ['warn', 'VPN 出口可能被反作弊限制'] : ['ok', '网络类型对联机影响不大'];
    else if (proxied) verdict = key === 'ai' || key === 'streaming' ? ['warn', '代理 / VPN 出口，可能被识别'] : ['leak', '代理 / VPN 出口，容易触发风控'];
    else if (hosting) {
      verdict = key === 'ai' ? ['warn', '机房 IP，网页端可能频繁验证']
        : key === 'payment' || key === 'crypto' ? ['warn', '机房 IP，可能需要额外验证']
          : key === 'streaming' ? ['leak', '机房 IP，多数平台限制或只给自制内容']
            : ['leak', '机房 IP，容易触发风控'];
    } else if (usage === 'business') verdict = ['warn', '商业网络，平台对其判断不一'];
    else if (consumer && isNative === false) verdict = ['warn', '注册地与定位不一致，可能被识别为其他地区'];
    else if (consumer && isNative === true) verdict = ['ok', '原生家宽或移动网络'];
    else verdict = ['warn', '原生状态未知'];

    if (verdict[0] === 'ok' && reputationSeverity === 'mild') return ['warn', '有黑名单或漏洞记录'];
    if (verdict[0] === 'ok' && !reputationComplete) return ['warn', '信誉数据不完整，建议实测'];
    return verdict;
  };

  return [
    ['ecommerce', '跨境电商'], ['payment', '跨境支付'], ['ai', 'AI 应用'], ['social', '社媒运营'],
    ['ads', '广告投放'], ['streaming', '流媒体解锁'], ['gaming', '游戏联机'], ['crypto', '加密货币'],
  ].map(([key, label]) => {
    const [tone, note] = judge(key);
    return { key, label, status: SCENE_STATUS[tone], tone, note };
  });
}

const memCache = new Map<string, { exp: number; data: HomeIpLookupResult }>();
/* 同一个 IP 正在查询时，后来的请求共享这次结果，不重复请求上游 */
const inflight = new Map<string, Promise<HomeIpLookupResult>>();

const LIMITED_LABEL = '查询过于频繁，稍后重试';

/* 访客超出 lookup 预算时的结果：不请求任何上游，只给出 IP 本身和（查看本机时）Cloudflare 随请求附带的归属，其余项明确为未获取 */
function limitedLookup(parsed: NonNullable<ReturnType<typeof parseIp>>, cf: Record<string, unknown> | null, retryAfter: number): HomeIpLookupResult {
  const countryCode = String(cf?.country || '').toUpperCase();
  const asn = cf?.asn ? Number(cf.asn) || null : null;
  const isp = (cf?.asOrganization as string) || '—';
  const timezone = (cf?.timezone as string) || '—';
  const city = (cf?.city as string) || '—';
  const region = (cf?.region as string) || '—';
  return {
    ip: parsed.normalized,
    version: parsed.version,
    isBogon: false,
    ipTypeLabel: '未知',
    ipTypeTone: 'gray',
    usageType: 'unknown',
    isDualIsp: false,
    isp,
    org: isp,
    asn,
    asnCode: asn ? `AS${asn}` : '—',
    domain: '—',
    rirName: '—',
    rirCountry: '',
    isNative: null,
    isDatacenter: null,
    hasThreat: null,
    threatLabel: LIMITED_LABEL,
    isProxy: null,
    proxyLabel: LIMITED_LABEL,
    score: null,
    grade: '—',
    scoreTone: 'muted',
    scoreConfidence: 'none',
    reputationCoverage: 'unavailable',
    reputationChecks: [],
    scoringVersion: '2026-11-23',
    lookupStatus: 'limited',
    retryAfter,
    portsKnown: false,
    scoreBase: SCORE_BASE,
    factors: [],
    bgpPrefix: '—',
    rpkiStatus: 'unknown',
    rpkiLabel: 'RPKI 状态未知',
    ptrRecord: '—',
    ptrStatus: 'failed',
    openPorts: [],
    proxyPorts: [],
    vulnsCount: 0,
    dnsblListed: [],
    dnsblTotal: DNSBL_ZONES.length,
    dnsblChecks: [],
    abuseEmail: '—',
    scenes: [],
    riskChecks: [],
    countryCode,
    countryZh: countryCode ? countryCodeToZh(countryCode, countryCode) : '未知',
    flagEmoji: isoToFlag(countryCode),
    region,
    city,
    regionEn: region,
    cityEn: city,
    postalCode: (cf?.postalCode as string) || '—',
    asnTraffic: null,
    latitude: null,
    longitude: null,
    timezone,
    localTimeHm: formatLocalTime(timezone),
    continentZh: CONTINENT_ZH[String(cf?.continent || '').toUpperCase()] || '未知',
  };
}

export const STREAM_SOURCES: Array<{ id: string; label: string }> = [
  { id: 'ipwhois', label: 'ipwho.is' },
  { id: 'ipquery', label: 'ipquery.io' },
  { id: 'proxycheck', label: 'proxycheck.io' },
  { id: 'rir', label: 'RIR / RDAP' },
  { id: 'bgp', label: 'RIPEstat BGP' },
  { id: 'rpki', label: 'RPKI ROA' },
  { id: 'shodan', label: 'Shodan InternetDB' },
  { id: 'dnsbl', label: '4× DNSBL' },
  { id: 'peeringdb', label: 'PeeringDB / ASN' },
  { id: 'ipsum', label: 'IPsum' },
  { id: 'ranges', label: 'X4B / DROP / FireHOL' },
];

export async function lookupIpFull(
  rawIp: string,
  cfMeta?: Record<string, unknown> | null,
  isSelf = false,
  optionalKeys?: OptionalIntelKeys | null,
  streamOpts?: LookupStreamOptions,
): Promise<HomeIpLookupResult> {
  // 访客自己的查询带有 Cloudflare 信息，流式查询要逐源回报进度，这两类不合流
  const parsed = parseIp(rawIp);
  const shareable = parsed && !parsed.isBogon && !isSelf && !optionalKeys && !streamOpts?.onSource && !streamOpts?.bypassCache;
  if (!shareable) return runLookup(rawIp, cfMeta, isSelf, optionalKeys, streamOpts);
  const pending = inflight.get(parsed.normalized);
  if (pending) {
    const shared = await pending;
    // 发起者超出了自己的预算，不代表后来者也超出
    return shared.lookupStatus === 'limited' ? runLookup(rawIp, cfMeta, isSelf, optionalKeys, streamOpts) : shared;
  }
  const task = runLookup(rawIp, cfMeta, isSelf, optionalKeys, streamOpts).finally(() => inflight.delete(parsed.normalized));
  inflight.set(parsed.normalized, task);
  return task;
}

async function runLookup(
  rawIp: string,
  cfMeta?: Record<string, unknown> | null,
  isSelf = false,
  optionalKeys?: OptionalIntelKeys | null,
  streamOpts?: LookupStreamOptions,
): Promise<HomeIpLookupResult> {
  const parsed = parseIp(rawIp);
  if (!parsed) {
    throw new Error('无效的 IP 地址');
  }

  if (parsed.isBogon) {
    return {
      ip: parsed.normalized,
      version: parsed.version,
      isBogon: true,
      bogonReason: parsed.bogonReason,
      ipTypeLabel: '保留地址',
      ipTypeTone: 'gray',
      usageType: 'reserved',
      isDualIsp: false,
      isp: parsed.bogonReason || 'IANA Reserved',
      org: '本地 / 内网保留网段',
      asn: null,
      asnCode: '—',
      domain: '—',
      rirName: 'IANA',
      rirCountry: '',
      isNative: null,
      isDatacenter: null,
      hasThreat: null,
      threatLabel: '不适用',
      isProxy: null,
      proxyLabel: '不适用',
      score: null,
      grade: '—',
      scoreTone: 'muted',
      scoreConfidence: 'none',
      reputationCoverage: 'unavailable',
      reputationChecks: [],
      scoringVersion: '2026-11-23',
      lookupStatus: 'unavailable',
      portsKnown: false,
      scoreBase: SCORE_BASE,
      factors: [],
      bgpPrefix: '—',
      rpkiStatus: 'unknown',
      rpkiLabel: '不适用',
      ptrRecord: '—',
      ptrStatus: 'none',
      openPorts: [],
      proxyPorts: [],
      vulnsCount: 0,
      dnsblListed: [],
      dnsblTotal: DNSBL_ZONES.length,
      dnsblChecks: [],
      abuseEmail: '—',
      scenes: [],
      riskChecks: [],
      countryCode: '',
      countryZh: '内网 / 保留地址',
      flagEmoji: '',
      region: '—',
      city: '—',
      regionEn: '—',
      cityEn: '—',
      postalCode: '—',
      asnTraffic: null,
      latitude: null,
      longitude: null,
      timezone: '—',
      localTimeHm: '',
      continentZh: '—',
    };
  }

  const cacheKey = parsed.normalized;
  const cached = memCache.get(cacheKey);
  if (cached && cached.exp > Date.now() && !isSelf && !streamOpts?.bypassCache) {
    if (streamOpts?.onSource) {
      for (const src of STREAM_SOURCES) {
        const publicCheck = cached.data.reputationChecks.find((check) => check.source === 'IPsum');
        const status = src.id === 'ipsum' && (!publicCheck || publicCheck.status === 'unavailable') ? 'fail' : 'ok';
        streamOpts.onSource({ id: src.id, label: src.label, status });
      }
    }
    return { ...cached.data, localTimeHm: formatLocalTime(cached.data.timezone) };
  }

  if (streamOpts?.visitorIp) {
    const rate = rateLimit('lookup', streamOpts.visitorIp);
    if (!rate.ok) {
      for (const src of STREAM_SOURCES) streamOpts.onSource?.({ id: src.id, label: src.label, status: 'skip' });
      return limitedLookup(parsed, isSelf ? cfMeta || null : null, rate.resetIn);
    }
  }

  const keys = await resolveOptionalKeys(optionalKeys);

  interface IpWhoResp {
    success?: boolean;
    message?: string;
    continent_code?: string;
    country_code?: string;
    country?: string;
    region?: string;
    city?: string;
    postal?: string;
    latitude?: number;
    longitude?: number;
    connection?: { asn?: number; org?: string; isp?: string; domain?: string };
    timezone?: { id?: string };
    security?: { proxy?: boolean; vpn?: boolean; tor?: boolean; hosting?: boolean };
  }

  interface IpQueryResp {
    ip?: string;
    isp?: { asn?: string; org?: string; isp?: string };
    location?: {
      country?: string;
      country_code?: string;
      city?: string;
      state?: string;
      zipcode?: string;
      latitude?: number;
      longitude?: number;
      timezone?: string;
    };
    risk?: {
      is_mobile?: boolean;
      is_vpn?: boolean;
      is_tor?: boolean;
      is_proxy?: boolean;
      is_datacenter?: boolean;
      risk_score?: number;
    };
  }

  interface ProxyCheckEntry {
    asn?: string;
    provider?: string;
    organisation?: string;
    country?: string;
    isocode?: string;
    region?: string;
    city?: string;
    postcode?: string;
    timezone?: string;
    latitude?: number;
    longitude?: number;
    proxy?: string; // "yes" | "no"
    type?: string;  // "VPN" | "TOR" | "Hosting" | "Business" | "ISP" | "Wireless" | "Residential"
    risk?: number;  // 0 - 100
  }

  interface IpapiIsResp {
    ip?: string;
    is_mobile?: boolean;
    is_datacenter?: boolean;
    is_tor?: boolean;
    is_proxy?: boolean;
    is_vpn?: boolean;
    is_abuser?: boolean;
    company?: { name?: string; domain?: string; type?: string; abuser_score?: string };
    asn?: { asn?: number; org?: string; domain?: string; type?: string; country?: string; abuser_score?: string };
    location?: { country_code?: string; state?: string; city?: string; zip?: string; timezone?: string; latitude?: number; longitude?: number };
  }

  interface AbuseIpdbResp {
    data?: {
      abuseConfidenceScore?: number;
      totalReports?: number;
      usageType?: string;
      isp?: string;
      domain?: string;
      isTor?: boolean;
    };
  }

  interface ShodanResp {
    ports?: number[];
    hostnames?: string[];
    tags?: string[];
    vulns?: string[];
    noRecord?: boolean;
  }

  const proxyCheckUrl = `https://proxycheck.io/v2/${encodeURIComponent(parsed.normalized)}?vpn=1&asn=1&risk=1${
    keys.proxycheckKey ? `&key=${encodeURIComponent(keys.proxycheckKey)}` : ''
  }`;

  const ipWhoUrl = `https://ipwho.is/${encodeURIComponent(parsed.normalized)}?lang=en`;
  const ipQueryUrl = `https://api.ipquery.io/${encodeURIComponent(parsed.normalized)}?format=json`;
  const onSrc = streamOpts?.onSource;
  const [ipWhoRaw, ipQueryRaw, proxyCheckRaw, shodanRaw, routing, dnsblChecks, ipapiIsRaw, abuseRaw, [publicReputation, reputationHistory], rangeChecks] = await Promise.all([
    fetchJson<IpWhoResp>(ipWhoUrl, 2300).then((r) => {
      const ok = r?.success === true;
      const message = r && !ok ? String(r.message || 'success: false') : '';
      if (message && QUOTA_MESSAGE.test(message)) pauseUpstream(ipWhoUrl, message.slice(0, 80));
      onSrc?.({ id: 'ipwhois', label: 'ipwho.is', status: ok ? 'ok' : 'fail', ...(ok ? {} : { detail: message.slice(0, 120) || upstreamFailure(ipWhoUrl) }) });
      return r;
    }),
    fetchJson<IpQueryResp>(ipQueryUrl, 2200).then((r) => {
      onSrc?.({ id: 'ipquery', label: 'ipquery.io', status: r?.ip ? 'ok' : 'fail', ...(r?.ip ? {} : { detail: upstreamFailure(ipQueryUrl) }) });
      return r;
    }),
    fetchJson<Record<string, unknown>>(proxyCheckUrl, 2200).then((r) => {
      const ok = Boolean(r && (r.status === 'ok' || r.status === 'warning'));
      const message = r && !ok ? `${String(r.status || '')}: ${String(r.message || '')}` : '';
      if (!ok && (r?.status === 'denied' || QUOTA_MESSAGE.test(String(r?.message || '')))) pauseUpstream(proxyCheckUrl, message.slice(0, 80));
      onSrc?.({ id: 'proxycheck', label: 'proxycheck.io', status: ok ? 'ok' : 'fail', ...(ok ? {} : { detail: message.slice(0, 120) || upstreamFailure(proxyCheckUrl) }) });
      return r;
    }),
    parsed.version === 4
      ? fetchShodan<ShodanResp>(parsed.normalized).then((r) => {
          onSrc?.({ id: 'shodan', label: 'Shodan InternetDB', status: r ? 'ok' : 'fail' });
          return r;
        })
      : Promise.resolve(null).then((r) => {
          onSrc?.({ id: 'shodan', label: 'Shodan InternetDB', status: 'skip' });
          return r;
        }),
    fetchRirAndRouting(parsed.normalized, onSrc),
    parsed.version === 4
      ? checkIpv4Dnsbl(parsed.normalized).then((checks) => {
          const okCount = checks.filter((c) => c.status !== 'unknown').length;
          onSrc?.({ id: 'dnsbl', label: '4× DNSBL', status: okCount >= 2 ? 'ok' : 'fail' });
          return checks;
        })
      : Promise.resolve([] as DnsblCheck[]).then((checks) => {
          onSrc?.({ id: 'dnsbl', label: '4× DNSBL', status: 'skip' });
          return checks;
        }),
    // 方案 B 可选增强源：配置了 Key 时并发接入 ipapi.is 与 AbuseIPDB
    keys.ipapiIsKey
      ? fetchJson<IpapiIsResp>(`https://api.ipapi.is/?q=${encodeURIComponent(parsed.normalized)}&key=${encodeURIComponent(keys.ipapiIsKey)}`, 2300)
      : Promise.resolve(null),
    keys.abuseIpdbKey
      ? fetchJson<AbuseIpdbResp>(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(parsed.normalized)}&maxAgeInDays=90`,
          2300,
          { Key: keys.abuseIpdbKey }
        )
      : Promise.resolve(null),
    Promise.all([checkPublicReputation(parsed.normalized), checkReputationHistory(parsed.normalized)]).then((checks) => {
      onSrc?.({ id: 'ipsum', label: 'IPsum', status: checks[0].status === 'unavailable' ? 'fail' : 'ok' });
      return checks;
    }),
    checkRangeFeeds(parsed.normalized).then((checks) => {
      onSrc?.({ id: 'ranges', label: 'X4B / DROP / FireHOL', status: parsed.version !== 4 ? 'skip' : checks.some((c) => c.status === 'unavailable') ? 'fail' : 'ok' });
      return checks;
    }),
  ]);

  // 严格校验各上游返回：空对象（如测试桩默认返回）或错误状态不采信
  const ipWho = ipWhoRaw?.success === true ? ipWhoRaw : null;
  const ipQuery = ipQueryRaw && ipQueryRaw.ip && (ipQueryRaw.isp || ipQueryRaw.risk || ipQueryRaw.location) ? ipQueryRaw : null;
  const pcEntry: ProxyCheckEntry | null =
    proxyCheckRaw && (proxyCheckRaw.status === 'ok' || proxyCheckRaw.status === 'warning')
      && typeof proxyCheckRaw[parsed.normalized] === 'object' && proxyCheckRaw[parsed.normalized] !== null
      ? (proxyCheckRaw[parsed.normalized] as ProxyCheckEntry)
      : null;
  const ipapiIs = ipapiIsRaw && typeof ipapiIsRaw.asn === 'object' && ipapiIsRaw.asn !== null ? ipapiIsRaw : null;
  const abuseData = abuseRaw && typeof abuseRaw.data?.abuseConfidenceScore === 'number'
    && Number.isFinite(abuseRaw.data.abuseConfidenceScore) && abuseRaw.data.abuseConfidenceScore >= 0
    && abuseRaw.data.abuseConfidenceScore <= 100 ? abuseRaw.data : null;

  const shodan = shodanRaw && Array.isArray(shodanRaw.ports) && Array.isArray(shodanRaw.tags)
    && Array.isArray(shodanRaw.vulns) ? shodanRaw : null;
  const dnsblAnswered = dnsblChecks.filter((c) => c.status !== 'unknown').length;
  const dnsblListed = dnsblChecks.filter((c) => c.status === 'listed').map((c) => c.name);
  const dnsblComplete = parsed.version === 4 && dnsblChecks.length === DNSBL_ZONES.length
    && dnsblAnswered === DNSBL_ZONES.length;

  const cf = isSelf && cfMeta ? cfMeta : null;
  const countryCode = (
    (cf?.country as string)
    || ipWho?.country_code
    || ipQuery?.location?.country_code
    || pcEntry?.isocode
    || ipapiIs?.location?.country_code
    || ''
  ).toUpperCase();
  const continentCode = ((cf?.continent as string) || ipWho?.continent_code || '').toUpperCase();
  const countryZh = countryCodeToZh(countryCode, ipWho?.country || ipQuery?.location?.country || pcEntry?.country || countryCode);
  const flagEmoji = isoToFlag(countryCode);
  const region = ipWho?.region || ipQuery?.location?.state || pcEntry?.region || ipapiIs?.location?.state || (cf?.region as string) || '—';
  const city = ipWho?.city || ipQuery?.location?.city || pcEntry?.city || ipapiIs?.location?.city || (cf?.city as string) || '—';
  const postalCode = ([
    [ipWho?.city, ipWho?.postal],
    [ipQuery?.location?.city, ipQuery?.location?.zipcode],
    [pcEntry?.city, pcEntry?.postcode],
    [ipapiIs?.location?.city, ipapiIs?.location?.zip],
    // 只有查访客自己的出口时才有 Cloudflare 的 request.cf
    [cf?.city as string | undefined, cf?.postalCode as string | undefined],
  ] as Array<[string | undefined, string | undefined]>).find(([c, zip]) => c === city && zip && /^[\w -]{2,12}$/.test(zip.trim()))?.[1]?.trim() || '—';
  const englishPlace = (...values: unknown[]) => values.find((v): v is string => typeof v === 'string' && Boolean(v) && !/[\p{Script=Han}]/u.test(v)) || '—';
  const regionEn = englishPlace(ipWho?.region, ipQuery?.location?.state, pcEntry?.region, ipapiIs?.location?.state, cf?.region);
  const cityEn = englishPlace(ipWho?.city, ipQuery?.location?.city, pcEntry?.city, ipapiIs?.location?.city, cf?.city);
  const latitude = ipWho?.latitude ?? ipQuery?.location?.latitude ?? pcEntry?.latitude ?? ipapiIs?.location?.latitude ?? (cf?.latitude ? Number(cf.latitude) : null);
  const longitude = ipWho?.longitude ?? ipQuery?.location?.longitude ?? pcEntry?.longitude ?? ipapiIs?.location?.longitude ?? (cf?.longitude ? Number(cf.longitude) : null);
  const timezone = ipWho?.timezone?.id || ipQuery?.location?.timezone || pcEntry?.timezone || ipapiIs?.location?.timezone || (cf?.timezone as string) || '—';

  const parseAsnStr = (s?: string) => (s ? Number((s.match(/(\d+)/) || [])[1]) || null : null);
  // BGP 只有一个源 ASN 时以它为准：上游库的 ASN 可能还是转租前的旧记录
  const asn = routing.originAsn
    || (cf?.asn ? Number(cf.asn) : null)
    || ipWho?.connection?.asn
    || ipapiIs?.asn?.asn
    || parseAsnStr(ipQuery?.isp?.asn)
    || parseAsnStr(pcEntry?.asn)
    || routing.bgpAsn
    || null;
  const profile = asn ? KNOWN_ASN_PROFILES[asn] : undefined;

  // 若 ASN 不在内置表里，顺手查一次带 6h 缓存的 PeeringDB 拿到真实登记类型，同时查 ASN 的 RDAP 登记方
  // PeeringDB 返回 'not_listed' 表示确认未登记，null 表示没查到结果（超时或报错），两者不能混用
  const radarShare = asn && keys.radarToken ? fetchRadarBotShare(asn, keys.radarToken) : Promise.resolve(null);
  const [peeringDbResult, asnHolder] = asn && !profile ? await Promise.all([fetchPeeringDbType(asn), fetchAsnHolder(asn)]) : [null, null];
  const asnTraffic = await radarShare;
  const peeringDb = peeringDbResult && peeringDbResult !== 'not_listed' && peeringDbResult.infoType ? peeringDbResult : null;
  onSrc?.({
    id: 'peeringdb',
    label: 'PeeringDB / ASN',
    status: profile || peeringDbResult ? 'ok' : asn ? 'fail' : 'skip',
  });

  const isp = ipWho?.connection?.isp
    || ipQuery?.isp?.isp
    || pcEntry?.provider
    || ipapiIs?.company?.name
    || abuseData?.isp
    || (cf?.asOrganization as string)
    || profile?.name
    || peeringDb?.name
    || '未知';
  const org = ipWho?.connection?.org
    || ipQuery?.isp?.org
    || pcEntry?.organisation
    || ipapiIs?.asn?.org
    || (cf?.asOrganization as string)
    || isp;

  let domain = ipWho?.connection?.domain || ipapiIs?.company?.domain || ipapiIs?.asn?.domain || abuseData?.domain || '';
  if (!domain && org) {
    if (/tencent/i.test(isp + org)) domain = 'tencent.com';
    else if (/alibaba|aliyun/i.test(isp + org)) domain = 'alibabacloud.com';
    else if (/cloudflare/i.test(isp + org)) domain = 'cloudflare.com';
    else if (/google/i.test(isp + org)) domain = 'google.com';
    else if (/amazon|aws/i.test(isp + org)) domain = 'amazonaws.com';
    else if (/comcast/i.test(isp + org)) domain = 'comcast.com';
    else if (/chunghwa|hinet/i.test(isp + org)) domain = 'hinet.net';
    else if (asn) domain = `as${asn}.net`;
  }

  const pcTypeLow = String(pcEntry?.type || '').trim().toLowerCase();
  const ipapiCompanyType = ipapiIs?.company?.type || '';
  const ipapiAsnType = ipapiIs?.asn?.type || '';

  const upstreamHosting = Boolean(
    ipWho?.security?.hosting
    || ipQuery?.risk?.is_datacenter
    || ipapiIs?.is_datacenter
    || pcTypeLow === 'hosting'
    || ipapiCompanyType.toLowerCase() === 'hosting'
  );
  const upstreamMobile = Boolean(
    ipQuery?.risk?.is_mobile
    || ipapiIs?.is_mobile
    || pcTypeLow === 'wireless'
  );
  const upstreamTypeHint = ipapiCompanyType || ipapiAsnType
    || (pcTypeLow === 'isp' || pcTypeLow === 'residential' ? 'isp' : pcTypeLow === 'business' ? 'business' : '');

  // 租用地址段：地址段登记方和宣告它的 ASN 不是同一家，且 ASN 注册不满两年或没有 PeeringDB 登记。
  // 这类段多是转租给代理、VPN 或机房使用的，不能凭运营商名字里的 Telecom 判成家庭宽带。内置 ASN 表里的运营商不做这项判断。
  const registrant = routing.registrant || null;
  const asnAgeDays = asnHolder?.registeredAt ? (Date.now() - Date.parse(asnHolder.registeredAt)) / 86400000 : null;
  const youngAsn = asnAgeDays !== null && asnAgeDays < 730;
  const leasedRange = !profile && Boolean(registrant && asnHolder)
    && sameOrganization(registrant?.name || '', asnHolder?.name || '') === false && (youngAsn || peeringDbResult === 'not_listed');

  const hasOperatorIdentity = Boolean(asn || (isp !== '未知' && isp !== '—'));
  const classified: UsageType | 'unknown' = hasOperatorIdentity
    ? classifyIspAndAsn(asn, `${isp} ${org}`, upstreamHosting, upstreamMobile, peeringDb?.infoType, upstreamTypeHint)
    : 'unknown';
  const usage: UsageType | 'unknown' = leasedRange && (classified === 'residential' || classified === 'mobile') ? 'business' : classified;

  const networkKnown = usage !== 'unknown' && hasOperatorIdentity;
  const isDatacenter = networkKnown ? usage === 'hosting' || usage === 'cdn' : null;

  let ipTypeLabel = '家庭宽带';
  let ipTypeTone: 'green' | 'amber' | 'danger' | 'gray' = 'green';
  if (usage === 'hosting') {
    ipTypeLabel = '数据中心';
    ipTypeTone = 'danger';
  } else if (usage === 'cdn') {
    ipTypeLabel = 'CDN / 任播';
    ipTypeTone = 'amber';
  } else if (usage === 'mobile') {
    ipTypeLabel = '移动网络';
    ipTypeTone = 'green';
  } else if (usage === 'education') {
    ipTypeLabel = '教育网';
    ipTypeTone = 'green';
  } else if (usage === 'business') {
    ipTypeLabel = '商业网络';
    ipTypeTone = 'gray';
  }
  if (!networkKnown) {
    ipTypeLabel = '未知';
    ipTypeTone = 'gray';
  }

  const rirName = routing.rirName || '—';
  const rirCountry = (routing.rirCountry || ipapiIs?.asn?.country || '').toUpperCase();
  // 广播 IP：地址段的国家字段写成了定位国家，但登记机构在别国（如拉脱维亚公司登记、标成美国的段）。
  // 内置 ASN 表里的家宽和移动运营商不做这项判断，跨国运营商的子公司段常由总部登记。
  const verifiedCarrier = profile?.type === 'residential' || profile?.type === 'mobile';
  const registrantAbroad = !verifiedCarrier && Boolean(registrant?.country && countryCode) && registrant?.country !== countryCode;
  const isNative = countryCode && rirCountry ? usage !== 'cdn' && rirCountry === countryCode && !registrantAbroad : null;

  const tags = (shodan?.tags || []).map((t) => t.toLowerCase());
  const vulnsCount = shodan?.vulns?.length || 0;
  const openPorts = (shodan?.ports || []).slice(0, 16);
  const proxyPorts = openPorts.filter((p) => PROXY_PORTS_SET.has(p));
  const ptrRecord = routing.ptrRecord || shodan?.hostnames?.[0] || '—';
  const ptrStatus = ptrRecord !== '—' ? 'found' : routing.ptrStatus || 'failed';

  const isTor = Boolean(
    ipWho?.security?.tor
    || ipQuery?.risk?.is_tor
    || ipapiIs?.is_tor
    || abuseData?.isTor
    || pcTypeLow === 'tor'
    || tags.includes('tor')
  );
  // proxycheck 的免费接口会把大量云主机整段标成 VPN。机房地址只有它一家这样标时不采信，
  // 机房本身已按网络类型扣分；家宽、移动等网络上的同一标记仍然有效（多为住宅代理）。
  const hostingNetwork = usage === 'hosting' || usage === 'cdn';
  const pcFlag = pcEntry?.proxy === 'yes' && !hostingNetwork;
  // 网段名单：VPN 出口段按 VPN 计；Spamhaus DROP 是被劫持或犯罪团伙控制的网段，按重度；FireHOL level1 按中度
  const rangeVpn = rangeChecks.filter((c) => c.kind === 'vpn' && c.status === 'listed');
  const rangeAbuse = rangeChecks.filter((c) => c.kind === 'abuse' && c.status === 'listed');
  const dropListed = rangeAbuse.some((c) => c.source === 'Spamhaus DROP');
  const isVpn = Boolean(
    ipWho?.security?.vpn
    || ipQuery?.risk?.is_vpn
    || ipapiIs?.is_vpn
    || (pcFlag && pcTypeLow === 'vpn')
    || tags.includes('vpn')
    || (profile && profile.riskModifier <= -60)
    || rangeVpn.length > 0
  );
  const proxyFound = Boolean(
    isTor
    || isVpn
    || ipWho?.security?.proxy
    || ipQuery?.risk?.is_proxy
    || ipapiIs?.is_proxy
    || pcFlag
    || (proxyPorts.length > 0 && usage !== 'cdn')
  );
  const securityKnown = Boolean(
    (ipWho?.security && ['proxy', 'vpn', 'tor'].every((k) => typeof ipWho.security?.[k as 'proxy' | 'vpn' | 'tor'] === 'boolean'))
    || (ipQuery?.risk && typeof ipQuery.risk.is_proxy === 'boolean')
    || (pcEntry && (pcEntry.proxy === 'yes' || pcEntry.proxy === 'no'))
    || (ipapiIs && typeof ipapiIs.is_proxy === 'boolean')
  );
  const isProxy = proxyFound ? true : securityKnown ? false : null;
  const proxyLabel = isTor ? 'Tor 出口' : isVpn ? 'VPN 节点' : isProxy === true ? '公开代理'
    : isProxy === false ? '已查来源未见代理' : '代理状态未知';

  const isDualIsp = detectDualIsp({
    usage,
    asn,
    isp,
    org,
    isDatacenter,
    isProxy,
    ipapiCompanyType,
    ipapiAsnType,
    peeringDbType: peeringDb?.infoType,
  });

  const hasScanner = tags.includes('scanner');
  const hasCompromised = tags.includes('compromised') || tags.includes('malware');
  const abuseScore = abuseData?.abuseConfidenceScore ?? -1;
  const queryRisk = typeof ipQuery?.risk?.risk_score === 'number' && ipQuery.risk.risk_score >= 0 && ipQuery.risk.risk_score <= 100 ? ipQuery.risk.risk_score : -1;
  const proxyRisk = typeof pcEntry?.risk === 'number' && pcEntry.risk >= 0 && pcEntry.risk <= 100 ? pcEntry.risk : -1;
  const aggregateCount = publicReputation.status === 'listed' ? publicReputation.count || 1 : 0;
  // 当天不在名单里、但近 30 天曾被 ≥2 个名单收录：比当天命中低一档，≥5 个名单按中度，其余按轻度
  const pastLists = aggregateCount === 0 && reputationHistory.status === 'listed' ? reputationHistory.maxLists || 2 : 0;
  const severeRisk = dropListed || hasCompromised || abuseScore >= 75 || queryRisk >= 90 || proxyRisk >= 90 || aggregateCount >= 5;
  const moderateRisk = rangeAbuse.length > 0 || hasScanner || abuseScore >= 25 || ipapiIs?.is_abuser === true || queryRisk >= 65 || proxyRisk >= 75 || aggregateCount >= 3 || pastLists >= 5;
  const mildRisk = vulnsCount > 0 || dnsblListed.length > 0 || aggregateCount > 0 || pastLists > 0;
  const reputationSeverity = severeRisk ? 'severe' : moderateRisk ? 'moderate' : mildRisk ? 'mild' : 'none';
  const threatFound = reputationSeverity !== 'none';
  const publicKnown = publicReputation.status === 'listed' || publicReputation.status === 'not_listed';
  const abuseKnown = Boolean(abuseData || (ipapiIs && typeof ipapiIs.is_abuser === 'boolean'));
  const riskScoreKnown = queryRisk >= 0 || proxyRisk >= 0;
  // 免费来源齐全即视为信誉证据齐全：IPv4 需 IPsum、四个 DNSBL、Shodan 都有答复，外加至少一个风险分；
  // IPv6 没有这类公开名单，只能做到「有限」。AbuseIPDB / ipapi.is 只在配置了密钥时作为补充，不是必需项。
  const freeReputationKnown = parsed.version === 4 && publicKnown && dnsblComplete && Boolean(shodan) && riskScoreKnown;
  const reputationCoverage: ReputationCoverage = freeReputationKnown || (publicKnown && abuseKnown) ? 'complete'
    : publicKnown || abuseKnown || riskScoreKnown || dnsblAnswered > 0 ? 'limited' : 'unavailable';
  const checkedAt = new Date().toISOString();
  const reputationChecks: ReputationCheck[] = [
    publicReputation,
    ...(parsed.version === 4 && reputationHistory.status !== 'unavailable' ? [reputationHistory] : []),
    ...(parsed.version === 4 ? [
      { source: 'DNSBL ×4', checkedAt, status: dnsblListed.length ? 'listed' : dnsblComplete ? 'not_listed' : 'unavailable' } as ReputationCheck,
      { source: 'Shodan InternetDB', checkedAt, status: !shodan ? 'unavailable' : hasCompromised || hasScanner ? 'listed' : 'not_listed' } as ReputationCheck,
    ] : []),
    { source: 'proxycheck.io / ipquery.io risk', checkedAt, status: !riskScoreKnown ? 'unavailable' : Math.max(queryRisk, proxyRisk) >= 65 ? 'listed' : 'not_listed' },
    ...(parsed.version === 4 ? rangeChecks : []),
    ...(keys.abuseIpdbKey ? [{ source: 'AbuseIPDB', checkedAt, status: !abuseData ? 'unavailable' : abuseScore >= 25 ? 'listed' : 'not_listed' } as ReputationCheck] : []),
    ...(keys.ipapiIsKey ? [{ source: 'ipapi.is', checkedAt, status: !ipapiIs || typeof ipapiIs.is_abuser !== 'boolean' ? 'unavailable' : ipapiIs.is_abuser ? 'listed' : 'not_listed' } as ReputationCheck] : []),
  ];
  const hasThreat = threatFound ? true : reputationCoverage === 'complete' && Boolean(shodan) && dnsblComplete ? false : null;

  const threatLabel = dnsblListed.length
    ? `命中黑名单 (${dnsblListed.join(', ')})`
    : dropListed ? 'Spamhaus DROP 网段'
    : rangeAbuse.length > 0 ? 'FireHOL 攻击来源网段'
    : aggregateCount > 0 ? '公开信誉名单命中'
      : pastLists > 0 ? `近 30 天曾被 ${pastLists} 个名单收录`
      : abuseScore >= 25 ? `滥用举报 (${abuseScore}%)`
        : hasScanner ? '扫描活动记录'
          : hasCompromised || moderateRisk || severeRisk ? '存在风险记录'
            : vulnsCount > 0 ? `${vulnsCount} 个历史 CVE`
              : hasThreat === false ? '已查来源未见威胁' : '威胁数据不完整';

  // 分值都在 score-rules.ts；每一项连同它依据的原始数据记进 factors，页面上可以逐项展开核对
  const flag = (v: unknown) => (typeof v === 'boolean' ? String(v) : '');
  const ev = (source: string, field: string, value: unknown): FactorEvidence[] => {
    const text = value === null || value === undefined ? '' : String(value).trim();
    return text ? [{ source, field, value: text.slice(0, 160) }] : [];
  };
  const shodanEmpty = shodan?.noRecord ? ev('Shodan InternetDB', 'HTTP 404', 'No information available') : null;
  const shodanTags = shodanEmpty || (shodan ? ev('Shodan InternetDB', 'tags', tags.join(', ') || '[]') : []);

  const networkDelta = !networkKnown ? 0
    : usage === 'hosting' ? SCORE_DELTAS.hosting
      : usage === 'cdn' ? SCORE_DELTAS.cdn
        : usage === 'business' ? SCORE_DELTAS.business + (leasedRange ? SCORE_DELTAS.leased : 0)
          : usage === 'mobile' ? SCORE_DELTAS.mobile : 0;
  const nativeDelta = isNative === false && usage !== 'cdn' ? SCORE_DELTAS.nonNative : 0;
  const proxyDelta = isProxy ? SCORE_DELTAS.proxy : 0;
  const reputationDelta = severeRisk ? SCORE_DELTAS.reputationSevere : moderateRisk ? SCORE_DELTAS.reputationModerate : mildRisk ? SCORE_DELTAS.reputation : 0;
  const portsDelta = openPorts.length > MANY_PORTS_THRESHOLD ? SCORE_DELTAS.manyPorts : 0;

  const factors: ScoreFactor[] = [
    {
      key: 'network',
      label: '网络类型',
      status: leasedRange && usage === 'business' ? '商业网络（租用地址段）' : ipTypeLabel,
      delta: networkDelta,
      tone: !networkKnown ? 'muted' : usage === 'hosting' ? 'leak' : usage === 'cdn' || usage === 'business' ? 'warn' : 'ok',
      evidence: [
        ...ev('Cloudflare', 'request.cf.asn', cf?.asn),
        ...ev('ipwho.is', 'connection.asn', ipWho?.connection?.asn),
        ...ev('ipwho.is', 'connection.isp', ipWho?.connection?.isp),
        ...ev('ipwho.is', 'security.hosting', flag(ipWho?.security?.hosting)),
        ...ev('ipquery.io', 'risk.is_datacenter', flag(ipQuery?.risk?.is_datacenter)),
        ...ev('proxycheck.io', 'type', pcEntry?.type),
        ...(peeringDb ? ev('PeeringDB', 'info_type', `${peeringDb.infoType} (${peeringDb.name})`) : []),
        ...(ipapiIs ? ev('ipapi.is', 'company.type / asn.type', `${ipapiCompanyType || '—'} / ${ipapiAsnType || '—'}`) : []),
        ...(profile ? ev('JudgeIP ASN 表', `AS${profile.asn}`, `${profile.type} · ${profile.name}`) : []),
        ...(leasedRange ? ev('RDAP', 'registrant / ASN holder', `${registrant?.name} ≠ ${asnHolder?.name}${youngAsn ? ` · ASN registered ${asnHolder?.registeredAt}` : ' · not in PeeringDB'}`) : []),
      ],
    },
    {
      key: 'native',
      label: '原生 IP',
      status: isNative === null ? '查询未完成' : usage === 'cdn' ? 'CDN 不计此项' : isNative ? '注册地与定位一致'
        : registrantAbroad && rirCountry === countryCode ? `登记机构在 ${registrant?.country}，与定位不一致` : '注册地与定位不一致',
      delta: nativeDelta,
      tone: isNative === null || usage === 'cdn' ? 'muted' : isNative ? 'ok' : 'warn',
      evidence: [
        ...routing.whoisLines,
        ...ev('Cloudflare', 'request.cf.country', cf?.country),
        ...ev('ipwho.is', 'country_code', ipWho?.country_code),
        ...ev('ipquery.io', 'location.country_code', ipQuery?.location?.country_code),
        ...(asnHolder && asn ? ev('RDAP', `AS${asn} registrant`, `${asnHolder.name}${asnHolder.country ? ` (${asnHolder.country})` : ''}${asnHolder.registeredAt ? ` · registered ${asnHolder.registeredAt}` : ''}`) : []),
      ],
    },
    {
      key: 'proxy',
      label: '代理 / VPN / Tor',
      status: proxyLabel,
      delta: proxyDelta,
      tone: isProxy === null ? 'muted' : isProxy ? 'leak' : 'ok',
      evidence: [
        ...ev('ipwho.is', 'security.proxy', flag(ipWho?.security?.proxy)),
        ...ev('ipwho.is', 'security.vpn', flag(ipWho?.security?.vpn)),
        ...ev('ipwho.is', 'security.tor', flag(ipWho?.security?.tor)),
        ...ev('ipquery.io', 'risk.is_vpn / is_proxy', ipQuery?.risk ? `${Boolean(ipQuery.risk.is_vpn)} / ${Boolean(ipQuery.risk.is_proxy)}` : ''),
        ...ev('proxycheck.io', 'proxy / type', pcEntry ? `${pcEntry.proxy || 'no'}${pcEntry.type ? ` (${pcEntry.type})` : ''}` : ''),
        ...(ipapiIs ? ev('ipapi.is', 'is_vpn / is_proxy', `${Boolean(ipapiIs.is_vpn)} / ${Boolean(ipapiIs.is_proxy)}`) : []),
        ...shodanTags,
        ...(shodan && !shodanEmpty ? ev('Shodan InternetDB', '代理特征端口', proxyPorts.join(', ') || '[]') : []),
        ...(profile && profile.riskModifier <= -60 ? ev('JudgeIP ASN 表', `AS${profile.asn}`, profile.note) : []),
        ...rangeVpn.flatMap((c) => ev(c.source, 'range', c.range)),
      ],
    },
    {
      key: 'reputation',
      label: '黑名单与威胁记录',
      status: threatLabel,
      delta: reputationDelta,
      tone: hasThreat === null && !threatFound ? 'muted' : threatFound ? 'leak' : 'ok',
      evidence: [
        ...dnsblChecks.flatMap((c) => (c.query ? ev(c.name, c.query, c.answer || '无响应') : [])),
        ...ev('IPsum', 'status / aggregate count', `${publicReputation.status} / ${aggregateCount}`),
        ...ev('IPsum', 'updatedAt', publicReputation.updatedAt),
        ...rangeAbuse.flatMap((c) => ev(c.source, 'range', c.range)),
        ...(reputationHistory.status === 'listed'
          ? ev('IPsum 30-day history', 'last_seen / max_lists', `${reputationHistory.lastSeen} / ${reputationHistory.maxLists}`)
          : []),
        ...(typeof pcEntry?.risk === 'number' ? ev('proxycheck.io', 'risk', `${pcEntry.risk} / 100`) : []),
        ...(typeof ipQuery?.risk?.risk_score === 'number' ? ev('ipquery.io', 'risk_score', `${ipQuery.risk.risk_score} / 100`) : []),
        ...(abuseData ? ev('AbuseIPDB', 'abuseConfidenceScore', `${abuseData.abuseConfidenceScore}% (${abuseData.totalReports || 0} reports)`) : []),
        ...(ipapiIs?.company?.abuser_score ? ev('ipapi.is', 'abuser_score', ipapiIs.company.abuser_score) : []),
        ...shodanTags,
        ...(shodan && !shodanEmpty ? ev('Shodan InternetDB', 'vulns', (shodan.vulns || []).slice(0, 8).join(', ') || '[]') : []),
      ],
    },
    {
      key: 'ports',
      label: '开放端口数量',
      status: parsed.version === 6 ? '仅支持 IPv4' : !shodan ? '查询未完成' : `${openPorts.length} 个开放端口`,
      delta: portsDelta,
      tone: !shodan ? 'muted' : portsDelta ? 'warn' : 'ok',
      evidence: shodanEmpty || (shodan ? ev('Shodan InternetDB', 'ports', openPorts.join(', ') || '[]') : []),
    },
  ];

  const preliminaryScore = SCORE_BASE + factors.reduce((sum, f) => sum + f.delta, 0);
  const hasBasicEvidence = networkKnown && Boolean(countryCode) && isProxy !== null;
  const baseChecksComplete = parsed.version === 4 && isNative !== null && Boolean(shodan) && dnsblComplete;
  const coverageCap = Math.min(COVERAGE_CAPS[reputationCoverage], baseChecksComplete ? 99 : 79);
  const coverageDelta = hasBasicEvidence ? Math.min(0, coverageCap - preliminaryScore) : 0;
  factors.push({
    key: 'coverage', label: '信誉证据覆盖',
    status: reputationCoverage === 'complete' ? !baseChecksComplete ? '基础检查不完整' : '已查信誉来源齐备' : reputationCoverage === 'limited' ? '信誉覆盖有限' : '关键信誉数据缺失',
    delta: coverageDelta, tone: reputationCoverage === 'complete' ? 'ok' : 'muted',
    evidence: reputationChecks.flatMap((check) => [
      { source: check.source, field: 'status', value: check.status === 'listed' ? '风险命中' : check.status === 'not_listed' ? '未列入（仅该源）' : check.status === 'not_configured' ? '未配置' : '未获取' },
      { source: check.source, field: 'checkedAt', value: check.checkedAt },
      ...(check.updatedAt ? [{ source: check.source, field: 'updatedAt', value: check.updatedAt }] : []),
      ...(check.url ? [{ source: check.source, field: 'url', value: check.url }] : []),
    ]),
  });
  const safetyCap = REPUTATION_CAPS[reputationSeverity];
  factors.push({
    key: 'safety', label: '风险安全上限',
    status: severeRisk ? '重度风险上限 29' : moderateRisk ? '中度风险上限 49' : '未触发风险上限',
    delta: Math.min(0, safetyCap - preliminaryScore - coverageDelta), tone: severeRisk || moderateRisk ? 'leak' : 'muted',
    evidence: threatFound ? [{ source: 'JudgeIP', field: 'severity', value: reputationSeverity }] : [],
  });
  const rawScore = SCORE_BASE + factors.reduce((sum, f) => sum + f.delta, 0);
  const computedScore = clampScore(rawScore);
  if (computedScore !== rawScore) {
    factors.push({ key: 'clamp', label: '分数上下限', status: '限制在 5–99 之间', delta: computedScore - rawScore, tone: 'muted', evidence: [] });
  }

  // Coverage measures available evidence, not statistical prediction accuracy.
  const fullIpv4Evidence = parsed.version === 4 && networkKnown && Boolean(countryCode) && isNative !== null
    && isProxy !== null && Boolean(shodan) && dnsblComplete;
  const mediumEvidence = networkKnown && Boolean(countryCode) && isProxy !== null && (
    parsed.version === 6
      ? isNative !== null || Boolean(ipQuery || pcEntry || ipapiIs)
      : (dnsblAnswered >= 2 && Boolean(shodan || ipQuery || pcEntry)) || (dnsblComplete && !shodan && Boolean(ipQuery || pcEntry))
  );
  const lowEvidence = networkKnown && Boolean(countryCode) && isProxy !== null && Boolean(ipQuery || pcEntry || ipapiIs);

  const scoreConfidence: ScoreConfidence = fullIpv4Evidence && reputationCoverage === 'complete'
    ? 'high'
    : (mediumEvidence || fullIpv4Evidence) && reputationCoverage !== 'unavailable'
      ? 'medium'
      : lowEvidence || mediumEvidence || fullIpv4Evidence
        ? 'low'
        : 'none';

  const score = scoreConfidence !== 'none' ? computedScore : null;
  const scoreTone = score === null ? 'muted' : score >= 78 ? 'good' : score >= 50 ? 'warn' : 'bad';
  const grade = score === null ? '—' : scoreToCleanGrade(score);
  const lookupStatus = fullIpv4Evidence && reputationCoverage === 'complete'
    ? 'complete'
    : score !== null || networkKnown || countryCode || routing.bgpPrefix || shodan || dnsblComplete
      ? 'partial'
      : 'unavailable';

  const rpkiStatus = routing.rpkiStatus || 'unknown';
  const rpkiLabel = rpkiStatus === 'valid' ? 'RPKI 有效 (Valid)' : rpkiStatus === 'invalid' ? 'RPKI 异常 (Invalid)' : rpkiStatus === 'not_found' ? '未签发 ROA' : 'RPKI 状态未知';

  const scenes = score !== null ? buildSceneFitMatrix({ usage, isTor, isVpn, isProxy, isNative, reputationSeverity, reputationComplete: reputationCoverage === 'complete', countryCode }) : [];

  const riskChecks: RiskCheckItem[] = [
    {
      label: '代理 / VPN 隧道',
      status: isProxy === null ? '查询未完成' : isVpn ? '命中 VPN' : isProxy ? '疑似代理' : '未发现',
      tone: isProxy === null ? 'muted' : isProxy ? 'leak' : 'ok',
    },
    {
      label: 'Tor 匿名节点',
      status: isTor ? 'Tor 出口' : !securityKnown ? '查询未完成' : '未发现',
      tone: isTor ? 'leak' : !securityKnown ? 'muted' : 'ok',
    },
    {
      label: '代理特征端口',
      status: parsed.version === 6 ? '仅支持 IPv4' : !shodan ? '查询未完成' : proxyPorts.length > 0 ? `暴露 (${proxyPorts.join(', ')})` : '无暴露',
      tone: parsed.version === 6 || !shodan ? 'muted' : proxyPorts.length > 0 ? 'leak' : 'ok',
    },
    {
      label: 'DNSBL 邮件/垃圾黑名单',
      status:
        parsed.version === 6
          ? '仅支持 IPv4'
          : dnsblListed.length > 0
            ? `命中 ${dnsblListed.length}/${DNSBL_ZONES.length} (${dnsblListed.join(', ')})`
            : !dnsblComplete ? '查询未完成' : `0/${DNSBL_ZONES.length} 全部通过`,
      tone: dnsblListed.length > 0 ? 'leak' : parsed.version === 6 || !dnsblComplete ? 'muted' : 'ok',
    },
    {
      label: '扫描器与自动化标记',
      status: parsed.version === 6 ? '仅支持 IPv4' : !shodan ? '查询未完成' : hasScanner ? '存在扫描行为' : '无记录',
      tone: parsed.version === 6 || !shodan ? 'muted' : hasScanner ? 'warn' : 'ok',
    },
    {
      label: '失陷主机 / 漏洞暴露',
      status: parsed.version === 6 ? '仅支持 IPv4' : !shodan ? '查询未完成' : hasCompromised ? '失陷标记' : vulnsCount > 0 ? `${vulnsCount} 个历史 CVE` : '正常',
      tone: parsed.version === 6 || !shodan ? 'muted' : hasCompromised ? 'leak' : vulnsCount > 0 ? 'warn' : 'ok',
    },
  ];

  const result: HomeIpLookupResult = {
    ip: parsed.normalized,
    version: parsed.version,
    isBogon: false,
    ipTypeLabel,
    ipTypeTone,
    usageType: networkKnown ? usage : 'unknown',
    isDualIsp,
    isp,
    org,
    asn,
    asnCode: asn ? `AS${asn}` : '—',
    domain: domain || '—',
    rirName,
    rirCountry,
    registrantCountry: registrant?.country || undefined,
    isNative,
    isDatacenter,
    hasThreat,
    threatLabel,
    isProxy,
    proxyLabel,
    score,
    grade,
    scoreTone,
    scoreConfidence,
    reputationCoverage,
    reputationChecks,
    scoringVersion: '2026-11-23',
    lookupStatus,
    portsKnown: Boolean(shodan),
    scoreBase: SCORE_BASE,
    factors,
    bgpPrefix: routing.bgpPrefix || '—',
    rpkiStatus,
    rpkiLabel,
    ptrRecord,
    ptrStatus,
    openPorts,
    proxyPorts,
    vulnsCount,
    dnsblListed,
    dnsblTotal: DNSBL_ZONES.length,
    dnsblChecks,
    abuseEmail: routing.abuseEmail || '—',
    scenes,
    riskChecks,
    countryCode,
    countryZh,
    flagEmoji,
    region,
    city,
    regionEn,
    cityEn,
    postalCode,
    asnTraffic,
    latitude: latitude !== null && !Number.isNaN(latitude) ? Number(latitude.toFixed(3)) : null,
    longitude: longitude !== null && !Number.isNaN(longitude) ? Number(longitude.toFixed(3)) : null,
    timezone,
    localTimeHm: formatLocalTime(timezone),
    continentZh: CONTINENT_ZH[continentCode] || '未知',
  };

  if (memCache.size > CACHE_MAX_ENTRIES) {
    const first = memCache.keys().next().value;
    if (first) memCache.delete(first);
  }
  const cacheTtlMs = score !== null ? CACHE_COMPLETE_MINUTES * 60 * 1000 : CACHE_PARTIAL_SECONDS * 1000;
  memCache.set(cacheKey, { exp: Date.now() + cacheTtlMs, data: result });
  return result;
}
