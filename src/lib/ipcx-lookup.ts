import { classifyIspAndAsn, KNOWN_ASN_PROFILES, type UsageType } from './asn-intelligence';
import { parseIp } from './ip-utils';
import { CACHE_COMPLETE_MINUTES, CACHE_PARTIAL_SECONDS, CACHE_MAX_ENTRIES } from './data-sources';
import { SCORE_BASE, SCORE_DELTAS, SCORE_GRADES, MANY_PORTS_THRESHOLD, clampScore, type ScoreFactorKey } from './score-rules';

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
  isp: string;
  org: string;
  asn: number | null;
  asnCode: string;
  domain: string;
  rirName: string;
  rirCountry: string;
  isNative: boolean | null;
  isDatacenter: boolean | null;
  hasThreat: boolean | null;
  threatLabel: string;
  isProxy: boolean | null;
  proxyLabel: string;
  score: number | null;
  grade: string; // A+ / A / B / C / D / F (cleanip style)
  scoreTone: 'good' | 'warn' | 'bad' | 'muted';
  lookupStatus: 'complete' | 'partial' | 'unavailable';
  portsKnown: boolean;
  scoreBase: number;
  factors: ScoreFactor[];

  // Technical & Routing Indicators (from cleanip.io)
  bgpPrefix: string;
  rpkiStatus: 'valid' | 'invalid' | 'not_found' | 'unknown';
  rpkiLabel: string;
  ptrRecord: string;
  openPorts: number[];
  proxyPorts: number[];
  vulnsCount: number;
  dnsblListed: string[];
  dnsblTotal: number;
  dnsblChecks: DnsblCheck[];
  abuseEmail: string;

  // CleanIP Scene Fit & Risk Breakdown
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

const PROXY_PORTS_SET = new Set([1080, 1081, 3128, 8080, 8118, 8388, 8888, 9050, 10808, 2053, 2083, 2087, 51820]);

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

async function fetchJson<T>(url: string, timeoutMs = 2400, extraHeaders?: Record<string, string>): Promise<T | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'JudgeIP/1.0 (+https://judgeip.com)',
        ...(extraHeaders || {}),
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/* InternetDB 对没有扫描记录的 IP 返回 404，这是明确答复，按空记录处理；超时和其他状态码才算没查到 */
async function fetchShodan<T>(ipv4: string): Promise<T | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 2000);
  try {
    const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ipv4)}`, {
      signal: ctl.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'JudgeIP/1.0 (+https://judgeip.com)' },
    });
    if (res.status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], noRecord: true } as T;
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchRirAndRouting(ip: string): Promise<{
  rirName?: string;
  rirCountry?: string;
  bgpPrefix?: string;
  bgpAsn?: number;
  rpkiStatus?: 'valid' | 'invalid' | 'not_found' | 'unknown';
  ptrRecord?: string;
  abuseEmail?: string;
  whoisLines: FactorEvidence[];
}> {
  interface RipeWhois {
    data?: {
      authorities?: string[];
      records?: Array<Array<{ key?: string; value?: string }>>;
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
      result?: string[];
    };
  }
  interface RipeRpki {
    data?: {
      status?: string;
    };
  }

  const [whoisResp, netResp, rdnsResp] = await Promise.all([
    fetchJson<RipeWhois>(`https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`, 2100),
    fetchJson<RipeNetInfo>(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, 1900),
    fetchJson<RipeReverseDns>(`https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${encodeURIComponent(ip)}`, 1800),
  ]);

  let rirName = '';
  const auth = whoisResp?.data?.authorities?.[0]?.toUpperCase() || '';
  if (auth === 'RIPE') rirName = 'RIPE NCC';
  else if (auth) rirName = auth;

  let rirCountry = '';
  let abuseEmail = '';
  // 留下注册记录里能说明归属的几行原文，评分明细里当证据展示
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
  const bgpAsn = netResp?.data?.asns?.[0] ? Number(netResp.data.asns[0]) : undefined;
  const ptrRecord = rdnsResp?.data?.result?.[0] || '';

  let rpkiStatus: 'valid' | 'invalid' | 'not_found' | 'unknown' = 'unknown';
  if (bgpPrefix && bgpAsn) {
    const rpkiResp = await fetchJson<RipeRpki>(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=${bgpAsn}&prefix=${encodeURIComponent(bgpPrefix)}`,
      1600
    );
    const st = (rpkiResp?.data?.status || '').toLowerCase();
    if (st === 'valid') rpkiStatus = 'valid';
    else if (st.startsWith('invalid')) rpkiStatus = 'invalid';
    else if (st === 'unknown') rpkiStatus = 'not_found';
  }

  return { rirName, rirCountry, bgpPrefix, bgpAsn, rpkiStatus, ptrRecord, abuseEmail, whoisLines };
}

const DNS_RCODES: Record<number, string> = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

export async function checkIpv4Dnsbl(ipv4: string): Promise<DnsblCheck[]> {
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
      if (answers.some((a) => /^127\.0\.0\.[1-9]\d{0,2}$/.test(a))) return { name, status: 'listed', query, answer };
      return { name, status: 'unknown', query, answer };
    }
    if (res?.Answer && !Array.isArray(res.Answer)) return { name, status: 'unknown', query, answer };
    const authoritativeNegative = (res?.Status === 3 || res?.Status === 0)
      && answers.length === 0 && Array.isArray(res?.Authority) && res.Authority.some((a) => a?.type === 6);
    return { name, status: authoritativeNegative ? 'not_listed' : 'unknown', query, answer };
  }));
}

function buildSceneFitMatrix(opts: {
  usage: string;
  isNative: boolean;
  isProxy: boolean;
  hasThreat: boolean;
  dnsblCount: number;
  countryCode: string;
  score: number;
}): SceneFitItem[] {
  const { usage, isNative, isProxy, hasThreat, dnsblCount, countryCode, score } = opts;
  const isResOrMob = usage === 'residential' || usage === 'mobile';
  const aiBlocked = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP']).has(countryCode);

  const scenes: SceneFitItem[] = [
    {
      key: 'ecommerce',
      label: '跨境电商',
      status: isResOrMob && !isProxy && score >= 80 ? '适配' : score >= 60 && !hasThreat ? '仅买家/慎登店' : '高风险',
      tone: isResOrMob && !isProxy && score >= 80 ? 'ok' : score >= 60 && !hasThreat ? 'warn' : 'leak',
      note: 'Amazon / Shopee / TikTok Shop / Temu 卖家后台环境要求',
    },
    {
      key: 'payment',
      label: '跨境支付',
      status: score >= 78 && !isProxy && dnsblCount === 0 ? '适配' : score >= 55 ? '需 3DS 验证' : '易拒付',
      tone: score >= 78 && !isProxy && dnsblCount === 0 ? 'ok' : score >= 55 ? 'warn' : 'leak',
      note: 'Stripe / PayPal 账单地址与欺诈分风控',
    },
    {
      key: 'ai',
      label: 'AI 应用',
      status: aiBlocked ? `地区受限 (${countryCode})` : score >= 72 && !hasThreat ? '适配' : usage === 'hosting' ? 'API 可用/网页慎用' : '易弹验证',
      tone: aiBlocked ? 'leak' : score >= 72 && !hasThreat ? 'ok' : 'warn',
      note: 'ChatGPT / Claude / Gemini 地区与网络类型参考',
    },
    {
      key: 'social',
      label: '社媒运营',
      status: isResOrMob && isNative && !isProxy ? '原生适配' : isResOrMob ? '广播偏区注意' : '限流风险',
      tone: isResOrMob && isNative && !isProxy ? 'ok' : isResOrMob || score >= 65 ? 'warn' : 'leak',
      note: 'TikTok / X / Facebook / Instagram 推流权重与注册验证',
    },
    {
      key: 'ads',
      label: '广告投放',
      status: isResOrMob && !isProxy && dnsblCount === 0 ? '适配' : score >= 65 ? '需防关联' : '易封户',
      tone: isResOrMob && !isProxy && dnsblCount === 0 ? 'ok' : score >= 65 ? 'warn' : 'leak',
      note: 'Meta Ads / Google Ads 投放账户登录安全',
    },
    {
      key: 'streaming',
      label: '流媒体解锁',
      status: isResOrMob && isNative && !isProxy ? '完整版权库' : !isNative || usage === 'cdn' ? '仅自制剧/偏移' : '机房受限',
      tone: isResOrMob && isNative && !isProxy ? 'ok' : !isNative || usage === 'cdn' ? 'warn' : 'leak',
      note: 'Netflix / Disney+ / Spotify 本土版权识别',
    },
    {
      key: 'gaming',
      label: '游戏联机',
      status: usage === 'mobile' || usage === 'residential' ? '适配' : score >= 55 ? '可用' : '反作弊受限',
      tone: score >= 60 ? 'ok' : 'warn',
      note: 'Steam / 主机联机跨区与反作弊节点限制',
    },
    {
      key: 'crypto',
      label: '加密货币',
      status: ['CN', 'US'].includes(countryCode) ? `合规受限 (${countryCode})` : !isProxy && score >= 70 ? '适配' : '易触发 KYC',
      tone: ['CN', 'US'].includes(countryCode) ? 'warn' : !isProxy && score >= 70 ? 'ok' : 'warn',
      note: '主流交易所地区合规限制与异常 IP 二次验证',
    },
  ];

  return scenes;
}

const memCache = new Map<string, { exp: number; data: HomeIpLookupResult }>();

export async function lookupIpFull(
  rawIp: string,
  cfMeta?: Record<string, unknown> | null,
  isSelf = false
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
      lookupStatus: 'unavailable',
      portsKnown: false,
      scoreBase: SCORE_BASE,
      factors: [],
      bgpPrefix: '—',
      rpkiStatus: 'unknown',
      rpkiLabel: '不适用',
      ptrRecord: '—',
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
      latitude: null,
      longitude: null,
      timezone: '—',
      localTimeHm: '',
      continentZh: '—',
    };
  }

  const cacheKey = parsed.normalized;
  const cached = memCache.get(cacheKey);
  if (cached && cached.exp > Date.now() && !isSelf) {
    return { ...cached.data, localTimeHm: formatLocalTime(cached.data.timezone) };
  }

  interface IpWhoResp {
    success?: boolean;
    continent_code?: string;
    country_code?: string;
    country?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    connection?: { asn?: number; org?: string; isp?: string; domain?: string };
    timezone?: { id?: string };
    security?: { proxy?: boolean; vpn?: boolean; tor?: boolean; hosting?: boolean };
  }

  interface IpApiResp {
    status?: string;
    continentCode?: string;
    countryCode?: string;
    country?: string;
    regionName?: string;
    city?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    isp?: string;
    org?: string;
    as?: string;
    mobile?: boolean;
    proxy?: boolean;
    hosting?: boolean;
  }

  interface ShodanResp {
    ports?: number[];
    hostnames?: string[];
    tags?: string[];
    vulns?: string[];
    noRecord?: boolean;
  }

  const [ipWhoRaw, ipApiRaw, shodanRaw, routing, dnsblChecks] = await Promise.all([
    fetchJson<IpWhoResp>(`https://ipwho.is/${encodeURIComponent(parsed.normalized)}?lang=en`, 2300),
    fetchJson<IpApiResp>(
      `http://ip-api.com/json/${encodeURIComponent(parsed.normalized)}?lang=zh-CN&fields=status,continentCode,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`,
      2300
    ),
    parsed.version === 4 ? fetchShodan<ShodanResp>(parsed.normalized) : Promise.resolve(null),
    fetchRirAndRouting(parsed.normalized),
    parsed.version === 4 ? checkIpv4Dnsbl(parsed.normalized) : Promise.resolve([]),
  ]);

  // HTTP 200 with an error payload or an empty object is still missing data.
  const ipWho = ipWhoRaw?.success === true ? ipWhoRaw : null;
  const ipApi = ipApiRaw?.status === 'success' ? ipApiRaw : null;
  const shodan = shodanRaw && Array.isArray(shodanRaw.ports) && Array.isArray(shodanRaw.tags)
    && Array.isArray(shodanRaw.vulns) ? shodanRaw : null;
  const dnsblListed = dnsblChecks.filter((c) => c.status === 'listed').map((c) => c.name);
  const dnsblComplete = parsed.version === 4 && dnsblChecks.length === DNSBL_ZONES.length
    && dnsblChecks.every((c) => c.status !== 'unknown');
  const cf = isSelf && cfMeta ? cfMeta : null;
  const countryCode = ((cf?.country as string) || ipWho?.country_code || ipApi?.countryCode || '').toUpperCase();
  const continentCode = ((cf?.continent as string) || ipWho?.continent_code || ipApi?.continentCode || '').toUpperCase();
  const countryZh = countryCodeToZh(countryCode, ipWho?.country || ipApi?.country || countryCode);
  const flagEmoji = isoToFlag(countryCode);
  const region = ipApi?.regionName || ipWho?.region || (cf?.region as string) || '—';
  const city = ipApi?.city || ipWho?.city || (cf?.city as string) || '—';
  const englishPlace = (...values: unknown[]) => values.find((v): v is string => typeof v === 'string' && Boolean(v) && !/[\p{Script=Han}]/u.test(v)) || '—';
  const regionEn = englishPlace(ipWho?.region, cf?.region, ipApi?.regionName);
  const cityEn = englishPlace(ipWho?.city, cf?.city, ipApi?.city);
  const latitude = ipWho?.latitude ?? ipApi?.lat ?? (cf?.latitude ? Number(cf.latitude) : null);
  const longitude = ipWho?.longitude ?? ipApi?.lon ?? (cf?.longitude ? Number(cf.longitude) : null);
  const timezone = ipWho?.timezone?.id || ipApi?.timezone || (cf?.timezone as string) || '—';

  const asFromApi = ipApi?.as ? Number((ipApi.as.match(/^AS(\d+)/i) || [])[1]) || null : null;
  const asn = (cf?.asn ? Number(cf.asn) : null) || ipWho?.connection?.asn || asFromApi || routing.bgpAsn || null;
  const profile = asn ? KNOWN_ASN_PROFILES[asn] : undefined;

  const isp = ipWho?.connection?.isp || ipApi?.isp || (cf?.asOrganization as string) || profile?.name || '未知';
  const org = ipApi?.org || ipWho?.connection?.org || (cf?.asOrganization as string) || isp;
  let domain = ipWho?.connection?.domain || '';
  if (!domain && org) {
    if (/tencent/i.test(isp + org)) domain = 'tencent.com';
    else if (/alibaba|aliyun/i.test(isp + org)) domain = 'alibabacloud.com';
    else if (/cloudflare/i.test(isp + org)) domain = 'cloudflare.com';
    else if (/google/i.test(isp + org)) domain = 'google.com';
    else if (/amazon|aws/i.test(isp + org)) domain = 'amazonaws.com';
    else if (/comcast/i.test(isp + org)) domain = 'comcast.com';
    else if (/chunghwa|hinet/i.test(isp + org)) domain = 'hinet.net';
  }

  const upstreamHosting = Boolean(ipWho?.security?.hosting || ipApi?.hosting);
  const upstreamMobile = Boolean(ipApi?.mobile);
  const classifiedUsage = classifyIspAndAsn(asn, `${isp} ${org}`, upstreamHosting, upstreamMobile);
  const residentialEvidence = profile?.type === 'residential' || /telecom|broadband|cable|communications|fiber|fios/i.test(`${isp} ${org}`);
  const usage = classifiedUsage === 'residential' && !residentialEvidence ? 'unknown' : classifiedUsage;

  const networkKnown = usage !== 'unknown' && Boolean(asn || (isp !== '未知' && isp !== '—'));
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
    ipTypeLabel = '企业专线';
    ipTypeTone = 'gray';
  }

  if (!networkKnown) { ipTypeLabel = '未知'; ipTypeTone = 'gray'; }

  const rirName = routing.rirName || '—';
  const rirCountry = (routing.rirCountry || '').toUpperCase();
  const isNative = countryCode && rirCountry ? usage !== 'cdn' && rirCountry === countryCode : null;

  const tags = (shodan?.tags || []).map((t) => t.toLowerCase());
  const vulnsCount = shodan?.vulns?.length || 0;
  const openPorts = (shodan?.ports || []).slice(0, 16);
  const proxyPorts = openPorts.filter((p) => PROXY_PORTS_SET.has(p));
  const ptrRecord = routing.ptrRecord || shodan?.hostnames?.[0] || '—';

  const hasScanner = tags.includes('scanner');
  const hasCompromised = tags.includes('compromised') || tags.includes('malware');
  const threatFound = Boolean(hasCompromised || hasScanner || vulnsCount > 0 || dnsblListed.length > 0);
  const hasThreat = threatFound ? true : shodan && dnsblComplete ? false : null;
  const threatLabel = dnsblListed.length ? `命中黑名单 (${dnsblListed.join(', ')})`
    : hasScanner ? '扫描活动记录' : hasCompromised ? '存在风险记录'
      : vulnsCount > 0 ? `${vulnsCount} 个历史 CVE`
        : hasThreat === false ? '已查来源未见威胁' : '威胁数据不完整';

  const isTor = Boolean(ipWho?.security?.tor || tags.includes('tor'));
  const isVpn = Boolean(ipWho?.security?.vpn || tags.includes('vpn') || (profile && profile.riskModifier <= -60));
  const proxyFound = Boolean(isTor || isVpn || ipWho?.security?.proxy || ipApi?.proxy || proxyPorts.length > 0);
  const securityKnown = ipApi && typeof ipApi.proxy === 'boolean'
    || ipWho?.security && ['proxy', 'vpn', 'tor'].every((k) => typeof ipWho.security?.[k as 'proxy' | 'vpn' | 'tor'] === 'boolean');
  const isProxy = proxyFound ? true : securityKnown ? false : null;
  const proxyLabel = isTor ? 'Tor 出口' : isVpn ? 'VPN 节点' : isProxy === true ? '公开代理'
    : isProxy === false ? '已查来源未见代理' : '代理状态未知';

  // 分值都在 score-rules.ts；每一项连同它依据的原始数据记进 factors，页面上可以逐项展开核对
  const flag = (v: unknown) => (typeof v === 'boolean' ? String(v) : '');
  const ev = (source: string, field: string, value: unknown): FactorEvidence[] => {
    const text = value === null || value === undefined ? '' : String(value).trim();
    return text ? [{ source, field, value: text.slice(0, 160) }] : [];
  };
  /* 没有记录时证据只列一行，不逐个字段重复 "[]" */
  const shodanEmpty = shodan?.noRecord ? ev('Shodan InternetDB', 'HTTP 404', 'No information available') : null;
  const shodanTags = shodanEmpty || (shodan ? ev('Shodan InternetDB', 'tags', tags.join(', ') || '[]') : []);

  const networkDelta = !networkKnown ? 0 : usage === 'hosting' ? SCORE_DELTAS.hosting : usage === 'cdn' ? SCORE_DELTAS.cdn
    : usage === 'mobile' ? SCORE_DELTAS.mobile : 0;
  const nativeDelta = isNative === false && usage !== 'cdn' ? SCORE_DELTAS.nonNative : 0;
  const proxyDelta = isProxy ? SCORE_DELTAS.proxy : 0;
  const reputationDelta = dnsblListed.length > 0 || hasThreat ? SCORE_DELTAS.reputation : 0;
  const portsDelta = openPorts.length > MANY_PORTS_THRESHOLD ? SCORE_DELTAS.manyPorts : 0;

  const factors: ScoreFactor[] = [
    {
      key: 'network',
      label: '网络类型',
      status: ipTypeLabel,
      delta: networkDelta,
      tone: !networkKnown ? 'muted' : usage === 'hosting' ? 'leak' : usage === 'cdn' ? 'warn' : 'ok',
      evidence: [
        ...ev('Cloudflare', 'request.cf.asn', cf?.asn),
        ...ev('ipwho.is', 'connection.asn', ipWho?.connection?.asn),
        ...ev('ipwho.is', 'connection.isp', ipWho?.connection?.isp),
        ...ev('ipwho.is', 'security.hosting', flag(ipWho?.security?.hosting)),
        ...ev('ip-api.com', 'as', ipApi?.as),
        ...ev('ip-api.com', 'isp', ipApi?.isp),
        ...ev('ip-api.com', 'org', ipApi?.org),
        ...ev('ip-api.com', 'hosting', flag(ipApi?.hosting)),
        ...ev('ip-api.com', 'mobile', flag(ipApi?.mobile)),
        ...(profile ? ev('JudgeIP ASN 表', `AS${profile.asn}`, `${profile.type} · ${profile.name}`) : []),
      ],
    },
    {
      key: 'native',
      label: '原生 IP',
      status: isNative === null ? '查询未完成' : usage === 'cdn' ? 'CDN 不计此项' : isNative ? '注册地与定位一致' : '注册地与定位不一致',
      delta: nativeDelta,
      tone: isNative === null || usage === 'cdn' ? 'muted' : isNative ? 'ok' : 'warn',
      evidence: [
        ...routing.whoisLines,
        ...ev('Cloudflare', 'request.cf.country', cf?.country),
        ...ev('ipwho.is', 'country_code', ipWho?.country_code),
        ...ev('ip-api.com', 'countryCode', ipApi?.countryCode),
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
        ...ev('ip-api.com', 'proxy', flag(ipApi?.proxy)),
        ...shodanTags,
        ...(shodan && !shodanEmpty ? ev('Shodan InternetDB', '代理特征端口', proxyPorts.join(', ') || '[]') : []),
        ...(profile && profile.riskModifier <= -60 ? ev('JudgeIP ASN 表', `AS${profile.asn}`, profile.note) : []),
      ],
    },
    {
      key: 'reputation',
      label: '黑名单与威胁记录',
      status: threatLabel,
      delta: reputationDelta,
      tone: hasThreat === null ? 'muted' : hasThreat ? 'leak' : 'ok',
      evidence: [
        ...dnsblChecks.flatMap((c) => (c.query ? ev(c.name, c.query, c.answer || '无响应') : [])),
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

  const rawScore = SCORE_BASE + factors.reduce((sum, f) => sum + f.delta, 0);
  const computedScore = clampScore(rawScore);
  // 分数限制在 5–99 之间；被截断时单列一项，各项相加才对得上最终分数
  if (computedScore !== rawScore) {
    factors.push({ key: 'clamp', label: '分数上下限', status: '限制在 5–99 之间', delta: computedScore - rawScore, tone: 'muted', evidence: [] });
  }

  const scoreReady = networkKnown && Boolean(countryCode) && isNative !== null && isProxy !== null
    && hasThreat !== null && Boolean(shodan) && dnsblComplete;
  const score = scoreReady ? computedScore : null;
  const scoreTone = score === null ? 'muted' : score >= 78 ? 'good' : score >= 50 ? 'warn' : 'bad';
  const grade = score === null ? '—' : scoreToCleanGrade(score);
  const lookupStatus = scoreReady ? 'complete' : networkKnown || countryCode || routing.bgpPrefix || shodan || dnsblComplete ? 'partial' : 'unavailable';

  const rpkiStatus = routing.rpkiStatus || 'unknown';
  const rpkiLabel = rpkiStatus === 'valid' ? 'RPKI 有效 (Valid)' : rpkiStatus === 'invalid' ? 'RPKI 异常 (Invalid)' : rpkiStatus === 'not_found' ? '未签发 ROA' : 'RPKI 状态未知';

  const scenes = score !== null ? buildSceneFitMatrix({
    usage,
    isNative: isNative === true,
    isProxy: isProxy === true,
    hasThreat: hasThreat === true,
    dnsblCount: dnsblListed.length,
    countryCode,
    score,
  }) : [];

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
      status: !shodan ? '查询未完成' : hasScanner ? '存在扫描行为' : '无记录',
      tone: !shodan ? 'muted' : hasScanner ? 'warn' : 'ok',
    },
    {
      label: '失陷主机 / 漏洞暴露',
      status: !shodan ? '查询未完成' : hasCompromised ? '失陷标记' : vulnsCount > 0 ? `${vulnsCount} 个历史 CVE` : '正常',
      tone: !shodan ? 'muted' : hasCompromised ? 'leak' : vulnsCount > 0 ? 'warn' : 'ok',
    },
  ];

  const result: HomeIpLookupResult = {
    ip: parsed.normalized,
    version: parsed.version,
    isBogon: false,
    ipTypeLabel,
    ipTypeTone,
    usageType: networkKnown ? usage : 'unknown',
    isp,
    org,
    asn,
    asnCode: asn ? `AS${asn}` : '—',
    domain: domain || '—',
    rirName,
    rirCountry,
    isNative,
    isDatacenter,
    hasThreat,
    threatLabel,
    isProxy,
    proxyLabel,
    score,
    grade,
    scoreTone,
    lookupStatus,
    portsKnown: Boolean(shodan),
    scoreBase: SCORE_BASE,
    factors,
    bgpPrefix: routing.bgpPrefix || '—',
    rpkiStatus,
    rpkiLabel,
    ptrRecord,
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
  memCache.set(cacheKey, { exp: Date.now() + (lookupStatus === 'complete' ? CACHE_COMPLETE_MINUTES * 60 * 1000 : CACHE_PARTIAL_SECONDS * 1000), data: result });
  return result;
}
