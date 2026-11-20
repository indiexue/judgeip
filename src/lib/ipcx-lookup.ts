import { classifyIspAndAsn, KNOWN_ASN_PROFILES } from './asn-intelligence';
import { parseIp } from './ip-utils';

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

export interface HomeIpLookupResult {
  ip: string;
  version: 4 | 6;
  isBogon: boolean;
  bogonReason?: string;

  // Network Attributes
  ipTypeLabel: string;
  ipTypeTone: 'green' | 'amber' | 'danger' | 'gray';
  isp: string;
  org: string;
  asn: number | null;
  asnCode: string;
  humanPct: string;
  botPct: string;
  domain: string;
  rirName: string;
  rirCountry: string;
  isNative: boolean;
  isDatacenter: boolean;
  hasThreat: boolean;
  threatLabel: string;
  isProxy: boolean;
  proxyLabel: string;
  score: number;
  grade: string; // A+ / A / B / C / D / F (cleanip style)
  scoreTone: 'good' | 'warn' | 'bad';

  // Technical & Routing Indicators (from cleanip.io)
  bgpPrefix: string;
  rpkiStatus: 'valid' | 'invalid' | 'unknown';
  rpkiLabel: string;
  ptrRecord: string;
  openPorts: number[];
  proxyPorts: number[];
  vulnsCount: number;
  dnsblListed: string[];
  dnsblTotal: number;
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
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 68) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
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

async function fetchRirAndRouting(ip: string): Promise<{
  rirName?: string;
  rirCountry?: string;
  bgpPrefix?: string;
  bgpAsn?: number;
  rpkiStatus?: 'valid' | 'invalid' | 'unknown';
  ptrRecord?: string;
  abuseEmail?: string;
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
  for (const group of whoisResp?.data?.records || []) {
    for (const item of group) {
      const k = (item.key || '').toLowerCase();
      const v = (item.value || '').trim();
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

  let rpkiStatus: 'valid' | 'invalid' | 'unknown' = 'unknown';
  if (bgpPrefix && bgpAsn) {
    const rpkiResp = await fetchJson<RipeRpki>(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=${bgpAsn}&prefix=${encodeURIComponent(bgpPrefix)}`,
      1600
    );
    const st = (rpkiResp?.data?.status || '').toLowerCase();
    if (st === 'valid') rpkiStatus = 'valid';
    else if (st.startsWith('invalid')) rpkiStatus = 'invalid';
  }

  return { rirName, rirCountry, bgpPrefix, bgpAsn, rpkiStatus, ptrRecord, abuseEmail };
}

export async function checkIpv4Dnsbl(ipv4: string): Promise<string[]> {
  const octets = ipv4.split('.');
  if (octets.length !== 4) return [];
  const reversed = octets.slice().reverse().join('.');

  const hits = await Promise.all(
    DNSBL_ZONES.map(async ({ zone, name }) => {
      const qname = `${reversed}.${zone}`;
      const res = await fetchJson<{ Status?: number; Answer?: Array<{ type?: number; data?: string }> }>(
        `https://1.1.1.1/dns-query?name=${encodeURIComponent(qname)}&type=A`,
        1600,
        { Accept: 'application/dns-json' }
      );
      if (res && res.Status === 0 && Array.isArray(res.Answer)) {
        const listed = res.Answer.some((a) => a.type === 1 && String(a.data || '').startsWith('127.0.0.'));
        if (listed) return name;
      }
      return null;
    })
  );
  return hits.filter((x): x is string => Boolean(x));
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
      note: 'ChatGPT / Claude / Gemini 地区许可与防降智',
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
      isp: parsed.bogonReason || 'IANA Reserved',
      org: '本地 / 内网保留网段',
      asn: null,
      asnCode: '—',
      humanPct: '—',
      botPct: '—',
      domain: '—',
      rirName: 'IANA',
      rirCountry: '',
      isNative: false,
      isDatacenter: false,
      hasThreat: false,
      threatLabel: '无威胁记录',
      isProxy: false,
      proxyLabel: '非代理',
      score: 100,
      grade: 'A+',
      scoreTone: 'good',
      bgpPrefix: '—',
      rpkiStatus: 'unknown',
      rpkiLabel: '不适用',
      ptrRecord: '—',
      openPorts: [],
      proxyPorts: [],
      vulnsCount: 0,
      dnsblListed: [],
      dnsblTotal: DNSBL_ZONES.length,
      abuseEmail: '—',
      scenes: [],
      riskChecks: [],
      countryCode: '',
      countryZh: '内网 / 保留地址',
      flagEmoji: '',
      region: '—',
      city: '—',
      latitude: null,
      longitude: null,
      timezone: 'UTC',
      localTimeHm: formatLocalTime('UTC'),
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
  }

  const [ipWho, ipApi, shodan, routing, dnsblListed] = await Promise.all([
    fetchJson<IpWhoResp>(`https://ipwho.is/${encodeURIComponent(parsed.normalized)}?lang=zh-CN`, 2300),
    fetchJson<IpApiResp>(
      `http://ip-api.com/json/${encodeURIComponent(parsed.normalized)}?lang=zh-CN&fields=status,continentCode,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`,
      2300
    ),
    parsed.version === 4
      ? fetchJson<ShodanResp>(`https://internetdb.shodan.io/${encodeURIComponent(parsed.normalized)}`, 2000)
      : Promise.resolve(null),
    fetchRirAndRouting(parsed.normalized),
    parsed.version === 4 ? checkIpv4Dnsbl(parsed.normalized) : Promise.resolve([]),
  ]);

  const cf = isSelf && cfMeta ? cfMeta : null;
  const countryCode = ((cf?.country as string) || ipWho?.country_code || ipApi?.countryCode || 'US').toUpperCase();
  const continentCode = ((cf?.continent as string) || ipWho?.continent_code || ipApi?.continentCode || 'AS').toUpperCase();
  const countryZh = countryCodeToZh(countryCode, ipWho?.country || ipApi?.country || countryCode);
  const flagEmoji = isoToFlag(countryCode);
  const region = ipApi?.regionName || ipWho?.region || (cf?.region as string) || '—';
  const city = ipApi?.city || ipWho?.city || (cf?.city as string) || '—';
  const latitude = ipWho?.latitude ?? ipApi?.lat ?? (cf?.latitude ? Number(cf.latitude) : null);
  const longitude = ipWho?.longitude ?? ipApi?.lon ?? (cf?.longitude ? Number(cf.longitude) : null);
  const timezone = ipWho?.timezone?.id || ipApi?.timezone || (cf?.timezone as string) || 'UTC';

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
  const usage = classifyIspAndAsn(asn, `${isp} ${org}`, upstreamHosting, upstreamMobile);

  const isDatacenter = usage === 'hosting' || usage === 'cdn';
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

  const seed = (asn || 12345) % 97;
  let humanNum = 86.4;
  if (usage === 'hosting') humanNum = Number((6.5 + (seed % 140) / 10).toFixed(1));
  else if (usage === 'cdn') humanNum = Number((38.0 + (seed % 180) / 10).toFixed(1));
  else if (usage === 'mobile') humanNum = Number((91.0 + (seed % 70) / 10).toFixed(1));
  else humanNum = Number((82.0 + (seed % 140) / 10).toFixed(1));
  const botNum = Number((100 - humanNum).toFixed(1));

  const rirName = routing.rirName || guessRirByContinentOrCountry(continentCode, countryCode);
  const rirCountry = (routing.rirCountry || profile?.registeredCountry || countryCode).toUpperCase();
  const isNative = usage !== 'cdn' && rirCountry === countryCode;

  const tags = (shodan?.tags || []).map((t) => t.toLowerCase());
  const vulnsCount = shodan?.vulns?.length || 0;
  const openPorts = (shodan?.ports || []).slice(0, 16);
  const proxyPorts = openPorts.filter((p) => PROXY_PORTS_SET.has(p));
  const ptrRecord = routing.ptrRecord || shodan?.hostnames?.[0] || '—';

  const hasScanner = tags.includes('scanner');
  const hasCompromised = tags.includes('compromised') || tags.includes('malware');
  const hasThreat = Boolean(hasCompromised || hasScanner || vulnsCount >= 3 || dnsblListed.length > 0);
  const threatLabel =
    dnsblListed.length > 0
      ? `命中黑名单 (${dnsblListed.join(', ')})`
      : hasScanner
        ? '扫描活动记录'
        : hasCompromised
          ? '存在风险记录'
          : '无威胁记录';

  const isTor = Boolean(ipWho?.security?.tor || tags.includes('tor'));
  const isVpn = Boolean(ipWho?.security?.vpn || tags.includes('vpn') || (profile && profile.riskModifier <= -60));
  const isProxy = Boolean(isTor || isVpn || ipWho?.security?.proxy || ipApi?.proxy || proxyPorts.length > 0);
  const proxyLabel = isTor ? 'Tor 出口' : isVpn ? 'VPN 节点' : isProxy ? '公开代理' : '非代理';

  let score = 95;
  if (usage === 'hosting') score -= 33;
  else if (usage === 'cdn') score -= 25;
  else if (usage === 'mobile') score += 2;

  if (!isNative && usage !== 'cdn') score -= 12;
  if (isProxy) score -= 24;
  if (dnsblListed.length > 0) score -= 18;
  else if (hasThreat) score -= 18;
  if (openPorts.length > 6) score -= 5;
  score = Math.max(5, Math.min(99, Math.round(score)));

  const scoreTone: 'good' | 'warn' | 'bad' = score >= 78 ? 'good' : score >= 50 ? 'warn' : 'bad';
  const grade = scoreToCleanGrade(score);

  const rpkiStatus = routing.rpkiStatus || 'unknown';
  const rpkiLabel = rpkiStatus === 'valid' ? 'RPKI 有效 (Valid)' : rpkiStatus === 'invalid' ? 'RPKI 异常 (Invalid)' : '未签发 ROA';

  const scenes = buildSceneFitMatrix({
    usage,
    isNative,
    isProxy,
    hasThreat,
    dnsblCount: dnsblListed.length,
    countryCode,
    score,
  });

  const riskChecks: RiskCheckItem[] = [
    {
      label: '代理 / VPN 隧道',
      status: isVpn ? '命中 VPN' : isProxy ? '疑似代理' : '未发现',
      tone: isProxy ? 'leak' : 'ok',
    },
    {
      label: 'Tor 匿名节点',
      status: isTor ? 'Tor 出口' : '未发现',
      tone: isTor ? 'leak' : 'ok',
    },
    {
      label: '代理特征端口',
      status: parsed.version === 6 ? '仅支持 IPv4' : proxyPorts.length > 0 ? `暴露 (${proxyPorts.join(', ')})` : '无暴露',
      tone: parsed.version === 6 ? 'muted' : proxyPorts.length > 0 ? 'leak' : 'ok',
    },
    {
      label: 'DNSBL 邮件/垃圾黑名单',
      status:
        parsed.version === 6
          ? '仅支持 IPv4'
          : dnsblListed.length > 0
            ? `命中 ${dnsblListed.length}/${DNSBL_ZONES.length} (${dnsblListed.join(', ')})`
            : `0/${DNSBL_ZONES.length} 全部通过`,
      tone: parsed.version === 6 ? 'muted' : dnsblListed.length > 0 ? 'leak' : 'ok',
    },
    {
      label: '扫描器与自动化标记',
      status: hasScanner ? '存在扫描行为' : '无记录',
      tone: hasScanner ? 'warn' : 'ok',
    },
    {
      label: '失陷主机 / 漏洞暴露',
      status: hasCompromised ? '失陷标记' : vulnsCount > 0 ? `${vulnsCount} 个历史 CVE` : '正常',
      tone: hasCompromised ? 'leak' : vulnsCount > 0 ? 'warn' : 'ok',
    },
  ];

  const result: HomeIpLookupResult = {
    ip: parsed.normalized,
    version: parsed.version,
    isBogon: false,
    ipTypeLabel,
    ipTypeTone,
    isp,
    org,
    asn,
    asnCode: asn ? `AS${asn}` : '—',
    humanPct: `${humanNum}%`,
    botPct: `${botNum}%`,
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
    bgpPrefix: routing.bgpPrefix || '—',
    rpkiStatus,
    rpkiLabel,
    ptrRecord,
    openPorts,
    proxyPorts,
    vulnsCount,
    dnsblListed,
    dnsblTotal: DNSBL_ZONES.length,
    abuseEmail: routing.abuseEmail || '—',
    scenes,
    riskChecks,
    countryCode,
    countryZh,
    flagEmoji,
    region,
    city,
    latitude: latitude !== null && !Number.isNaN(latitude) ? Number(latitude.toFixed(3)) : null,
    longitude: longitude !== null && !Number.isNaN(longitude) ? Number(longitude.toFixed(3)) : null,
    timezone,
    localTimeHm: formatLocalTime(timezone),
    continentZh: CONTINENT_ZH[continentCode] || '其他',
  };

  if (memCache.size > 400) {
    const first = memCache.keys().next().value;
    if (first) memCache.delete(first);
  }
  memCache.set(cacheKey, { exp: Date.now() + 20 * 60 * 1000, data: result });
  return result;
}
