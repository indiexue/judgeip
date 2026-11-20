/**
 * JudgeIP Core Verdict Engine
 *
 * Performs multi-source IP intelligence fusion:
 * 1. Cloudflare Edge `request.cf` zero-latency metadata (when inspecting visitor or CF headers)
 * 2. Live Geo/ISP/Proxy telemetry (`ipwho.is` + `ip-api.com` fallback)
 * 3. RIR / RDAP Registration Country verification (distinguishing True Native IP vs Broadcasted Geo-fed IP!)
 * 4. Shodan InternetDB passive port & proxy-service exposure check (SOCKS5/HTTP/WireGuard/Shadowsocks ports)
 * 5. Transparent, explainable 0-100 Purity Score + S/A/B/C/D Grade + Platform Verdict Matrix
 */

import { classifyIspAndAsn, KNOWN_ASN_PROFILES, type UsageType } from './asn-intelligence';
import { parseIp } from './ip-utils';

export type VerdictGrade = 'S' | 'A' | 'B' | 'C' | 'D';
export type RiskLevel = 'pristine' | 'low' | 'elevated' | 'high' | 'critical';
export type NativeStatus = 'native' | 'broadcast' | 'anycast' | 'unknown';
export type PlatformStatus = 'pass' | 'warn' | 'block';

export interface ScoreFactor {
  id: string;
  delta: number; // Negative = deduction, Positive = bonus, 0 = neutral verification
  severity: 'good' | 'info' | 'warn' | 'bad';
  titleEn: string;
  titleZh: string;
  detailEn: string;
  detailZh: string;
}

export interface PlatformVerdict {
  id: 'tiktok' | 'ai' | 'ecommerce' | 'streaming' | 'payments';
  nameEn: string;
  nameZh: string;
  status: PlatformStatus;
  badgeEn: string;
  badgeZh: string;
  reasonEn: string;
  reasonZh: string;
}

export interface IpVerdictReport {
  ip: string;
  version: 4 | 6;
  evaluatedAt: string;
  latencyMs: number;

  // JudgeIP Core Verdict
  score: number; // 0 - 100 (Higher = Cleaner / More Pure)
  fraudRisk: number; // 100 - score (0 - 100, Lower = Safer)
  grade: VerdictGrade;
  riskLevel: RiskLevel;
  verdictTitleEn: string;
  verdictTitleZh: string;
  verdictSummaryEn: string;
  verdictSummaryZh: string;

  // Network & Geo Identity
  geo: {
    countryCode: string;
    countryName: string;
    region: string;
    city: string;
    postalCode: string;
    latitude: number | null;
    longitude: number | null;
    timezone: string;
  };
  network: {
    asn: number | null;
    asnCode: string;
    isp: string;
    org: string;
    domain: string;
    usageType: UsageType;
    rirCountryCode: string;
    nativeStatus: NativeStatus;
  };

  // Security & Protocol Exposure Signals
  signals: {
    isDatacenter: boolean;
    isProxyOrVpn: boolean;
    isTor: boolean;
    isAbuserOrCrawler: boolean;
    hasExposedProxyPorts: boolean;
    openPorts: number[];
    vulnsCount: number;
    hostnames: string[];
    edgeTlsVersion?: string;
    edgeHttpProtocol?: string;
    edgeColo?: string;
  };

  factors: ScoreFactor[];
  platforms: PlatformVerdict[];
  sources: string[];
}

interface ShodanInternetDbResp {
  ip?: string;
  ports?: number[];
  hostnames?: string[];
  tags?: string[];
  vulns?: string[];
}

const PROXY_SIGNATURE_PORTS = new Set([1080, 1081, 3128, 8080, 8118, 8388, 8888, 9050, 10808, 2053, 2083, 2087, 2096, 51820]);

async function fetchJsonWithTimeout<T>(url: string, timeoutMs = 2400): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'JudgeIP-EdgeEngine/1.0 (+https://judgeip.com)',
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

/**
 * Queries RIPE Stat (aggregates global RIR WHOIS/RDAP allocations across ARIN, RIPE, APNIC, LACNIC, AFRINIC)
 * to extract the original RIR registration country of an IP prefix.
 */
async function fetchRirAllocationCountry(ip: string): Promise<{ rirCountry: string; prefix?: string } | null> {
  interface RipeWhoisResp {
    data?: {
      records?: Array<Array<{ key?: string; value?: string }>>;
    };
  }
  const resp = await fetchJsonWithTimeout<RipeWhoisResp>(
    `https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`,
    2200
  );
  const records = resp?.data?.records;
  if (!records || !Array.isArray(records)) return null;

  let rirCountry = '';
  let prefix = '';
  for (const group of records) {
    for (const entry of group) {
      const k = (entry.key || '').toLowerCase();
      const v = (entry.value || '').trim();
      if (!prefix && (k === 'inetnum' || k === 'inet6num' || k === 'netrange' || k === 'route')) {
        prefix = v;
      }
      if (!rirCountry && k === 'country' && /^[a-zA-Z]{2}$/.test(v)) {
        // Ignore EU region pseudo-code if a more specific country exists later
        if (v.toUpperCase() !== 'EU') {
          rirCountry = v.toUpperCase();
        }
      }
    }
  }
  return rirCountry ? { rirCountry, prefix } : null;
}

function computeGrade(score: number): VerdictGrade {
  if (score >= 90) return 'S';
  if (score >= 78) return 'A';
  if (score >= 60) return 'B';
  if (score >= 40) return 'C';
  return 'D';
}

function computeRiskLevel(score: number): RiskLevel {
  if (score >= 90) return 'pristine';
  if (score >= 75) return 'low';
  if (score >= 55) return 'elevated';
  if (score >= 35) return 'high';
  return 'critical';
}

// Simple in-isolate LRU memory cache for ultra-fast repeated lookups (supplements optional Cloudflare KV)
const memoryCache = new Map<string, { expiresAt: number; report: IpVerdictReport }>();

export interface EvaluateOptions {
  cfMetadata?: Record<string, unknown> | null;
  isDirectVisitor?: boolean;
  kvNamespace?: KVNamespace;
}

export async function evaluateIpVerdict(rawIp: string, options: EvaluateOptions = {}): Promise<IpVerdictReport> {
  const startedAt = Date.now();
  const parsed = parseIp(rawIp);

  if (!parsed) {
    throw new Error('Invalid IPv4 or IPv6 address');
  }

  if (parsed.isBogon) {
    return buildBogonReport(parsed.normalized, parsed.version, parsed.bogonReason || 'Private/Reserved IP', Date.now() - startedAt);
  }

  const cacheKey = `verdict:v1:${parsed.normalized}`;
  const now = Date.now();
  const memHit = memoryCache.get(cacheKey);
  if (memHit && memHit.expiresAt > now && !options.isDirectVisitor) {
    return {
      ...memHit.report,
      latencyMs: Math.max(1, Date.now() - startedAt),
    };
  }

  if (options.kvNamespace && !options.isDirectVisitor) {
    try {
      const cached = await options.kvNamespace.get<IpVerdictReport>(cacheKey, 'json');
      if (cached) {
        return { ...cached, latencyMs: Math.max(1, Date.now() - startedAt) };
      }
    } catch {
      // Ignore KV failure and proceed live
    }
  }

  // Parallel intelligence fan-out: Geo/ISP + Shodan InternetDB + RIR Registration Country
  interface IpWhoisResp {
    success?: boolean;
    country_code?: string;
    country?: string;
    region?: string;
    city?: string;
    postal?: string;
    latitude?: number;
    longitude?: number;
    connection?: {
      asn?: number;
      org?: string;
      isp?: string;
      domain?: string;
    };
    timezone?: {
      id?: string;
    };
    security?: {
      anonymous?: boolean;
      proxy?: boolean;
      vpn?: boolean;
      tor?: boolean;
      hosting?: boolean;
    };
  }

  interface IpApiFallbackResp {
    status?: string;
    country?: string;
    countryCode?: string;
    regionName?: string;
    city?: string;
    zip?: string;
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

  const [ipWho, ipApi, shodan, rirInfo] = await Promise.all([
    fetchJsonWithTimeout<IpWhoisResp>(`https://ipwho.is/${encodeURIComponent(parsed.normalized)}`, 2200),
    fetchJsonWithTimeout<IpApiFallbackResp>(
      `http://ip-api.com/json/${encodeURIComponent(parsed.normalized)}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`,
      2200
    ),
    parsed.version === 4
      ? fetchJsonWithTimeout<ShodanInternetDbResp>(`https://internetdb.shodan.io/${encodeURIComponent(parsed.normalized)}`, 2000)
      : Promise.resolve(null),
    fetchRirAllocationCountry(parsed.normalized),
  ]);

  const sources: string[] = ['JudgeIP ASN Heuristics'];
  const cf = options.isDirectVisitor && options.cfMetadata ? options.cfMetadata : null;
  if (cf) sources.push('Cloudflare Edge Telemetry');
  if (ipWho?.success) sources.push('IPWhois Routing Feed');
  if (ipApi?.status === 'success') sources.push('BGP/Geo Upstream');
  if (shodan?.ip) sources.push('Shodan InternetDB');
  if (rirInfo?.rirCountry) sources.push('RIR WHOIS Allocation');

  // Consolidate Geo & ASN
  const countryCode = (
    (cf?.country as string) ||
    ipWho?.country_code ||
    ipApi?.countryCode ||
    'US'
  ).toUpperCase();

  const countryName = ipWho?.country || ipApi?.country || countryCode;
  const region = (cf?.region as string) || ipWho?.region || ipApi?.regionName || '';
  const city = (cf?.city as string) || ipWho?.city || ipApi?.city || '';
  const postalCode = (cf?.postalCode as string) || ipWho?.postal || ipApi?.zip || '';
  const latitude = ipWho?.latitude ?? ipApi?.lat ?? (cf?.latitude ? Number(cf.latitude) : null);
  const longitude = ipWho?.longitude ?? ipApi?.lon ?? (cf?.longitude ? Number(cf.longitude) : null);
  const timezone = (cf?.timezone as string) || ipWho?.timezone?.id || ipApi?.timezone || 'UTC';

  const parsedAsFromApi = ipApi?.as ? Number((ipApi.as.match(/^AS(\d+)/i) || [])[1]) || null : null;
  const asn = (cf?.asn ? Number(cf.asn) : null) || ipWho?.connection?.asn || parsedAsFromApi || null;
  const knownProfile = asn ? KNOWN_ASN_PROFILES[asn] : undefined;

  const isp = ipWho?.connection?.isp || ipApi?.isp || (cf?.asOrganization as string) || knownProfile?.name || 'Unknown ISP';
  const org = ipWho?.connection?.org || ipApi?.org || (cf?.asOrganization as string) || isp;
  const domain = ipWho?.connection?.domain || '';

  const upstreamHosting = Boolean(ipWho?.security?.hosting || ipApi?.hosting);
  const upstreamMobile = Boolean(ipApi?.mobile);
  const usageType = classifyIspAndAsn(asn, `${isp} ${org}`, upstreamHosting, upstreamMobile);

  // RIR Native IP vs Broadcasted IP Verification
  const rirCountryCode = (rirInfo?.rirCountry || knownProfile?.registeredCountry || countryCode).toUpperCase();
  let nativeStatus: NativeStatus = 'unknown';
  if (usageType === 'cdn') {
    nativeStatus = 'anycast';
  } else if (rirCountryCode && countryCode) {
    nativeStatus = rirCountryCode === countryCode ? 'native' : 'broadcast';
  }

  // Threat & Protocol Signals
  const openPorts = Array.isArray(shodan?.ports) ? shodan.ports.slice(0, 20) : [];
  const shodanTags = Array.isArray(shodan?.tags) ? shodan.tags.map((t) => t.toLowerCase()) : [];
  const hostnames = Array.isArray(shodan?.hostnames) ? shodan.hostnames.slice(0, 6) : [];
  const vulnsCount = Array.isArray(shodan?.vulns) ? shodan.vulns.length : 0;

  const exposedProxyPorts = openPorts.filter((p) => PROXY_SIGNATURE_PORTS.has(p));
  const hasExposedProxyPorts = exposedProxyPorts.length > 0;
  const hostnameImpliesProxy = hostnames.some((h) => /(vpn|proxy|tor|exit|socks|relay|node|vps|cloud|dedi)/i.test(h));

  const isDatacenter = usageType === 'hosting' || usageType === 'cdn' || shodanTags.includes('cloud') || shodanTags.includes('vpn');
  const isTor = Boolean(ipWho?.security?.tor || shodanTags.includes('tor'));
  const isProxyOrVpn = Boolean(
    ipWho?.security?.vpn ||
      ipWho?.security?.proxy ||
      ipApi?.proxy ||
      shodanTags.includes('vpn') ||
      shodanTags.includes('proxy') ||
      hasExposedProxyPorts ||
      (knownProfile && knownProfile.riskModifier <= -60)
  );
  const isAbuserOrCrawler = Boolean(shodanTags.includes('scanner') || shodanTags.includes('compromised') || shodanTags.includes('malware') || vulnsCount >= 3);

  // Build Explainable Purity Score (Base 92, clamped 0..100)
  let score = 92;
  const factors: ScoreFactor[] = [];

  // 1. ISP / ASN Type Factor
  if (usageType === 'residential') {
    score += 5;
    factors.push({
      id: 'isp_residential',
      delta: +5,
      severity: 'good',
      titleEn: 'Genuine Consumer ISP ASN',
      titleZh: '真实家庭宽带运营商 ASN',
      detailEn: `Routed via consumer broadband network (${isp}). High baseline trust for social & e-commerce platforms.`,
      detailZh: `隶属于民用家庭宽带网络 (${isp})，在社媒养号与跨境电商风控中拥有最高基础信任度。`,
    });
  } else if (usageType === 'mobile') {
    score += 6;
    factors.push({
      id: 'isp_mobile',
      delta: +6,
      severity: 'good',
      titleEn: 'Cellular Mobile Carrier (CGNAT)',
      titleZh: '蜂窝移动通信基站网络 (4G/5G)',
      detailEn: `Mobile carrier IP (${isp}) shares CGNAT across real handsets — rarely blocked by anti-bot engines.`,
      detailZh: `移动蜂窝基站网络 (${isp}) 天然由大量真实手机共享 CGNAT，极少触发平台封号机制。`,
    });
  } else if (usageType === 'education') {
    score += 2;
    factors.push({
      id: 'isp_edu',
      delta: +2,
      severity: 'info',
      titleEn: 'Academic / Research Network',
      titleZh: '高校 / 科研学术机构网络',
      detailEn: `Assigned to an educational or research institution (${isp}). Generally clean reputation.`,
      detailZh: `分配给高校或科研教育网 (${isp})，整体历史信誉干净。`,
    });
  } else if (usageType === 'cdn') {
    score -= 35;
    factors.push({
      id: 'isp_cdn',
      delta: -35,
      severity: 'warn',
      titleEn: 'Anycast CDN / Cloud Edge Proxy',
      titleZh: 'Anycast 边缘网关 / WARP 代理节点',
      detailEn: `Belongs to global edge network (${isp}). Websites recognize this as shared proxy/CDN egress rather than a household.`,
      detailZh: `属于全球任播边缘网络 (${isp})，各大平台会将其识别为共享代理/WARP 出口而非真实家庭住户。`,
    });
  } else if (usageType === 'hosting') {
    const penalty = knownProfile?.riskModifier ? Math.min(-35, knownProfile.riskModifier) : -45;
    score += penalty;
    factors.push({
      id: 'isp_hosting',
      delta: penalty,
      severity: 'bad',
      titleEn: 'Datacenter / Cloud Hosting ASN',
      titleZh: 'IDC 机房 / 云服务器托管段',
      detailEn: `${knownProfile?.note || isp} is classified as commercial server hosting. High risk of zero-views on TikTok and verification loops on AI/payment sites.`,
      detailZh: `识别为商业机房/云服务器网络 (${knownProfile?.note || isp})，极易触发 TikTok 零播放、AI 封号及支付风控。`,
    });
  }

  // 2. Native vs Broadcast IP Factor
  if (nativeStatus === 'native') {
    score += 3;
    factors.push({
      id: 'rir_native',
      delta: +3,
      severity: 'good',
      titleEn: `Verified Native IP (${countryCode})`,
      titleZh: `RIR 原生 IP 验真通过 (${countryCode})`,
      detailEn: `RIR WHOIS registration country (${rirCountryCode}) matches physical GeoIP location (${countryCode}).`,
      detailZh: `RIR 注册局原始分配国 (${rirCountryCode}) 与当前 BGP 物理归属地 (${countryCode}) 完全一致，属正宗原生 IP。`,
    });
  } else if (nativeStatus === 'broadcast') {
    score -= 18;
    factors.push({
      id: 'rir_broadcast',
      delta: -18,
      severity: 'warn',
      titleEn: `Broadcasted / Geo-Fed IP (${rirCountryCode} → ${countryCode})`,
      titleZh: `广播 IP 警告（原注册国 ${rirCountryCode} → 宣告至 ${countryCode}）`,
      detailEn: `Originally registered under ${rirCountryCode} in RIR WHOIS, but BGP-announced in ${countryCode}. Streaming & strict region locks may misidentify your region.`,
      detailZh: `WHOIS 原始注册地为 ${rirCountryCode}，后经 BGP 广播宣告至 ${countryCode}。部分流媒体、TikTok 及 AI 平台可能将其识别回原注册国。`,
    });
  } else if (nativeStatus === 'anycast') {
    factors.push({
      id: 'rir_anycast',
      delta: 0,
      severity: 'info',
      titleEn: 'Global Anycast Prefix',
      titleZh: '全球 Anycast 多点任播路由',
      detailEn: `Prefix is announced simultaneously from multiple global PoPs (RIR HQ: ${rirCountryCode}, Exit: ${countryCode}).`,
      detailZh: `该网段在全球多个边缘机房同时任播宣告（注册总部 ${rirCountryCode}，当前出口 ${countryCode}）。`,
    });
  }

  // 3. Proxy / VPN / Tor Intelligence Factor
  if (isTor) {
    score -= 50;
    factors.push({
      id: 'tor_exit',
      delta: -50,
      severity: 'bad',
      titleEn: 'Active Tor Anonymity Exit Node',
      titleZh: '命中 Tor 洋葱路由出口节点',
      detailEn: 'Listed as a public Tor exit relay. Blocked by virtually all banking, e-commerce, and AI platforms.',
      detailZh: '命中公开 Tor 匿名出口黑名单，几乎所有跨境支付、电商及主流 AI 平台均会直接拦截。',
    });
  } else if (isProxyOrVpn && usageType !== 'hosting') {
    score -= 28;
    factors.push({
      id: 'proxy_vpn_flag',
      delta: -28,
      severity: 'bad',
      titleEn: 'Proxy / VPN Tunnel Signature Detected',
      titleZh: '检测到共享 VPN / 代理中转特征',
      detailEn: 'Upstream threat feeds or proxy port telemetry flagged this IP as an active anonymizer or residential proxy relay.',
      detailZh: '威胁情报源或端口探针标记该 IP 存在活跃的共享 VPN / 代理转发行为（疑似被多人混用的家宽代理池）。',
    });
  } else if (isProxyOrVpn && usageType === 'hosting') {
    score -= 12;
    factors.push({
      id: 'proxy_vpn_hosting',
      delta: -12,
      severity: 'bad',
      titleEn: 'Known Commercial VPN / Proxy Transit',
      titleZh: '已知公共 VPN / 机场代理出口段',
      detailEn: 'Matches known public VPN or proxy server infrastructure with high multi-user IP sharing.',
      detailZh: '命中公共 VPN 或商业代理节点特征，多人共用出口会导致极高的连坐关联风险。',
    });
  }

  // 4. Shodan Open Ports & Reverse DNS Hygiene
  if (hasExposedProxyPorts) {
    score -= 15;
    factors.push({
      id: 'exposed_proxy_ports',
      delta: -15,
      severity: 'bad',
      titleEn: `Exposed Proxy / Tunnel Ports (${exposedProxyPorts.join(', ')})`,
      titleZh: `公网暴露代理特征端口 (${exposedProxyPorts.join(', ')})`,
      detailEn: 'Passive Internet scan detected open proxy/VPN listener ports on this IP, revealing non-household gateway behavior.',
      detailZh: '全网被动扫描发现该 IP 开放了代理或隧道监听端口，暴露了非普通家庭路由器的中转网关特征。',
    });
  } else if (openPorts.length > 5) {
    score -= 8;
    factors.push({
      id: 'many_open_ports',
      delta: -8,
      severity: 'warn',
      titleEn: `${openPorts.length} Publicly Reachable Server Ports`,
      titleZh: `开放 ${openPorts.length} 个公网服务端口`,
      detailEn: `Open ports (${openPorts.slice(0, 6).join(', ')}) indicate an internet-facing server rather than a NATed home device.`,
      detailZh: `公网暴露多个服务端口 (${openPorts.slice(0, 6).join(', ')})，表现为公网服务器而非家用 NAT 终端。`,
    });
  } else if (parsed.version === 4) {
    factors.push({
      id: 'clean_port_surface',
      delta: 0,
      severity: 'good',
      titleEn: 'Zero Exposed Proxy Ports',
      titleZh: '零代理特征端口暴露（端口面干净）',
      detailEn: 'No open SOCKS5, HTTP proxy, Shadowsocks, or WireGuard ports found in passive Internet scans.',
      detailZh: '全网扫描未发现开放 SOCKS5、HTTP 代理或常见科学上网协议特征端口，外网指纹隐蔽。',
    });
  }

  if (isAbuserOrCrawler) {
    score -= 22;
    factors.push({
      id: 'abuse_scanner',
      delta: -22,
      severity: 'bad',
      titleEn: 'Abuse / Scanner / CVE Footprint',
      titleZh: '存在恶意扫描或安全漏洞黑历史',
      detailEn: `Tagged with automated scanning activity or ${vulnsCount} unpatched CVEs in threat intelligence feeds.`,
      detailZh: `在威胁情报库中存在自动化扫描记录或 ${vulnsCount} 个未修复高危漏洞特征，连带欺诈分偏高。`,
    });
  } else if (hostnameImpliesProxy) {
    score -= 6;
    factors.push({
      id: 'rdns_server_hint',
      delta: -6,
      severity: 'warn',
      titleEn: 'Server-Style Reverse DNS (rDNS)',
      titleZh: '反向解析域名 (rDNS) 含机房/代理字样',
      detailEn: `PTR hostname (${hostnames[0]}) contains server/proxy naming patterns.`,
      detailZh: `PTR 反向域名 (${hostnames[0]}) 带有明显的云主机或代理节点命名规律。`,
    });
  }

  score = Math.max(2, Math.min(100, Math.round(score)));
  const fraudRisk = 100 - score;
  const grade = computeGrade(score);
  const riskLevel = computeRiskLevel(score);

  const verdictCopy = buildVerdictHeadline(grade, usageType, nativeStatus, countryCode);
  const platforms = buildPlatformMatrix({
    score,
    usageType,
    nativeStatus,
    countryCode,
    isProxyOrVpn,
    isTor,
    isAbuserOrCrawler,
  });

  const report: IpVerdictReport = {
    ip: parsed.normalized,
    version: parsed.version,
    evaluatedAt: new Date().toISOString(),
    latencyMs: Math.max(1, Date.now() - startedAt),
    score,
    fraudRisk,
    grade,
    riskLevel,
    verdictTitleEn: verdictCopy.titleEn,
    verdictTitleZh: verdictCopy.titleZh,
    verdictSummaryEn: verdictCopy.summaryEn,
    verdictSummaryZh: verdictCopy.summaryZh,
    geo: {
      countryCode,
      countryName,
      region,
      city,
      postalCode,
      latitude,
      longitude,
      timezone,
    },
    network: {
      asn,
      asnCode: asn ? `AS${asn}` : 'N/A',
      isp,
      org,
      domain,
      usageType,
      rirCountryCode,
      nativeStatus,
    },
    signals: {
      isDatacenter,
      isProxyOrVpn,
      isTor,
      isAbuserOrCrawler,
      hasExposedProxyPorts,
      openPorts,
      vulnsCount,
      hostnames,
      edgeTlsVersion: (cf?.tlsVersion as string) || undefined,
      edgeHttpProtocol: (cf?.httpProtocol as string) || undefined,
      edgeColo: (cf?.colo as string) || undefined,
    },
    factors,
    platforms,
    sources,
  };

  // Cache for 20 minutes in isolate memory (cap size at 500 entries)
  if (memoryCache.size > 500) {
    const oldestKey = memoryCache.keys().next().value;
    if (oldestKey) memoryCache.delete(oldestKey);
  }
  memoryCache.set(cacheKey, { expiresAt: now + 20 * 60 * 1000, report });

  if (options.kvNamespace && !options.isDirectVisitor) {
    try {
      await options.kvNamespace.put(cacheKey, JSON.stringify(report), { expirationTtl: 3600 });
    } catch {
      // Non-fatal
    }
  }

  return report;
}

function buildVerdictHeadline(grade: VerdictGrade, usageType: UsageType, nativeStatus: NativeStatus, country: string) {
  if (grade === 'S') {
    return {
      titleEn: `Pristine Native ${usageType === 'mobile' ? 'Mobile' : 'Residential'} IP`,
      titleZh: `极品纯净 · 原生${usageType === 'mobile' ? '蜂窝移动' : '家庭宽带'} IP`,
      summaryEn: `Final Verdict: Grade S. Genuine ${country} consumer ISP allocation with aligned RIR registration and zero proxy/port leaks.`,
      summaryZh: `判官终审：S 级极品纯净度。正宗 ${country} 本土民用宽带分配，RIR 注册国一致且无任何代理端口与黑名单污染，适合高价值账号长期运营。`,
    };
  }
  if (grade === 'A') {
    return {
      titleEn: 'Clean & Trustworthy Network Identity',
      titleZh: '优良纯净 · 高信任度网络环境',
      summaryEn: `Final Verdict: Grade A. Low fraud footprint suitable for daily browsing, AI workspaces, and standard regional services.`,
      summaryZh: `判官终审：A 级优良纯净度。整体欺诈风险极低，可安全用于主流跨境业务、AI 工具订阅与日常访问。`,
    };
  }
  if (grade === 'B') {
    return {
      titleEn: nativeStatus === 'broadcast' ? 'Broadcasted / Mixed-Signal IP' : 'Moderate Shared Network Risk',
      titleZh: nativeStatus === 'broadcast' ? '中度风险 · 广播宣告或混合特征 IP' : '中度风险 · 共享出口或轻度疑似特征',
      summaryEn: 'Final Verdict: Grade B. Usable for general web traffic, but strict anti-fraud platforms may trigger CAPTCHA or secondary SMS checks.',
      summaryZh: '判官终审：B 级中度风险。普通网页浏览无碍，但在风控极严的电商主店或新号注册场景下可能触发人机验证或二次风控。',
    };
  }
  if (grade === 'C') {
    return {
      titleEn: 'Datacenter / Shared Proxy Footprint',
      titleZh: '高危预警 · 机房托管或共享代理池',
      summaryEn: 'Final Verdict: Grade C. Recognized as server hosting or shared VPN infrastructure. Not recommended for TikTok, banking, or seller accounts.',
      summaryZh: '判官终审：C 级高风险环境。已被识别为云服务器机房或共享代理网络，严禁直接用于 TikTok 养号、跨境收款与电商店铺防关联。',
    };
  }
  return {
    titleEn: 'Critical Risk · Flagged Proxy / Abused Node',
    titleZh: '极高危裁决 · 万人骑节点或黑名单污染',
    summaryEn: 'Final Verdict: Grade D. Heavy anonymizer, exposed proxy ports, or abuse history detected. Expect immediate blocks or shadowbans.',
    summaryZh: '判官终审：D 级极高危裁决！命中公共代理/机房黑名单或暴露代理端口，极易导致账号秒封、零播放或支付拒付，建议立即更换纯净原生住宅 IP。',
  };
}

function buildPlatformMatrix(ctx: {
  score: number;
  usageType: UsageType;
  nativeStatus: NativeStatus;
  countryCode: string;
  isProxyOrVpn: boolean;
  isTor: boolean;
  isAbuserOrCrawler: boolean;
}): PlatformVerdict[] {
  const { score, usageType, nativeStatus, countryCode, isProxyOrVpn, isTor, isAbuserOrCrawler } = ctx;
  const isResOrMob = usageType === 'residential' || usageType === 'mobile';
  const aiRestrictedRegions = new Set(['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP']);

  // 1. TikTok Matrix
  let tiktok: PlatformVerdict;
  if (isResOrMob && nativeStatus === 'native' && !isProxyOrVpn && score >= 82) {
    tiktok = {
      id: 'tiktok',
      nameEn: 'TikTok Creator / Shop',
      nameZh: 'TikTok 养号 / 小店直播',
      status: 'pass',
      badgeEn: 'Native Residential Pass',
      badgeZh: '真原生家宽 · 推荐运营',
      reasonEn: `Clean ${countryCode} native ISP — optimal for normal For-You feed recommendation weight.`,
      reasonZh: `${countryCode} 正宗本土原生宽带，符合自然推流权重标准，不易出现 0 播放黑屏。`,
    };
  } else if (usageType === 'hosting' || usageType === 'cdn' || isTor || score < 55) {
    tiktok = {
      id: 'tiktok',
      nameEn: 'TikTok Creator / Shop',
      nameZh: 'TikTok 养号 / 小店直播',
      status: 'block',
      badgeEn: 'Shadowban / 0-View Risk',
      badgeZh: '极易 0 播放 / 限流高危',
      reasonEn: 'TikTok strictly penalizes datacenter ASNs and shared VPN exits with 0-view shadowbans.',
      reasonZh: 'TikTok 算法对机房 ASN 与公共代理极其敏感，使用此 IP 发视频极易触发 0 播放或店铺二审。',
    };
  } else {
    tiktok = {
      id: 'tiktok',
      nameEn: 'TikTok Creator / Shop',
      nameZh: 'TikTok 养号 / 小店直播',
      status: 'warn',
      badgeEn: nativeStatus === 'broadcast' ? 'Broadcast IP Caution' : 'Shared Pool Caution',
      badgeZh: nativeStatus === 'broadcast' ? '广播 IP · 推流偏区风险' : '共享特征 · 仅限浏览',
      reasonEn: 'Broadcasted prefix or moderate proxy signal may cause region mismatch in feed targeting.',
      reasonZh: '存在广播宣告或轻度共享特征，可能导致账号归属区错乱或推流受限，核心主号建议升级静态原生家宽。',
    };
  }

  // 2. AI Platforms (Claude / ChatGPT / Gemini)
  let ai: PlatformVerdict;
  if (aiRestrictedRegions.has(countryCode)) {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT / Gemini',
      nameZh: 'Claude / ChatGPT 防封检测',
      status: 'block',
      badgeEn: `Unsupported Region (${countryCode})`,
      badgeZh: `服务受限地区 (${countryCode})`,
      reasonEn: `Anthropic & OpenAI restrict direct access from ${countryCode}. Switch to a clean US/SG/JP/EU residential exit.`,
      reasonZh: `OpenAI 与 Anthropic 官方限制 ${countryCode} 地区访问，请切换至美/日/新/欧等支持地区的纯净节点。`,
    };
  } else if (isTor || isAbuserOrCrawler || score < 42) {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT / Gemini',
      nameZh: 'Claude / ChatGPT 防封检测',
      status: 'block',
      badgeEn: 'High Ban Probability',
      badgeZh: 'Claude 极易封号 / 降智',
      reasonEn: 'High-abuse datacenter/VPN exit triggers Anthropic automated account suspension & OpenAI PoW degradation.',
      reasonZh: '高污染机房/万人骑出口极易触发 Claude 自动封号及 ChatGPT 频繁弹验证/模型降智。',
    };
  } else if (usageType === 'hosting' || usageType === 'cdn') {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT / Gemini',
      nameZh: 'Claude / ChatGPT 防封检测',
      status: 'warn',
      badgeEn: 'API OK · Web Account Caution',
      badgeZh: 'API 可用 · 网页号慎用',
      reasonEn: 'Datacenter IP works for API calls, but Claude.ai web sign-ups strongly prefer residential ISPs.',
      reasonZh: '调用 API 接口无碍，但直接登录 Claude 网页版付费账号存在组织风控连坐隐患。',
    };
  } else {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT / Gemini',
      nameZh: 'Claude / ChatGPT 防封检测',
      status: 'pass',
      badgeEn: 'Full Reasoning & Safe Login',
      badgeZh: '满血不降智 · 安全登录',
      reasonEn: `Supported region (${countryCode}) with clean residential reputation — low risk of false bans.`,
      reasonZh: `支持地区 (${countryCode}) 且具备干净家宽信誉，不易触发风控封禁或算力降级。`,
    };
  }

  // 3. Cross-border E-commerce (Amazon / Etsy / Shopee / eBay)
  let ecommerce: PlatformVerdict;
  if (isResOrMob && !isProxyOrVpn && score >= 80) {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / Etsy Seller',
      nameZh: 'Amazon / Etsy 店铺防关联',
      status: 'pass',
      badgeEn: 'Isolated Seller Safe',
      badgeZh: '独立纯净 · 可登主店铺',
      reasonEn: 'Dedicated-looking consumer ISP footprint minimizes multi-account linkage alerts.',
      reasonZh: '本土运营商宽带指纹干净，配合独立浏览器环境可有效规避多店铺关联审核。',
    };
  } else if (score >= 58 && !isTor) {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / Etsy Seller',
      nameZh: 'Amazon / Etsy 店铺防关联',
      status: 'warn',
      badgeEn: 'Buyer OK · Seller Risky',
      badgeZh: '买家号可用 · 卖家店慎登',
      reasonEn: 'Acceptable for normal shopping, but seller central logins require static native residential IPs.',
      reasonZh: '可用于普通买家浏览下单，但登录跨境卖家后台存在同段历史关联风险。',
    };
  } else {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / Etsy Seller',
      nameZh: 'Amazon / Etsy 店铺防关联',
      status: 'block',
      badgeEn: 'Account Linkage Hazard',
      badgeZh: '高关联封店风险',
      reasonEn: 'Shared hosting/VPN IPs are heavily blacklisted by Etsy & Amazon Seller risk engines.',
      reasonZh: 'Etsy 与亚马逊卖家风控对机房及共享代理段实施严厉连坐扫号，切勿直接登录店铺后台。',
    };
  }

  // 4. Streaming Unlock (Netflix / Disney+ / Spotify)
  let streaming: PlatformVerdict;
  if (isResOrMob && nativeStatus === 'native' && !isProxyOrVpn) {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Disney+ Originals',
      nameZh: 'Netflix / 流媒体全解锁',
      status: 'pass',
      badgeEn: `Full ${countryCode} Library Unlock`,
      badgeZh: `解锁 ${countryCode} 本土非自制剧`,
      reasonEn: 'Native residential ISP unlocks full local third-party catalog without proxy error.',
      reasonZh: '正宗原生本土 ISP，完美解锁当地版权库（含非自制剧、Disney+ 及区域限定体育赛事）。',
    };
  } else if (nativeStatus === 'broadcast' || usageType === 'cdn') {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Disney+ Originals',
      nameZh: 'Netflix / 流媒体全解锁',
      status: 'warn',
      badgeEn: 'Originals Only / Geo Drift',
      badgeZh: '仅自制剧或跨区偏移',
      reasonEn: 'Broadcasted or Anycast IP often falls back to Netflix Originals-only catalog.',
      reasonZh: '广播 IP 或边缘任播段容易被流媒体版权库识别为代理，通常仅能观看 Netflix 自制剧。',
    };
  } else {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Disney+ Originals',
      nameZh: 'Netflix / 流媒体全解锁',
      status: 'block',
      badgeEn: 'Unblocker / Proxy Flagged',
      badgeZh: '机房段 · 版权库受限',
      reasonEn: 'Commercial hosting ASNs are routinely restricted to Originals or blocked by Disney+/Hulu.',
      reasonZh: '主流商业云机房网段均在流媒体 Unblocker 拦截名单内，无法稳定解锁本土版权内容。',
    };
  }

  // 5. FinTech & Payments (Stripe / PayPal)
  let payments: PlatformVerdict;
  if (score >= 78 && !isProxyOrVpn && !isTor) {
    payments = {
      id: 'payments',
      nameEn: 'Stripe Radar / PayPal',
      nameZh: 'Stripe / PayPal 支付风控',
      status: 'pass',
      badgeEn: 'Low 3DS Friction',
      badgeZh: '低拒付分 · 顺畅绑卡支付',
      reasonEn: 'Low fraud score passes Stripe Radar checks when billing country & browser timezone match.',
      reasonZh: '反欺诈评分健康，只要保持账单国家与浏览器本地时区一致即可顺畅完成绑卡结账。',
    };
  } else if (score >= 52 && !isTor) {
    payments = {
      id: 'payments',
      nameEn: 'Stripe Radar / PayPal',
      nameZh: 'Stripe / PayPal 支付风控',
      status: 'warn',
      badgeEn: '3DS Verification Likely',
      badgeZh: '易触发 3DS 验证 / 预授权审单',
      reasonEn: 'Elevated network risk may trigger mandatory 3D-Secure or manual card verification.',
      reasonZh: '网络环境存在一定代理或机房权重，大额支付或虚拟卡绑卡可能触发强制 3DS 验证。',
    };
  } else {
    payments = {
      id: 'payments',
      nameEn: 'Stripe Radar / PayPal',
      nameZh: 'Stripe / PayPal 支付风控',
      status: 'block',
      badgeEn: 'High Decline / Limitation Risk',
      badgeZh: '极易拒付 / PayPal 180天风控',
      reasonEn: 'Stripe Radar & PayPal automatically decline high-risk anonymizer/VPS checkouts.',
      reasonZh: '高危代理与云机房 IP 登录收付款账户极易触发 Stripe Radar 拦截或 PayPal 账户受限。',
    };
  }

  return [tiktok, ai, ecommerce, streaming, payments];
}

function buildBogonReport(ip: string, version: 4 | 6, reason: string, latencyMs: number): IpVerdictReport {
  return {
    ip,
    version,
    evaluatedAt: new Date().toISOString(),
    latencyMs: Math.max(1, latencyMs),
    score: 100,
    fraudRisk: 0,
    grade: 'A',
    riskLevel: 'low',
    verdictTitleEn: 'Private / Local Reserved Address',
    verdictTitleZh: '内网保留地址 / 本地回环 IP',
    verdictSummaryEn: `${ip} falls within ${reason} and is not publicly routable on the global Internet.`,
    verdictSummaryZh: `${ip} 属于 ${reason}，仅在局域网或本地回环环境内生效，不参与公网路由。`,
    geo: {
      countryCode: 'LO',
      countryName: 'Local / Private Network',
      region: 'Internal',
      city: 'Localhost',
      postalCode: '',
      latitude: null,
      longitude: null,
      timezone: 'UTC',
    },
    network: {
      asn: null,
      asnCode: 'PRIVATE',
      isp: reason,
      org: 'IANA Reserved Address Space',
      domain: 'local',
      usageType: 'reserved',
      rirCountryCode: 'LO',
      nativeStatus: 'unknown',
    },
    signals: {
      isDatacenter: false,
      isProxyOrVpn: false,
      isTor: false,
      isAbuserOrCrawler: false,
      hasExposedProxyPorts: false,
      openPorts: [],
      vulnsCount: 0,
      hostnames: [],
    },
    factors: [
      {
        id: 'bogon_range',
        delta: 0,
        severity: 'info',
        titleEn: reason,
        titleZh: 'IANA 私有/保留地址段',
        detailEn: 'Non-routable internal address. Query a public IPv4/IPv6 address to inspect internet purity.',
        detailZh: '非公网可路由地址。请在上方输入框填入您的公网出口 IP 进行纯净度裁决。',
      },
    ],
    platforms: [],
    sources: ['IANA RFC Registry'],
  };
}
