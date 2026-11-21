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
import type { KVNamespace } from '@cloudflare/workers-types';

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
      titleEn: 'Residential ISP Network',
      titleZh: '家庭宽带运营商网络',
      detailEn: `Assigned to consumer broadband ISP (${isp}).`,
      detailZh: `归属普通民用宽带运营商 (${isp})，信誉度良好。`,
    });
  } else if (usageType === 'mobile') {
    score += 6;
    factors.push({
      id: 'isp_mobile',
      delta: +6,
      severity: 'good',
      titleEn: 'Mobile Carrier Network',
      titleZh: '移动蜂窝运营商网络',
      detailEn: `Mobile carrier network (${isp}) using shared carrier NAT.`,
      detailZh: `归属移动通信运营商 (${isp})，通常不易触发反爬与风控拦截。`,
    });
  } else if (usageType === 'education') {
    score += 2;
    factors.push({
      id: 'isp_edu',
      delta: +2,
      severity: 'info',
      titleEn: 'Education / Research Network',
      titleZh: '教育或科研机构网络',
      detailEn: `Assigned to an academic or research organization (${isp}).`,
      detailZh: `分配给高校或科研机构 (${isp})，历史风险较低。`,
    });
  } else if (usageType === 'cdn') {
    score -= 35;
    factors.push({
      id: 'isp_cdn',
      delta: -35,
      severity: 'warn',
      titleEn: 'CDN / Anycast Edge Network',
      titleZh: 'CDN / 边缘网络出口',
      detailEn: `Belongs to an edge/CDN provider (${isp}) rather than a local household ISP.`,
      detailZh: `属于边缘网关或公共代理服务 (${isp})，非普通家庭宽带地址。`,
    });
  } else if (usageType === 'hosting') {
    const penalty = knownProfile?.riskModifier ? Math.min(-35, knownProfile.riskModifier) : -45;
    score += penalty;
    factors.push({
      id: 'isp_hosting',
      delta: penalty,
      severity: 'bad',
      titleEn: 'Datacenter / Cloud Hosting ASN',
      titleZh: '数据中心 / 云服务器网段',
      detailEn: `${knownProfile?.note || isp} is registered as server hosting infrastructure.`,
      detailZh: `所属自治系统 (${knownProfile?.note || isp}) 为云服务器或托管机房网段。`,
    });
  }

  // 2. Native vs Broadcast IP Factor
  if (nativeStatus === 'native') {
    score += 3;
    factors.push({
      id: 'rir_native',
      delta: +3,
      severity: 'good',
      titleEn: `Native IP (${countryCode})`,
      titleZh: `原生 IP (${countryCode})`,
      detailEn: `WHOIS registration country (${rirCountryCode}) matches GeoIP location (${countryCode}).`,
      detailZh: `WHOIS 注册国家 (${rirCountryCode}) 与当前物理归属地 (${countryCode}) 一致。`,
    });
  } else if (nativeStatus === 'broadcast') {
    score -= 18;
    factors.push({
      id: 'rir_broadcast',
      delta: -18,
      severity: 'warn',
      titleEn: `Broadcasted IP (${rirCountryCode} → ${countryCode})`,
      titleZh: `广播 IP（注册国 ${rirCountryCode} → 当前 ${countryCode}）`,
      detailEn: `Registered under ${rirCountryCode} in WHOIS, currently routed in ${countryCode}. Some services may detect the original country.`,
      detailZh: `WHOIS 原始注册国为 ${rirCountryCode}，通过 BGP 广播在 ${countryCode} 使用，部分平台可能识别为原注册国。`,
    });
  } else if (nativeStatus === 'anycast') {
    factors.push({
      id: 'rir_anycast',
      delta: 0,
      severity: 'info',
      titleEn: 'Anycast Prefix',
      titleZh: '全球任播网段 (Anycast)',
      detailEn: `Announced from multiple global locations (RIR: ${rirCountryCode}, Current: ${countryCode}).`,
      detailZh: `该网段在全球多地同时宣告（注册地 ${rirCountryCode}，当前接入 ${countryCode}）。`,
    });
  }

  // 3. Proxy / VPN / Tor Intelligence Factor
  if (isTor) {
    score -= 50;
    factors.push({
      id: 'tor_exit',
      delta: -50,
      severity: 'bad',
      titleEn: 'Tor Exit Node',
      titleZh: 'Tor 出口节点',
      detailEn: 'Listed as a public Tor exit relay.',
      detailZh: '位于公开 Tor 匿名网络出口列表中，大多数网站会直接限制访问。',
    });
  } else if (isProxyOrVpn && usageType !== 'hosting') {
    score -= 28;
    factors.push({
      id: 'proxy_vpn_flag',
      delta: -28,
      severity: 'bad',
      titleEn: 'Proxy / VPN Activity Detected',
      titleZh: '检测到代理或 VPN 特征',
      detailEn: 'Flagged by upstream security feeds or open proxy port checks.',
      detailZh: '风险库或端口检测显示该地址存在共享代理或 VPN 转发记录。',
    });
  } else if (isProxyOrVpn && usageType === 'hosting') {
    score -= 12;
    factors.push({
      id: 'proxy_vpn_hosting',
      delta: -12,
      severity: 'bad',
      titleEn: 'Commercial VPN / Proxy Provider',
      titleZh: '已知公共 VPN / 代理服务商',
      detailEn: 'Matches known commercial VPN or shared proxy server ranges.',
      detailZh: '属于常见商业 VPN 或公共代理服务商网段，多人共用概率较高。',
    });
  }

  // 4. Shodan Open Ports & Reverse DNS Hygiene
  if (hasExposedProxyPorts) {
    score -= 15;
    factors.push({
      id: 'exposed_proxy_ports',
      delta: -15,
      severity: 'bad',
      titleEn: `Open Proxy Ports (${exposedProxyPorts.join(', ')})`,
      titleZh: `开放代理端口 (${exposedProxyPorts.join(', ')})`,
      detailEn: 'Publicly reachable proxy or tunnel ports detected in Shodan scans.',
      detailZh: '公网扫描发现开放常见代理或隧道服务端口。',
    });
  } else if (openPorts.length > 5) {
    score -= 8;
    factors.push({
      id: 'many_open_ports',
      delta: -8,
      severity: 'warn',
      titleEn: `${openPorts.length} Open Public Ports`,
      titleZh: `开放 ${openPorts.length} 个公网端口`,
      detailEn: `Multiple open ports (${openPorts.slice(0, 6).join(', ')}) suggest a server host.`,
      detailZh: `对外开放多个服务端口 (${openPorts.slice(0, 6).join(', ')})，具有服务器特征。`,
    });
  } else if (parsed.version === 4) {
    factors.push({
      id: 'clean_port_surface',
      delta: 0,
      severity: 'good',
      titleEn: 'No Exposed Proxy Ports',
      titleZh: '无公开代理端口暴露',
      detailEn: 'No open SOCKS5, HTTP proxy, or VPN ports found in public scan data.',
      detailZh: '公开扫描数据中未发现开放常见代理端口。',
    });
  }

  if (isAbuserOrCrawler) {
    score -= 22;
    factors.push({
      id: 'abuse_scanner',
      delta: -22,
      severity: 'bad',
      titleEn: 'Historical Abuse / Vulnerability Tags',
      titleZh: '存在扫描或安全漏洞记录',
      detailEn: `Flagged with scanner activity or ${vulnsCount} known CVEs in Shodan.`,
      detailZh: `在威胁记录中存在扫描行为或 ${vulnsCount} 个未修复漏洞记录。`,
    });
  } else if (hostnameImpliesProxy) {
    score -= 6;
    factors.push({
      id: 'rdns_server_hint',
      delta: -6,
      severity: 'warn',
      titleEn: 'Server Hostname Pattern (rDNS)',
      titleZh: '反向域名包含服务器特征词',
      detailEn: `PTR record (${hostnames[0]}) matches hosting/proxy naming conventions.`,
      detailZh: `反向解析记录 (${hostnames[0]}) 带有云主机或节点命名特征。`,
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
      titleEn: `Clean Native ${usageType === 'mobile' ? 'Mobile' : 'Residential'} IP`,
      titleZh: `高纯净度 · ${country} 原生${usageType === 'mobile' ? '移动网络' : '家庭宽带'}`,
      summaryEn: `${country} consumer ISP address with matching WHOIS registration and no detected proxy or blacklist records.`,
      summaryZh: `属于 ${country} 本地民用宽带网段，WHOIS 注册国家与归属地一致，未发现代理端口暴露或风险记录。`,
    };
  }
  if (grade === 'A') {
    return {
      titleEn: 'Low-Risk Network Address',
      titleZh: '纯净度良好 · 低风险网络',
      summaryEn: 'Clean network reputation with low fraud indicators, suitable for regular web services.',
      summaryZh: '整体网络信誉良好，无明显滥用记录，适合常规跨境业务与日常访问。',
    };
  }
  if (grade === 'B') {
    return {
      titleEn: nativeStatus === 'broadcast' ? 'Broadcasted IP · Moderate Risk' : 'Moderate Risk · Shared Signal',
      titleZh: nativeStatus === 'broadcast' ? '中等风险 · 广播 IP 网段' : '中等风险 · 存在共享网络特征',
      summaryEn: 'Usable for general browsing, though stricter platforms may request CAPTCHA verification.',
      summaryZh: '日常网页浏览正常，但在风控较严的平台注册或登录时可能出现人机验证。',
    };
  }
  if (grade === 'C') {
    return {
      titleEn: 'High Risk · Hosting / Shared Proxy',
      titleZh: '较高风险 · 机房托管或共享节点',
      summaryEn: 'Identified as cloud hosting or shared proxy infrastructure. Not recommended for sensitive accounts.',
      summaryZh: '识别为云服务器机房或共享代理网络，不建议直接用于对网络环境敏感的账号运营。',
    };
  }
  return {
    titleEn: 'High Fraud Risk · Flagged Proxy / Hosting',
    titleZh: '高风险 · 公共代理或受污染网段',
    summaryEn: 'Public VPN/proxy exit, exposed tunnel ports, or abuse history detected. Frequently restricted by websites.',
    summaryZh: '检测到公共代理出口、开放代理端口或历史滥用记录，访问主流平台容易受限或触发风控。',
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
      nameEn: 'TikTok',
      nameZh: 'TikTok 运营',
      status: 'pass',
      badgeEn: 'Available',
      badgeZh: '正常可用',
      reasonEn: `Native ${countryCode} consumer ISP with clean reputation.`,
      reasonZh: `${countryCode} 本地原生宽带，符合常规账号推流环境要求。`,
    };
  } else if (usageType === 'hosting' || usageType === 'cdn' || isTor || score < 55) {
    tiktok = {
      id: 'tiktok',
      nameEn: 'TikTok',
      nameZh: 'TikTok 运营',
      status: 'block',
      badgeEn: 'High Risk',
      badgeZh: '限流风险高',
      reasonEn: 'Datacenter ASNs and public proxies frequently trigger traffic restrictions.',
      reasonZh: '机房网段与公共代理容易触发账号异常验证或播放受限。',
    };
  } else {
    tiktok = {
      id: 'tiktok',
      nameEn: 'TikTok',
      nameZh: 'TikTok 运营',
      status: 'warn',
      badgeEn: nativeStatus === 'broadcast' ? 'Broadcast IP' : 'Caution',
      badgeZh: nativeStatus === 'broadcast' ? '广播网段' : '一般可用',
      reasonEn: 'Broadcasted prefix or shared network may affect region targeting accuracy.',
      reasonZh: '非本地原生分配或存在共享特征，可能导致地区识别偏差。',
    };
  }

  // 2. AI Platforms (Claude / ChatGPT / Gemini)
  let ai: PlatformVerdict;
  if (aiRestrictedRegions.has(countryCode)) {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT',
      nameZh: 'Claude / ChatGPT',
      status: 'block',
      badgeEn: `Unsupported (${countryCode})`,
      badgeZh: `地区受限 (${countryCode})`,
      reasonEn: `Service is not officially supported in ${countryCode}.`,
      reasonZh: `当前所在地区 (${countryCode}) 不在官方支持服务列表内。`,
    };
  } else if (isTor || isAbuserOrCrawler || score < 42) {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT',
      nameZh: 'Claude / ChatGPT',
      status: 'block',
      badgeEn: 'High Risk',
      badgeZh: '风控风险高',
      reasonEn: 'High-risk proxy ranges often trigger login blocks or frequent CAPTCHAs.',
      reasonZh: '高风险代理网段容易导致登录受阻、频繁人机验证或账号受限。',
    };
  } else if (usageType === 'hosting' || usageType === 'cdn') {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT',
      nameZh: 'Claude / ChatGPT',
      status: 'warn',
      badgeEn: 'Hosting IP',
      badgeZh: '机房出口',
      reasonEn: 'Works for API requests, though web accounts are safer on residential networks.',
      reasonZh: '调用 API 正常，网页端长期登录更建议使用宽带网络。',
    };
  } else {
    ai = {
      id: 'ai',
      nameEn: 'Claude / ChatGPT',
      nameZh: 'Claude / ChatGPT',
      status: 'pass',
      badgeEn: 'Supported',
      badgeZh: '正常可用',
      reasonEn: `Supported region (${countryCode}) with low risk score.`,
      reasonZh: `属于受支持地区 (${countryCode})，网络信誉正常。`,
    };
  }

  // 3. Cross-border E-commerce (Amazon / Etsy / Shopee / eBay)
  let ecommerce: PlatformVerdict;
  if (isResOrMob && !isProxyOrVpn && score >= 80) {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / E-commerce',
      nameZh: '跨境电商店铺',
      status: 'pass',
      badgeEn: 'Low Risk',
      badgeZh: '环境正常',
      reasonEn: 'Standard residential ISP footprint suitable for store management.',
      reasonZh: '常规本地宽带特征，适合配合独立环境进行店铺管理。',
    };
  } else if (score >= 58 && !isTor) {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / E-commerce',
      nameZh: '跨境电商店铺',
      status: 'warn',
      badgeEn: 'Buyer Only',
      badgeZh: '仅适合浏览',
      reasonEn: 'Fine for browsing, but seller accounts typically require dedicated residential IPs.',
      reasonZh: '普通购物浏览无碍，登录卖家后台建议使用固定独享宽带 IP。',
    };
  } else {
    ecommerce = {
      id: 'ecommerce',
      nameEn: 'Amazon / E-commerce',
      nameZh: '跨境电商店铺',
      status: 'block',
      badgeEn: 'High Risk',
      badgeZh: '不建议使用',
      reasonEn: 'Datacenter and shared VPN addresses carry high account verification risk.',
      reasonZh: '机房及多人共享节点登录电商后台容易触发二审验证。',
    };
  }

  // 4. Streaming Unlock (Netflix / Disney+ / Spotify)
  let streaming: PlatformVerdict;
  if (isResOrMob && nativeStatus === 'native' && !isProxyOrVpn) {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Streaming',
      nameZh: '流媒体地域版权',
      status: 'pass',
      badgeEn: `Local (${countryCode})`,
      badgeZh: `本地片库 (${countryCode})`,
      reasonEn: 'Native ISP typically accesses full regional streaming libraries.',
      reasonZh: '原生运营商网段，通常可正常访问当地完整版权内容。',
    };
  } else if (nativeStatus === 'broadcast' || usageType === 'cdn') {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Streaming',
      nameZh: '流媒体地域版权',
      status: 'warn',
      badgeEn: 'Limited',
      badgeZh: '部分受限',
      reasonEn: 'Broadcasted or Anycast prefixes may be limited to Originals-only content.',
      reasonZh: '广播或任播网段可能仅解锁自制内容，或出现跨区偏差。',
    };
  } else {
    streaming = {
      id: 'streaming',
      nameEn: 'Netflix / Streaming',
      nameZh: '流媒体地域版权',
      status: 'block',
      badgeEn: 'Restricted',
      badgeZh: '机房受限',
      reasonEn: 'Cloud hosting ranges are commonly flagged by streaming proxy filters.',
      reasonZh: '商业云主机网段通常会被流媒体平台识别并限制地区版权库。',
    };
  }

  // 5. FinTech & Payments (Stripe / PayPal)
  let payments: PlatformVerdict;
  if (score >= 78 && !isProxyOrVpn && !isTor) {
    payments = {
      id: 'payments',
      nameEn: 'Stripe / PayPal',
      nameZh: '在线支付结账',
      status: 'pass',
      badgeEn: 'Normal',
      badgeZh: '风控较低',
      reasonEn: 'Low fraud score when browser timezone matches billing country.',
      reasonZh: '风险分较低，保持浏览器时区与账单地区一致即可正常支付。',
    };
  } else if (score >= 52 && !isTor) {
    payments = {
      id: 'payments',
      nameEn: 'Stripe / PayPal',
      nameZh: '在线支付结账',
      status: 'warn',
      badgeEn: '3DS Check',
      badgeZh: '可能需验证',
      reasonEn: 'Moderate risk score may trigger 3D-Secure verification during checkout.',
      reasonZh: '在线支付时可能触发银行 3DS 短信或二次身份验证。',
    };
  } else {
    payments = {
      id: 'payments',
      nameEn: 'Stripe / PayPal',
      nameZh: '在线支付结账',
      status: 'block',
      badgeEn: 'High Risk',
      badgeZh: '易被拦截',
      reasonEn: 'High-risk proxy/hosting exits are frequently declined by payment gateways.',
      reasonZh: '高风险代理或机房出口容易触发支付网关拒付保护。',
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
