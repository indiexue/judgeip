/**
 * IP 报告用到的数据来源。/data 页面、API 文档和 curl 文本报告都从这里取，
 * 增减上游时改这一处，页面上的说明随之更新。
 */
interface Text {
  zh: string;
  en: string;
}

export interface DataSource {
  name: string;
  url: string;
  provides: Text;
  scope: Text;
  freshness: Text;
  /* 单次请求的超时，毫秒 */
  timeoutMs: number;
}

export const REPORT_SOURCES: DataSource[] = [
  {
    name: 'IPsum', url: 'https://github.com/stamparm/ipsum',
    provides: { zh: 'IPv4 聚合信誉名单、底层名单计数与更新时间（不是独立票数）；Unlicense', en: 'Aggregated IPv4 reputation, underlying list count and update timestamp (not independent votes); Unlicense' },
    scope: { zh: 'IPv4；未列入不代表无滥用', en: 'IPv4; absence does not prove no abuse' },
    freshness: { zh: '每天定时抓取并重新部署；当天索引超过 72 小时记为未获取。另保留近 30 天被 ≥2 份名单收录的历史，该历史文件在公开仓库中', en: 'Fetched daily with a redeploy; a same-day index older than 72 hours is unavailable. A 30-day history of addresses listed by at least 2 lists is also kept, in the public repository' },
    timeoutMs: 2800,
  },
  {
    name: 'X4BNet VPN ranges / Spamhaus DROP / FireHOL level1', url: 'https://github.com/X4BNet/lists_vpn',
    provides: { zh: '按网段发布的名单：X4BNet 的 VPN 出口段（MIT）命中按 VPN 计；Spamhaus DROP 命中按重度风险；FireHOL level1 命中按中度风险', en: 'Range lists: X4BNet VPN exit ranges (MIT) count as VPN; a Spamhaus DROP hit is severe risk; a FireHOL level1 hit is moderate risk' },
    scope: { zh: 'IPv4；只覆盖已收录的网段，未命中不代表不是 VPN 或没有滥用', en: 'IPv4; covers listed ranges only, a miss does not rule out VPN or abuse' },
    freshness: { zh: '每次部署时抓取；超过 8 天的文件记为未获取', en: 'Fetched at each deployment; files older than 8 days are unavailable' },
    timeoutMs: 1200,
  },
  {
    name: 'Cloudflare Radar (optional)', url: 'https://radar.cloudflare.com/',
    provides: { zh: '人机比例：该 ASN 近 7 天发往 Cloudflare 的 HTTP 请求里人类与机器流量的占比；不参与评分', en: 'Human / bot share: human and automated share of HTTP requests from the ASN to Cloudflare over the last 7 days; not scored' },
    scope: { zh: '整个 ASN 的统计，不是单个 IP；仅在配置 Radar API Token 时显示', en: 'Whole-ASN statistic, not per IP; shown only with a Radar API token configured' },
    freshness: { zh: '按 ASN 缓存 12 小时', en: 'Cached per ASN for 12 hours' }, timeoutMs: 2000,
  },
  {
    name: 'AbuseIPDB / ipapi.is (optional)', url: 'https://www.abuseipdb.com/',
    provides: { zh: '仅配置授权 Key 时查询滥用证据；未配置与失败单独展示', en: 'Abuse evidence only with configured authorized keys; not configured and unavailable are explicit' },
    scope: { zh: '取决于提供者；不含 IPQualityScore / ipdata', en: 'Provider-dependent; does not include IPQualityScore / ipdata' },
    freshness: { zh: '随查询获取；受提供者配额和历史窗口限制', en: 'Fetched per lookup, subject to provider quota and history windows' }, timeoutMs: 2300,
  },
  {
    name: 'ipwho.is',
    url: 'https://ipwho.is',
    provides: { zh: '国家、地区、城市、经纬度、时区、ASN 与运营商，以及 proxy / vpn / tor / hosting 标记', en: 'Country, region, city, coordinates, time zone, ASN and operator, plus proxy / vpn / tor / hosting flags' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '由对方维护，更新频率未公开', en: 'Maintained upstream; update frequency not published' },
    timeoutMs: 2300,
  },
  {
    name: 'ipquery.io',
    url: 'https://ipquery.io',
    provides: { zh: '双栈 ASN / 运营商归属、地理位置，以及 is_datacenter / is_vpn / is_tor / is_proxy 与风险分', en: 'Dual-stack ASN / operator, geolocation, plus is_datacenter / is_vpn / is_tor / is_proxy and risk score' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '实时查询公开威胁与路由聚合库', en: 'Queried live against aggregated routing and risk feeds' },
    timeoutMs: 2200,
  },
  {
    name: 'proxycheck.io',
    url: 'https://proxycheck.io',
    provides: { zh: 'VPN / 代理 / Tor / 机房类型识别与 0–100 风险评分（支持配置 PROXYCHECK_KEY 提升配额）', en: 'VPN / proxy / Tor / hosting type classification and 0–100 risk score (optional PROXYCHECK_KEY for higher quota)' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '每日同步商业 VPN 出口与代理池', en: 'Synced daily with commercial VPN exits and proxy pools' },
    timeoutMs: 2200,
  },
  {
    name: 'PeeringDB',
    url: 'https://www.peeringdb.com',
    provides: { zh: '自治系统（ASN）官方登记的网络类型（Cable/DSL/ISP、Content、Enterprise、Educational、NSP）', en: 'Operator-registered ASN network type (Cable/DSL/ISP, Content, Enterprise, Educational, NSP)' },
    scope: { zh: '全球活跃 ASN', en: 'Global active ASNs' },
    freshness: { zh: '按 ASN 查询，边缘节点缓存 6 小时', en: 'Queried by ASN and cached for 6 hours per edge node' },
    timeoutMs: 1600,
  },
  {
    name: 'Shodan InternetDB',
    url: 'https://internetdb.shodan.io',
    provides: { zh: '历史扫描到的开放端口、标签（vpn、tor、scanner、compromised 等）、CVE 编号和主机名', en: 'Open ports seen in past scans, tags (vpn, tor, scanner, compromised and others), CVE IDs and hostnames' },
    scope: { zh: '仅 IPv4', en: 'IPv4 only' },
    freshness: { zh: '对方每周更新一次，不是实时探测', en: 'Updated weekly upstream; not a live probe' },
    timeoutMs: 2000,
  },
  {
    name: 'RIPEstat & RDAP',
    url: 'https://stat.ripe.net',
    provides: { zh: 'RIR 注册机构与注册国家（whois / rir，超时由 RDAP 兜底）、地址段登记机构及其所在国家、ASN 持有方与注册日期（RDAP）、BGP 前缀与起源 ASN（network-info）、PTR 反向解析、RPKI 校验结果', en: 'RIR and registered country (whois / rir, with RDAP fallback on timeout), range registrant and its country, ASN holder and registration date (RDAP), BGP prefix and origin ASN (network-info), PTR record, RPKI validation result' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '实时查询各 RIR 与路由采集点', en: 'Queried live against the RIRs and route collectors' },
    timeoutMs: 3200,
  },
  {
    name: 'DNSBL',
    url: 'https://1.1.1.1/dns-query',
    provides: { zh: 'SpamCop、DroneBL、Barracuda、UCEPROTECT Level 1 四个黑名单是否列入，经 Cloudflare DoH 查询', en: 'Listing status on SpamCop, DroneBL, Barracuda and UCEPROTECT Level 1, queried over Cloudflare DoH' },
    scope: { zh: '仅 IPv4', en: 'IPv4 only' },
    freshness: { zh: '实时查询，受 DNS 记录 TTL 影响', en: 'Queried live, subject to DNS record TTLs' },
    timeoutMs: 1600,
  },
  {
    name: 'Cloudflare request.cf',
    url: 'https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties',
    provides: { zh: '访客自己这次请求的 ASN、国家、城市、时区、接入机房和 TLS 版本', en: "The visitor's own ASN, country, city, time zone, edge location and TLS version for the current request" },
    scope: { zh: '只用于查看本机 IP，查询别的 IP 时不用', en: 'Only when viewing your own IP; not used for other IPs' },
    freshness: { zh: '随请求实时给出', en: 'Supplied with each request' },
    timeoutMs: 0,
  },
];

/* 首页“多库定位”一栏逐个对比的地理库 */
export const GEO_SOURCES: Array<{ name: string; url: string }> = [
  { name: 'IP2Location.io', url: 'https://www.ip2location.io' },
  { name: 'DB-IP', url: 'https://db-ip.com' },
  { name: 'IPinfo', url: 'https://ipinfo.io' },
  { name: 'MaxMind GeoLite2 (GeoJS)', url: 'https://www.geojs.io' },
];

/* 与 ipcx-lookup.ts 里 memCache 的设置一致 */
export const CACHE_COMPLETE_MINUTES = 20;
export const CACHE_PARTIAL_SECONDS = 30;
export const CACHE_MAX_ENTRIES = 400;
