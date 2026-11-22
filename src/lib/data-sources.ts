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
    name: 'ipwho.is',
    url: 'https://ipwho.is',
    provides: { zh: '国家、地区、城市、经纬度、时区、ASN 与运营商，以及 proxy / vpn / tor / hosting 标记', en: 'Country, region, city, coordinates, time zone, ASN and operator, plus proxy / vpn / tor / hosting flags' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '由对方维护，更新频率未公开', en: 'Maintained upstream; update frequency not published' },
    timeoutMs: 2300,
  },
  {
    name: 'ip-api.com',
    url: 'https://ip-api.com',
    provides: { zh: '国家、地区、城市、时区、ISP / 组织 / AS，以及 mobile / proxy / hosting 标记', en: 'Country, region, city, time zone, ISP / organisation / AS, plus mobile / proxy / hosting flags' },
    scope: { zh: 'IPv4、IPv6', en: 'IPv4, IPv6' },
    freshness: { zh: '由对方维护，更新频率未公开', en: 'Maintained upstream; update frequency not published' },
    timeoutMs: 2300,
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
    name: 'RIPEstat',
    url: 'https://stat.ripe.net',
    provides: { zh: 'RIR 注册机构与注册国家（whois / rir，超时由 RDAP 兜底）、BGP 前缀与起源 ASN（network-info）、PTR 反向解析、RPKI 校验结果', en: 'RIR and registered country (whois / rir, with RDAP fallback on timeout), BGP prefix and origin ASN (network-info), PTR record, RPKI validation result' },
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
