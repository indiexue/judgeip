/**
 * 首页评分的全部规则。lookupIpFull 按这里的分值计分，/scoring 页面和 curl 文本报告也从这里取数，
 * 页面上公布的规则与实际计分因此是同一份，不会各说各话。
 */
export const SCORE_BASE = 95;
export const SCORE_MIN = 5;
export const SCORE_MAX = 99;

export const SCORE_DELTAS = {
  hosting: -33,
  cdn: -25,
  business: -6,
  mobile: 2,
  nonNative: -12,
  proxy: -24,
  reputation: -18,
  manyPorts: -5,
} as const;

/* 开放端口数超过这个值才扣分 */
export const MANY_PORTS_THRESHOLD = 6;

export type ScoreConfidence = 'high' | 'medium' | 'low' | 'none';

export const SCORE_GRADES: Array<{ grade: string; min: number }> = [
  { grade: 'A+', min: 90 },
  { grade: 'A', min: 80 },
  { grade: 'B', min: 68 },
  { grade: 'C', min: 50 },
  { grade: 'D', min: 30 },
  { grade: 'F', min: 0 },
];

export type ScoreFactorKey = 'network' | 'native' | 'proxy' | 'reputation' | 'ports' | 'clamp';

export interface ScoreRuleRow {
  when: { zh: string; en: string };
  delta: number;
}

export interface ScoreRule {
  key: Exclude<ScoreFactorKey, 'clamp'>;
  label: { zh: string; en: string };
  rows: ScoreRuleRow[];
  basis: { zh: string; en: string };
  sources: Array<string | { zh: string; en: string }>;
}

export const SCORE_RULES: ScoreRule[] = [
  {
    key: 'network',
    label: { zh: '网络类型', en: 'Network type' },
    rows: [
      { when: { zh: '数据中心 / 云主机', en: 'Data center / cloud hosting' }, delta: SCORE_DELTAS.hosting },
      { when: { zh: 'CDN / 任播网络', en: 'CDN / anycast network' }, delta: SCORE_DELTAS.cdn },
      { when: { zh: '商业网络 / 企业专线', en: 'Business / commercial transit' }, delta: SCORE_DELTAS.business },
      { when: { zh: '移动网络', en: 'Mobile network' }, delta: SCORE_DELTAS.mobile },
      { when: { zh: '家庭宽带、教育网', en: 'Residential broadband, education' }, delta: 0 },
    ],
    basis: {
      zh: '综合本站 ASN 库、PeeringDB 自治系统登记类型、运营商名称关键词，以及 ipwho.is、ip-api.com、ipquery.io、proxycheck.io（及可选 ipapi.is）的多源标记交叉判定。既非机房又无家宽证据的商业或专线自治系统归为商业网络。同时满足 ASN 与登记机构均为电信宽带运营商时，标记为「双 ISP」。',
      en: 'Cross-classified from the curated ASN table, PeeringDB network type, operator keywords, and hosting / mobile flags from ipwho.is, ip-api.com, ipquery.io and proxycheck.io (plus optional ipapi.is). Registered networks that are neither hosting nor consumer broadband are classified as business networks. When both the origin ASN and the range registrant are consumer carriers, Dual ISP is shown.',
    },
    sources: [{ zh: 'JudgeIP ASN 表', en: 'JudgeIP ASN table' }, 'PeeringDB', 'ipwho.is', 'ip-api.com', 'ipquery.io', 'proxycheck.io'],
  },
  {
    key: 'native',
    label: { zh: '原生 IP', en: 'Native IP' },
    rows: [
      { when: { zh: '注册国家与定位国家不一致（广播 IP）', en: 'Registered country differs from geolocated country (geo-announced IP)' }, delta: SCORE_DELTAS.nonNative },
      { when: { zh: '两者一致，或网络类型为 CDN', en: 'Both match, or the network is a CDN' }, delta: 0 },
    ],
    basis: {
      zh: '注册国家取自 RIR WHOIS / RDAP 记录里的国家字段，定位国家取自多源地理库。两者相同记为原生 IP。',
      en: 'The registered country comes from RIR WHOIS / RDAP records; the geolocated country comes from geolocation databases. Matching values count as a native IP.',
    },
    sources: ['RIPEstat whois', 'RDAP', 'ipwho.is', 'ip-api.com', 'ipquery.io'],
  },
  {
    key: 'proxy',
    label: { zh: '代理 / VPN / Tor', en: 'Proxy / VPN / Tor' },
    rows: [
      { when: { zh: '任一来源标记为代理、VPN 或 Tor，或开放了代理特征端口', en: 'Any source flags proxy, VPN or Tor, or a typical proxy port is open' }, delta: SCORE_DELTAS.proxy },
    ],
    basis: {
      zh: '综合 ipwho.is、ip-api.com、ipquery.io、proxycheck.io（及可选 ipapi.is）的 proxy / vpn / tor 标记、Shodan 的 vpn / tor 标签、是否开放 1080、3128、8080 等代理特征端口，以及 ASN 是否属于商业 VPN 骨干网。',
      en: 'Combines proxy / vpn / tor flags from ipwho.is, ip-api.com, ipquery.io and proxycheck.io (plus optional ipapi.is), Shodan vpn / tor tags, open proxy ports such as 1080, 3128 and 8080, and commercial VPN ASNs.',
    },
    sources: ['ipwho.is', 'ip-api.com', 'ipquery.io', 'proxycheck.io', 'Shodan InternetDB'],
  },
  {
    key: 'reputation',
    label: { zh: '黑名单与威胁记录', en: 'Blocklists and threat records' },
    rows: [
      { when: { zh: '命中任一 DNSBL、高风险欺诈/滥用分，或有扫描、失陷标签与历史 CVE', en: 'Listed on any DNSBL, high abuse/risk score, or tagged as scanner/compromised/CVE' }, delta: SCORE_DELTAS.reputation },
    ],
    basis: {
      zh: '通过 DoH 查询 SpamCop、DroneBL、Barracuda、UCEPROTECT 四个黑名单，并结合 Shodan 漏洞/失陷标签与多源风险分（proxycheck / ipquery 及可选 AbuseIPDB）。多项同时命中也只扣一次。',
      en: 'Queries SpamCop, DroneBL, Barracuda and UCEPROTECT over DoH, combined with Shodan compromise/CVE records and multi-source abuse scores (proxycheck / ipquery and optional AbuseIPDB). Multiple hits deduct once.',
    },
    sources: ['SpamCop', 'DroneBL', 'Barracuda', 'UCEPROTECT', 'Shodan InternetDB', 'proxycheck.io'],
  },
  {
    key: 'ports',
    label: { zh: '开放端口数量', en: 'Open ports' },
    rows: [
      { when: { zh: `开放端口超过 ${MANY_PORTS_THRESHOLD} 个`, en: `More than ${MANY_PORTS_THRESHOLD} open ports` }, delta: SCORE_DELTAS.manyPorts },
    ],
    basis: {
      zh: '端口数据来自 Shodan InternetDB 的历史扫描结果，不是实时探测，仅支持 IPv4（IPv6 地址此项记 0 分并标注为中置信度）。',
      en: 'Port data comes from past scans in Shodan InternetDB, not a live probe, and covers IPv4 only (IPv6 addresses skip this item with medium confidence).',
    },
    sources: ['Shodan InternetDB'],
  },
];

export function clampScore(raw: number): number {
  return Math.max(SCORE_MIN, Math.min(SCORE_MAX, Math.round(raw)));
}

export function formatDelta(delta: number): string {
  return delta > 0 ? `+${delta}` : delta < 0 ? `−${Math.abs(delta)}` : '0';
}
