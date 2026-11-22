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
  mobile: 2,
  nonNative: -12,
  proxy: -24,
  reputation: -18,
  manyPorts: -5,
} as const;

/* 开放端口数超过这个值才扣分 */
export const MANY_PORTS_THRESHOLD = 6;

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
  sources: string[];
}

export const SCORE_RULES: ScoreRule[] = [
  {
    key: 'network',
    label: { zh: '网络类型', en: 'Network type' },
    rows: [
      { when: { zh: '数据中心 / 云主机', en: 'Data center / cloud hosting' }, delta: SCORE_DELTAS.hosting },
      { when: { zh: 'CDN / 任播网络', en: 'CDN / anycast network' }, delta: SCORE_DELTAS.cdn },
      { when: { zh: '移动网络', en: 'Mobile network' }, delta: SCORE_DELTAS.mobile },
      { when: { zh: '家庭宽带、教育网、企业专线', en: 'Residential, education, business' }, delta: 0 },
    ],
    basis: {
      zh: '先查本站维护的 ASN 表，再看运营商名称里的关键词，最后参考 ipwho.is 与 ip-api.com 的 hosting / mobile 标记。只有 ASN 表或运营商名称能佐证时才认定为家庭宽带，否则记为未知、不出分。',
      en: 'The ASN is looked up in a table maintained by this site, then the operator name is matched against keywords, then the hosting / mobile flags from ipwho.is and ip-api.com are used. An IP only counts as residential when the ASN table or the operator name supports it; otherwise the type is unknown and no score is given.',
    },
    sources: ['ipwho.is', 'ip-api.com', 'Cloudflare request.cf'],
  },
  {
    key: 'native',
    label: { zh: '原生 IP', en: 'Native IP' },
    rows: [
      { when: { zh: '注册国家与定位国家不一致（广播 IP）', en: 'Registered country differs from geolocated country (geo-announced IP)' }, delta: SCORE_DELTAS.nonNative },
      { when: { zh: '两者一致，或网络类型为 CDN', en: 'Both match, or the network is a CDN' }, delta: 0 },
    ],
    basis: {
      zh: '注册国家取自 RIR WHOIS 记录里的 country 字段，定位国家取自地理库。两者相同记为原生 IP。',
      en: 'The registered country is the country field of the RIR WHOIS record; the geolocated country comes from the geolocation database. Matching values count as a native IP.',
    },
    sources: ['RIPEstat whois', 'ipwho.is', 'ip-api.com'],
  },
  {
    key: 'proxy',
    label: { zh: '代理 / VPN / Tor', en: 'Proxy / VPN / Tor' },
    rows: [
      { when: { zh: '任一来源标记为代理、VPN 或 Tor，或开放了代理特征端口', en: 'Any source flags proxy, VPN or Tor, or a typical proxy port is open' }, delta: SCORE_DELTAS.proxy },
    ],
    basis: {
      zh: '看 ipwho.is 的 proxy / vpn / tor 标记、ip-api.com 的 proxy 标记、Shodan 的 vpn / tor 标签、是否开放 1080、3128、8080 等代理特征端口，以及 ASN 是否属于已知的商业 VPN 网络。',
      en: 'Uses the proxy / vpn / tor flags from ipwho.is, the proxy flag from ip-api.com, vpn / tor tags from Shodan, open proxy ports such as 1080, 3128 and 8080, and whether the ASN is a known commercial VPN network.',
    },
    sources: ['ipwho.is', 'ip-api.com', 'Shodan InternetDB'],
  },
  {
    key: 'reputation',
    label: { zh: '黑名单与威胁记录', en: 'Blocklists and threat records' },
    rows: [
      { when: { zh: '命中任一 DNSBL，或有扫描、失陷标签，或有历史 CVE', en: 'Listed on any DNSBL, tagged as scanner or compromised, or has past CVEs' }, delta: SCORE_DELTAS.reputation },
    ],
    basis: {
      zh: '通过 DoH 逐个查询 SpamCop、DroneBL、Barracuda、UCEPROTECT；只有权威服务器明确答复才算「未列入」，超时或被拒绝记为未知。同时读取 Shodan 的标签与漏洞列表。多项同时命中也只扣一次。',
      en: 'SpamCop, DroneBL, Barracuda and UCEPROTECT are each queried over DoH; only an authoritative answer counts as "not listed", a timeout or refusal is unknown. Shodan tags and CVE lists are read as well. Several hits still deduct only once.',
    },
    sources: ['SpamCop', 'DroneBL', 'Barracuda', 'UCEPROTECT', 'Shodan InternetDB'],
  },
  {
    key: 'ports',
    label: { zh: '开放端口数量', en: 'Open ports' },
    rows: [
      { when: { zh: `开放端口超过 ${MANY_PORTS_THRESHOLD} 个`, en: `More than ${MANY_PORTS_THRESHOLD} open ports` }, delta: SCORE_DELTAS.manyPorts },
    ],
    basis: {
      zh: '端口数据来自 Shodan InternetDB 的历史扫描结果，不是实时探测，仅支持 IPv4。',
      en: 'Port data comes from past scans in Shodan InternetDB, not a live probe, and covers IPv4 only.',
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
