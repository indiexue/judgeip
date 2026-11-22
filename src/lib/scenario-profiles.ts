/**
 * 原生 IP、住宅 IP、TikTok IP 三个检测页（/native-ip、/residential-ip、/tiktok-ip）的打分表。
 * 每个场景只看和它有关的几项，权重加起来是 100；页面上公布的权重和实际打分用的是同一份。
 * 权重是 JudgeIP 自己定的经验值，和首页的综合评分是两套数，不是任何平台的官方规则。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';
import { MANY_PORTS_THRESHOLD } from './score-rules';

export type ScenarioId = 'native-ip' | 'residential-ip' | 'tiktok-ip';
export type ScenarioCheck = 'registry' | 'notCdn' | 'residential' | 'native' | 'noProxy' | 'clean' | 'fewPorts';
export type ScenarioStatus = 'pass' | 'partial' | 'fail' | 'unknown';
export type ScenarioLevel = 'pass' | 'warn' | 'fail' | 'unknown';

type Text = { zh: string; en: string };

export interface ScenarioItem {
  check: ScenarioCheck;
  weight: number;
}

export interface Scenario {
  id: ScenarioId;
  path: string;
  name: Text;
  items: ScenarioItem[];
}

export interface ScenarioItemResult extends ScenarioItem {
  status: ScenarioStatus;
  earned: number;
  detail: Text;
}

/* 总分低于这个数记为不符合；全部通过才记为符合 */
export const SCENARIO_FAIL_BELOW = 60;

export const SCENARIOS: Scenario[] = [
  {
    id: 'native-ip',
    path: '/native-ip',
    name: { zh: '原生 IP', en: 'Native IP' },
    items: [
      { check: 'registry', weight: 60 },
      { check: 'notCdn', weight: 25 },
      { check: 'noProxy', weight: 15 },
    ],
  },
  {
    id: 'residential-ip',
    path: '/residential-ip',
    name: { zh: '住宅 IP', en: 'Residential IP' },
    items: [
      { check: 'residential', weight: 60 },
      { check: 'noProxy', weight: 20 },
      { check: 'clean', weight: 10 },
      { check: 'fewPorts', weight: 10 },
    ],
  },
  {
    id: 'tiktok-ip',
    path: '/tiktok-ip',
    name: { zh: 'TikTok IP', en: 'TikTok IP' },
    items: [
      { check: 'residential', weight: 45 },
      { check: 'native', weight: 25 },
      { check: 'noProxy', weight: 20 },
      { check: 'clean', weight: 10 },
    ],
  },
];

export const CHECK_LABELS: Record<ScenarioCheck, Text> = {
  registry: { zh: '注册国家与定位国家一致', en: 'Registry country matches location' },
  notCdn: { zh: '不是 CDN / 任播地址', en: 'Not a CDN / anycast address' },
  residential: { zh: '住宅或移动网络', en: 'Residential or mobile network' },
  native: { zh: '原生 IP', en: 'Native IP' },
  noProxy: { zh: '无代理标记', en: 'No proxy flag' },
  clean: { zh: '无黑名单或威胁记录', en: 'No blocklist or threat records' },
  fewPorts: { zh: `开放端口不超过 ${MANY_PORTS_THRESHOLD} 个`, en: `No more than ${MANY_PORTS_THRESHOLD} open ports` },
};

export const CHECK_BASIS: Record<ScenarioCheck, Text> = {
  registry: { zh: 'RIR whois 登记的国家，对比定位库给出的国家', en: 'Country in the RIR whois record against the country from geolocation' },
  notCdn: { zh: '按 ASN 和运营商名称归类的网络类型', en: 'Network type classified from the ASN and operator name' },
  residential: { zh: '按 ASN 和运营商名称归类的网络类型', en: 'Network type classified from the ASN and operator name' },
  native: { zh: '注册国家与定位国家一致，且不是 CDN / 任播', en: 'Registry country matches location and the address is not CDN / anycast' },
  noProxy: { zh: '定位库的 proxy / vpn / tor 标记，加上 Shodan 的标签和代理端口', en: 'Proxy / VPN / Tor flags from geolocation data, plus Shodan tags and proxy ports' },
  clean: { zh: '四个 DNSBL 黑名单，加上 Shodan 的扫描、失陷标签和 CVE', en: 'Four DNSBL blocklists, plus Shodan scanner and compromise tags and CVEs' },
  fewPorts: { zh: 'Shodan InternetDB 历史扫描到的开放端口', en: 'Open ports seen in past Shodan InternetDB scans' },
};

export const STATUS_LABELS: Record<ScenarioStatus, Text> = {
  pass: { zh: '通过', en: 'Pass' },
  partial: { zh: '部分', en: 'Partial' },
  fail: { zh: '未通过', en: 'Fail' },
  unknown: { zh: '缺数据', en: 'No data' },
};

export const SCENARIO_LEVEL_LABELS: Record<ScenarioLevel, Text> = {
  pass: { zh: '符合', en: 'Meets it' },
  warn: { zh: '部分符合', en: 'Partly meets it' },
  fail: { zh: '不符合', en: 'Does not meet it' },
  unknown: { zh: '无法判断', en: 'Undetermined' },
};

type Facts = Pick<
  HomeIpLookupResult,
  'isBogon' | 'usageType' | 'isNative' | 'rirCountry' | 'countryCode' | 'isProxy' | 'hasThreat' | 'portsKnown' | 'openPorts'
>;

type Outcome = { status: ScenarioStatus; detail: Text };

const out = (status: ScenarioStatus, zh: string, en: string): Outcome => ({ status, detail: { zh, en } });

/** 单项的判定。缺数据时是 unknown，不当作通过。 */
function judgeCheck(check: ScenarioCheck, info: Facts): Outcome {
  if (check === 'registry') {
    if (!info.rirCountry || !info.countryCode) return out('unknown', '注册国家或定位国家缺失', 'Registry or location country missing');
    return info.rirCountry === info.countryCode
      ? out('pass', `注册 ${info.rirCountry}，定位 ${info.countryCode}`, `Registered ${info.rirCountry}, located ${info.countryCode}`)
      : out('fail', `注册 ${info.rirCountry}，定位 ${info.countryCode}，是广播 IP`, `Registered ${info.rirCountry}, located ${info.countryCode}: geo-announced`);
  }
  if (check === 'notCdn') {
    if (info.usageType === 'unknown') return out('unknown', '网络类型未知', 'Network type unknown');
    return info.usageType === 'cdn'
      ? out('fail', 'CDN / 任播地址，没有固定位置', 'CDN / anycast address with no fixed location')
      : out('pass', '不是 CDN / 任播', 'Not CDN / anycast');
  }
  if (check === 'residential') {
    if (info.usageType === 'unknown') return out('unknown', '网络类型未知', 'Network type unknown');
    if (info.usageType === 'residential') return out('pass', '家庭宽带', 'Residential broadband');
    if (info.usageType === 'mobile') return out('pass', '移动网络', 'Mobile network');
    if (info.usageType === 'hosting') return out('fail', '数据中心 IP', 'Data center IP');
    if (info.usageType === 'cdn') return out('fail', 'CDN / 任播 IP', 'CDN / anycast IP');
    if (info.usageType === 'reserved') return out('fail', '保留地址', 'Reserved address');
    return out('partial', '企业或教育网络，不是住宅', 'Business or education network, not residential');
  }
  if (check === 'native') {
    if (info.isNative === null) return out('unknown', '注册国家或定位国家缺失', 'Registry or location country missing');
    if (info.isNative) return out('pass', `注册 ${info.rirCountry}，定位 ${info.countryCode}`, `Registered ${info.rirCountry}, located ${info.countryCode}`);
    return info.usageType === 'cdn'
      ? out('fail', 'CDN / 任播地址，不算原生', 'CDN / anycast address, not counted as native')
      : out('fail', `注册 ${info.rirCountry}，定位 ${info.countryCode}，是广播 IP`, `Registered ${info.rirCountry}, located ${info.countryCode}: geo-announced`);
  }
  if (check === 'noProxy') {
    if (info.isProxy === null) return out('unknown', '代理标记没查到', 'Proxy flag unavailable');
    return info.isProxy
      ? out('fail', '被标记为代理 / VPN / Tor', 'Flagged as proxy / VPN / Tor')
      : out('pass', '没有代理标记', 'No proxy flag');
  }
  if (check === 'clean') {
    if (info.hasThreat === null) return out('unknown', '黑名单没查全', 'Blocklist check incomplete');
    return info.hasThreat
      ? out('fail', '命中黑名单或威胁记录', 'Blocklisted or has threat records')
      : out('pass', '没有记录', 'No records');
  }
  if (!info.portsKnown) return out('unknown', '端口数据没取到', 'Port data unavailable');
  const n = info.openPorts.length;
  return n > MANY_PORTS_THRESHOLD
    ? out('fail', `${n} 个开放端口`, `${n} open ports`)
    : out('pass', n === 0 ? '没有开放端口记录' : `${n} 个开放端口`, n === 0 ? 'No open ports on record' : `${n} open port${n === 1 ? '' : 's'}`);
}

/**
 * 按一个 IP 的查询结果给某个场景打分。通过拿满该项权重，部分拿一半，未通过不得分。
 * 有一项缺数据就不出总分，缺的数据不当作通过；缺的项全算通过也到不了及格线时，仍记为不符合。
 */
export function evaluateScenario(scenario: Scenario, info: Facts): { items: ScenarioItemResult[]; total: number | null; level: ScenarioLevel } {
  if (info.isBogon) {
    const detail = { zh: '保留地址，不是公网出口', en: 'Reserved address, not a public egress' };
    return { items: scenario.items.map((item) => ({ ...item, status: 'unknown' as const, earned: 0, detail })), total: null, level: 'unknown' };
  }

  const items = scenario.items.map((item) => {
    const { status, detail } = judgeCheck(item.check, info);
    const earned = status === 'pass' ? item.weight : status === 'partial' ? Math.round(item.weight / 2) : 0;
    return { ...item, status, earned, detail };
  });

  const total = items.reduce((n, item) => n + item.earned, 0);
  if (items.some((item) => item.status === 'unknown')) {
    const best = items.reduce((n, item) => n + (item.status === 'unknown' ? item.weight : item.earned), 0);
    return { items, total: null, level: best < SCENARIO_FAIL_BELOW ? 'fail' : 'unknown' };
  }
  const level = total < SCENARIO_FAIL_BELOW ? 'fail' : items.every((item) => item.status === 'pass') ? 'pass' : 'warn';
  return { items, total, level };
}

export function scenarioById(id: ScenarioId): Scenario {
  return SCENARIOS.find((s) => s.id === id)!;
}

/** 页面用的结果：标签和说明已经按语言取好。 */
export function scoreScenario(id: ScenarioId, info: Facts, lang: Lang) {
  const scenario = scenarioById(id);
  const result = evaluateScenario(scenario, info);
  return {
    total: result.total,
    level: result.level,
    label: SCENARIO_LEVEL_LABELS[result.level][lang],
    items: result.items.map((item) => ({
      check: item.check,
      weight: item.weight,
      earned: item.earned,
      status: item.status,
      label: CHECK_LABELS[item.check][lang],
      basis: CHECK_BASIS[item.check][lang],
      statusLabel: STATUS_LABELS[item.status][lang],
      detail: item.detail[lang],
    })),
  };
}
