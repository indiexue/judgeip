/**
 * `curl judgeip.com/<ip>` 返回的纯文本报告。传入的 info 已经按语言换好了标签，
 * 这里只负责排版；分数、等级和各项加减分都直接取自查询结果，不另算一遍。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';
import { SCORE_MAX, formatDelta } from './score-rules';

const SITE = 'https://judgeip.com';

/* 汉字和全角符号在终端里占两列，按显示宽度补空格才能对齐 */
const WIDE = /[ᄀ-ᅟ⺀-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦]/;

function width(text: string): number {
  let n = 0;
  for (const ch of text) n += WIDE.test(ch) ? 2 : 1;
  return n;
}

function pad(text: string, cols: number): string {
  return text + ' '.repeat(Math.max(1, cols - width(text)));
}

function padStart(text: string, cols: number): string {
  return ' '.repeat(Math.max(0, cols - width(text))) + text;
}

const known = (value: string) => Boolean(value) && value !== '—' && value !== '未知' && value !== 'Unknown';

export type Tr = (zh: string, enText: string) => string;

export function scoreText(info: HomeIpLookupResult, t: Tr): string {
  if (info.score !== null) {
    const conf = info.scoreConfidence === 'medium'
      ? t(' · 置信度中', ' · medium confidence')
      : info.scoreConfidence === 'low'
        ? t(' · 置信度低', ' · low confidence')
        : '';
    return `${info.score} / ${SCORE_MAX} · ${info.grade}${conf}`;
  }
  return t('未出分（基础归属或风险数据源未返回）', 'No score (core network or risk sources did not respond)');
}

export function operatorText(info: HomeIpLookupResult, t: Tr): string {
  return [known(info.isp) ? info.isp : '', info.asn ? `(${info.asnCode})` : ''].filter(Boolean).join(' ') || t('未知', 'Unknown');
}

export function locationText(info: HomeIpLookupResult, t: Tr): string {
  return (
    [info.countryCode ? `${info.countryZh} (${info.countryCode})` : '', known(info.region) ? info.region : '', known(info.city) ? info.city : ''].filter(Boolean).join(' · ') ||
    t('未知', 'Unknown')
  );
}

export function nativeText(info: HomeIpLookupResult, t: Tr): string {
  if (info.isNative === null) return t('未知', 'Unknown');
  return info.isNative
    ? t(`是（注册地 ${info.rirCountry}，定位 ${info.countryCode}）`, `Yes (registered ${info.rirCountry}, located ${info.countryCode})`)
    : t(`否（注册地 ${info.rirCountry}，定位 ${info.countryCode}）`, `No (registered ${info.rirCountry}, located ${info.countryCode})`);
}

export function portsText(info: HomeIpLookupResult, t: Tr): string {
  if (info.openPorts.length > 0) return info.openPorts.join(', ');
  if (info.version !== 4) return t('仅支持 IPv4', 'IPv4 only');
  return info.portsKnown ? t('已查来源未见开放端口', 'None in checked source') : t('未取得', 'Unavailable');
}

export function blocklistText(info: HomeIpLookupResult, t: Tr, sep: string): string {
  if (info.version !== 4) return t('仅支持 IPv4', 'IPv4 only');
  if (info.dnsblListed.length > 0) return t(`命中 ${info.dnsblListed.join(sep)}`, `Listed on ${info.dnsblListed.join(sep)}`);
  const answered = info.dnsblChecks.filter((c) => c.status !== 'unknown').length;
  return answered === info.dnsblTotal
    ? t(`${info.dnsblTotal} 个均未列入`, `Not listed on any of ${info.dnsblTotal}`)
    : t(`${answered}/${info.dnsblTotal} 个有答复，均未列入`, `${answered}/${info.dnsblTotal} answered, none listed`);
}

export function renderTextReport(info: HomeIpLookupResult, lang: Lang): string {
  const en = lang === 'en';
  const t = (zh: string, enText: string) => (en ? enText : zh);
  const sep = en ? ', ' : '、';
  const rows: Array<[string, string]> = [];
  const add = (label: string, value: string) => rows.push([label, value]);

  if (info.isBogon) {
    add(t('类型', 'Type'), info.ipTypeLabel);
    add(t('说明', 'Note'), info.bogonReason || info.org);
  } else {
    add(t('评分', 'Score'), scoreText(info, t));
    add(t('网络类型', 'Network type'), info.isDualIsp ? `${info.ipTypeLabel} · ${t('双 ISP', 'Dual ISP')}` : info.ipTypeLabel);
    add(t('运营商', 'Operator'), operatorText(info, t));
    add(t('位置', 'Location'), locationText(info, t));
    if (known(info.timezone)) add(t('时区', 'Time zone'), info.timezone);
    add(t('原生 IP', 'Native IP'), nativeText(info, t));
    add(t('代理', 'Proxy'), info.proxyLabel);
    add(t('威胁记录', 'Threats'), info.threatLabel);
    if (known(info.bgpPrefix)) add(t('路由', 'Route'), `${info.bgpPrefix} · ${info.rpkiLabel}`);
    if (known(info.ptrRecord)) add('PTR', info.ptrRecord);
    add(t('开放端口', 'Open ports'), portsText(info, t));
    add(t('黑名单', 'Blocklists'), blocklistText(info, t, sep));
  }

  const labelCols = Math.max(...rows.map(([label]) => width(label))) + 2;
  const lines = [`JudgeIP · ${info.ip}`, '', ...rows.map(([label, value]) => pad(label, labelCols) + value)];

  if (!info.isBogon && info.factors.length > 0) {
    const nameCols = Math.max(width(t('基础分', 'Base score')), width(t('最终得分', 'Final score')), ...info.factors.map((f) => width(f.label))) + 2;
    const statusCols = Math.max(0, ...info.factors.map((f) => width(f.status))) + 2;
    const line = (name: string, status: string, value: string) => `  ${pad(name, nameCols)}${pad(status, statusCols)}${padStart(value, 4)}`;
    lines.push('', t('评分明细', 'Score breakdown'), line(t('基础分', 'Base score'), '', String(info.scoreBase)));
    for (const f of info.factors) lines.push(line(f.label, f.status, formatDelta(f.delta)));
    lines.push(line(t('最终得分', 'Final score'), info.score === null ? t('未出分', 'No score') : info.grade, info.score === null ? '—' : String(info.score)));
  }

  const prefix = en ? '/en' : '';
  const links: Array<[string, string]> = [[t('完整报告', 'Full report'), `${SITE}${prefix}/ip/${info.ip}`]];
  if (!info.isBogon) links.push([t('评分规则', 'Scoring rules'), `${SITE}${prefix}/scoring`]);
  const linkCols = Math.max(...links.map(([label]) => width(label))) + 2;
  lines.push('', ...links.map(([label, link]) => pad(label, linkCols) + link));

  return `${lines.join('\n')}\n`;
}

/* 多个 IP 的并排摘要，每个 IP 一段，顺序与传入一致；MCP 的 compare_ips 用 */
export function renderCompareText(infos: HomeIpLookupResult[], lang: Lang): string {
  const en = lang === 'en';
  const t: Tr = (zh, enText) => (en ? enText : zh);
  const sep = en ? ', ' : '、';
  const colon = en ? ': ' : '：';
  const blocks = infos.map((info) => {
    if (info.isBogon) return `${info.ip}\n  ${info.ipTypeLabel} · ${info.bogonReason || info.org}`;
    const changed = info.factors.filter((f) => f.delta !== 0);
    return [
      info.ip,
      `  ${t('评分', 'Score')}${colon}${scoreText(info, t)}`,
      `  ${t('网络', 'Network')}${colon}${[info.ipTypeLabel, operatorText(info, t), info.countryCode].filter(Boolean).join(' · ')}`,
      `  ${t('原生 IP', 'Native IP')}${colon}${nativeText(info, t)}`,
      `  ${t('代理', 'Proxy')}${colon}${info.proxyLabel}`,
      `  ${t('威胁记录', 'Threats')}${colon}${info.threatLabel}`,
      `  ${t('开放端口', 'Open ports')}${colon}${portsText(info, t)}`,
      `  ${t('黑名单', 'Blocklists')}${colon}${blocklistText(info, t, sep)}`,
      `  ${t('加减分', 'Adjustments')}${colon}${changed.length > 0 ? changed.map((f) => `${f.label} ${formatDelta(f.delta)}`).join(sep) : t('无', 'none')}`,
    ].join('\n');
  });
  return `${blocks.join('\n\n')}\n`;
}
