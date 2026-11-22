/**
 * 多 IP 并排对比（/compare）。页面按 ?ips= 的顺序排出表头，浏览器再逐个 IP 请求 /api/compare
 * 取一列的内容：一次查询要十来个上游请求，几个 IP 放在同一个请求里会超出 Workers 的子请求上限。
 * 每一格的文字在这里拼好，脚本只负责填表。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';
import { parseIp } from './ip-utils';
import { MANY_PORTS_THRESHOLD, SCORE_MAX, formatDelta, type ScoreFactorKey } from './score-rules';
import { blocklistText, portsText, scoreText, type Tr } from './text-report';

/* 一次最多并排几个 IP */
export const COMPARE_MAX = 6;

export interface CompareList {
  /* 规范化、去重后的地址，保持输入顺序 */
  ips: string[];
  /* 认不出来的片段，原样返回给页面提示 */
  invalid: string[];
  /* 超过上限被丢掉的有效地址数 */
  dropped: number;
}

export function parseCompareList(raw: string | null | undefined): CompareList {
  const tokens = (raw || '').slice(0, 600).split(/[\s,;，；、]+/).filter(Boolean);
  const ips: string[] = [];
  const invalid: string[] = [];
  let dropped = 0;
  for (const token of tokens) {
    const parsed = parseIp(token);
    if (!parsed) {
      if (invalid.length < COMPARE_MAX) invalid.push(token.slice(0, 60));
      continue;
    }
    if (ips.includes(parsed.normalized)) continue;
    if (ips.length >= COMPARE_MAX) {
      dropped++;
      continue;
    }
    ips.push(parsed.normalized);
  }
  return { ips, invalid, dropped };
}

export type CompareField = 'score' | 'type' | 'native' | 'proxy' | 'threat' | 'location' | 'operator' | 'registry' | 'blocklists' | 'ports';

/* 表格的行，顺序即页面上的顺序 */
export const COMPARE_FIELDS: Array<{ field: CompareField; label: { zh: string; en: string } }> = [
  { field: 'score', label: { zh: '综合评分', en: 'Overall score' } },
  { field: 'type', label: { zh: '网络类型', en: 'Network type' } },
  { field: 'native', label: { zh: '原生 IP', en: 'Native IP' } },
  { field: 'proxy', label: { zh: '代理', en: 'Proxy' } },
  { field: 'threat', label: { zh: '威胁记录', en: 'Threats' } },
  { field: 'blocklists', label: { zh: '黑名单', en: 'Blocklists' } },
  { field: 'ports', label: { zh: '开放端口', en: 'Open ports' } },
  { field: 'location', label: { zh: '位置', en: 'Location' } },
  { field: 'operator', label: { zh: '运营商', en: 'Operator' } },
  { field: 'registry', label: { zh: '注册机构', en: 'Registry' } },
];

export type CompareTone = 'ok' | 'warn' | 'leak' | 'muted';

export interface CompareCell {
  text: string;
  /* 有 tone 时 text 显示成对应颜色的标签 */
  tone?: CompareTone;
  sub?: string;
}

export interface CompareFactor {
  key: ScoreFactorKey;
  label: string;
  status: string;
  delta: number;
  deltaText: string;
}

export interface CompareColumn {
  ip: string;
  score: number | null;
  grade: string;
  scoreTone: CompareTone;
  cells: Record<CompareField, CompareCell>;
  base: number;
  factors: CompareFactor[];
}

const TYPE_TONE: Record<HomeIpLookupResult['ipTypeTone'], CompareTone> = { green: 'ok', amber: 'warn', danger: 'leak', gray: 'muted' };
const SCORE_TONE: Record<HomeIpLookupResult['scoreTone'], CompareTone> = { good: 'ok', warn: 'warn', bad: 'leak', muted: 'muted' };
const flagTone = (flag: boolean | null): CompareTone => (flag === null ? 'muted' : flag ? 'leak' : 'ok');
const known = (value: string) => Boolean(value) && value !== '—' && value !== '未知' && value !== 'Unknown';

/* 一个 IP 在对比表里的一列。info 已经按语言换好了标签。 */
export function compareColumn(info: HomeIpLookupResult, lang: Lang): CompareColumn {
  const en = lang === 'en';
  const t: Tr = (zh, enText) => (en ? enText : zh);
  const none: CompareCell = { text: '—' };

  if (info.isBogon) {
    return {
      ip: info.ip,
      score: null,
      grade: '',
      scoreTone: 'muted',
      cells: {
        score: { text: '—', sub: t('保留地址不评分', 'Reserved addresses are not scored') },
        type: { text: info.ipTypeLabel, tone: 'muted', sub: info.bogonReason || undefined },
        native: none, proxy: none, threat: none, blocklists: none, ports: none, location: none, operator: none, registry: none,
      },
      base: info.scoreBase,
      factors: [],
    };
  }

  const place = [info.region, info.city].filter(known).join(' · ');
  const cells: Record<CompareField, CompareCell> = {
    score:
      info.score !== null
        ? {
            text: `${info.score} / ${SCORE_MAX}`,
            tone: SCORE_TONE[info.scoreTone],
            sub: info.scoreConfidence === 'high'
              ? t(`等级 ${info.grade}`, `Grade ${info.grade}`)
              : t(`等级 ${info.grade} · 置信度${info.scoreConfidence === 'medium' ? '中' : '低'}`, `Grade ${info.grade} · ${info.scoreConfidence} conf.`),
          }
        : { text: '—', sub: scoreText(info, t) },
    type: {
      text: info.ipTypeLabel,
      tone: TYPE_TONE[info.ipTypeTone],
      ...(info.isDualIsp ? { sub: t('双 ISP', 'Dual ISP') } : {}),
    },
    native:
      info.isNative === null
        ? { text: t('未知', 'Unknown'), tone: 'muted' }
        : {
            text: info.isNative ? t('是', 'Yes') : t('否', 'No'),
            tone: info.isNative ? 'ok' : 'warn',
            sub: t(`注册 ${info.rirCountry} · 定位 ${info.countryCode}`, `Registered ${info.rirCountry} · located ${info.countryCode}`),
          },
    proxy: { text: info.proxyLabel, tone: flagTone(info.isProxy) },
    threat: { text: info.threatLabel, tone: flagTone(info.hasThreat) },
    blocklists: { text: blocklistText(info, t, en ? ', ' : '、'), ...(info.dnsblListed.length > 0 ? { tone: 'leak' as const } : {}) },
    ports:
      info.openPorts.length > 0
        ? {
            text: t(`${info.openPorts.length} 个`, String(info.openPorts.length)),
            ...(info.openPorts.length > MANY_PORTS_THRESHOLD ? { tone: 'warn' as const } : {}),
            sub: info.openPorts.join(', '),
          }
        : { text: portsText(info, t) },
    location: info.countryCode ? { text: `${info.countryZh} (${info.countryCode})`, sub: place || undefined } : { text: t('未知', 'Unknown') },
    operator: { text: known(info.isp) ? info.isp : t('未知', 'Unknown'), sub: info.asn ? info.asnCode : undefined },
    registry: {
      text: known(info.rirName) ? info.rirName : t('未知', 'Unknown'),
      sub: info.rirCountry ? t(`注册国家 ${info.rirCountry}`, `Registered in ${info.rirCountry}`) : undefined,
    },
  };

  return {
    ip: info.ip,
    score: info.score,
    grade: info.grade,
    scoreTone: SCORE_TONE[info.scoreTone],
    cells,
    base: info.scoreBase,
    factors: info.factors.map((f) => ({ key: f.key, label: f.label, status: f.status, delta: f.delta, deltaText: formatDelta(f.delta) })),
  };
}
