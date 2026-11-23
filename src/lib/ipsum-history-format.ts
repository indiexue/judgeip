/*
 * IPsum 近 30 天历史：每天由 GitHub Actions 把当天被 ≥2 个名单收录的 IPv4 合并进 data/ipsum-history.tsv，
 * 构建时再编译成定长二进制索引供 Worker 二分查找。只收 ≥2 个名单的地址：单名单命中占当天七成以上、信号最弱，
 * 当天的单名单命中仍由 ipsum.bin 判断。
 * 本文件不 import 其他模块，供 node --experimental-strip-types 直接运行的脚本使用。
 */
export const HISTORY_DAYS = 30;
export const HISTORY_MIN_LISTS = 2;
const DAY_MS = 24 * 3600 * 1000;

export interface HistoryEntry { firstSeen: string; lastSeen: string; maxLists: number }
export interface History { updatedAt: string; entries: Map<string, HistoryEntry> }

const HEADER = 'ip\tfirst_seen\tlast_seen\tmax_lists';
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((n, octet) => n * 256 + Number(octet), 0);
}

export function parseHistoryTsv(text: string): History | null {
  const stamp = text.match(/^# updated: (\S+)$/m)?.[1];
  if (!stamp || !Number.isFinite(Date.parse(stamp))) return null;
  const entries = new Map<string, HistoryEntry>();
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#') || line === HEADER) continue;
    const [ip, firstSeen, lastSeen, lists] = line.split('\t');
    const max = Number(lists);
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip || '') || !DATE_RE.test(firstSeen || '') || !DATE_RE.test(lastSeen || '')
      || !Number.isInteger(max) || max < 1 || max > 255) return null;
    entries.set(ip, { firstSeen, lastSeen, maxLists: max });
  }
  return { updatedAt: new Date(stamp).toISOString(), entries };
}

/* 把当天的 IPsum 合并进历史，并丢掉最后出现早于 HISTORY_DAYS 天的地址 */
export function mergeHistory(previous: History | null, feed: { entries: Map<string, number>; updatedAt: string }): History {
  const day = feed.updatedAt.slice(0, 10);
  const cutoff = new Date(Date.parse(day) - (HISTORY_DAYS - 1) * DAY_MS).toISOString().slice(0, 10);
  const entries = new Map<string, HistoryEntry>();
  for (const [ip, entry] of previous?.entries || []) if (entry.lastSeen >= cutoff) entries.set(ip, { ...entry });
  for (const [ip, lists] of feed.entries) {
    if (lists < HISTORY_MIN_LISTS) continue;
    const old = entries.get(ip);
    entries.set(ip, old
      ? { firstSeen: old.firstSeen < day ? old.firstSeen : day, lastSeen: old.lastSeen > day ? old.lastSeen : day, maxLists: Math.max(old.maxLists, lists) }
      : { firstSeen: day, lastSeen: day, maxLists: lists });
  }
  return { updatedAt: feed.updatedAt, entries };
}

export function serializeHistoryTsv(history: History): string {
  const rows = [...history.entries].sort((a, b) => ipv4ToInt(a[0]) - ipv4ToInt(b[0]));
  return [
    `# JudgeIP: IPv4 addresses listed by at least ${HISTORY_MIN_LISTS} IPsum lists in the last ${HISTORY_DAYS} days.`,
    '# Source: https://github.com/stamparm/ipsum (Unlicense). Updated daily by .github/workflows/ipsum-history.yml.',
    `# updated: ${history.updatedAt}`,
    HEADER,
    ...rows.map(([ip, e]) => `${ip}\t${e.firstSeen}\t${e.lastSeen}\t${e.maxLists}`),
    '',
  ].join('\n');
}

/* 二进制索引：'IPSH' + 更新时间(float64) + 条数(uint32)，之后每条 7 字节：IPv4(uint32) + 最后出现日(距 1970-01-01 的天数, uint16) + 最多名单数(uint8) */
export function compileHistoryIndex(history: History): Uint8Array {
  const rows = [...history.entries].map(([ip, e]) => ({ ip: ipv4ToInt(ip), day: Math.floor(Date.parse(e.lastSeen) / DAY_MS), lists: e.maxLists }))
    .sort((a, b) => a.ip - b.ip);
  const out = new Uint8Array(16 + rows.length * 7);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0x49505348);
  view.setFloat64(4, Date.parse(history.updatedAt));
  view.setUint32(12, rows.length);
  rows.forEach((row, i) => {
    view.setUint32(16 + i * 7, row.ip);
    view.setUint16(20 + i * 7, row.day);
    view.setUint8(22 + i * 7, row.lists);
  });
  return out;
}
