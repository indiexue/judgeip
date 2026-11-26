import type { D1Database } from '@cloudflare/workers-types';
import { parseIp } from './ip-utils';

export interface SiteStats {
  totalChecks: number;
  todayChecks: number;
  onlineSince: string | null;
}

interface CountableLookup {
  ip: string;
  isBogon: boolean;
  lookupStatus: string;
}

interface CounterRow {
  total: number | null;
}

export const EMPTY_STATS: SiteStats = { totalChecks: 0, todayChecks: 0, onlineSince: null };

// 上线日期：排名与统计存储启用、数据开始真实积累的第一天。只读，不在代码中改写。
export const SITE_ONLINE_SINCE = '2026-11-25';

async function resolveDatabase(database?: D1Database | null): Promise<D1Database | null | undefined> {
  if (database !== undefined) return database;
  try {
    const { env } = await import('cloudflare:workers');
    return env.RANKINGS_DB;
  } catch {
    return null;
  }
}

/**
 * 为一次成功出分的公网 IP 查询累计站点统计。
 * 计数按成功出分的查询次数（含同一 IP 的重复查询），不记录任何 IP 或访客信息；
 * 失败或未迁移时静默跳过，绝不阻断原有检测。
 */
export async function recordLookupStat(
  info: CountableLookup,
  database?: D1Database | null,
  now = Date.now(),
): Promise<void> {
  const parsed = parseIp(info.ip);
  if (!parsed || parsed.isBogon || info.isBogon || !['complete', 'partial'].includes(info.lookupStatus)) return;
  try {
    const db = await resolveDatabase(database);
    if (!db) return;
    const day = new Date(now).toISOString().slice(0, 10);
    await db.batch([
      db.prepare(`INSERT INTO stats_counters (name, value) VALUES ('total', 1)
        ON CONFLICT (name) DO UPDATE SET value = value + 1`),
      db.prepare(`INSERT INTO stats_daily (day, value) VALUES (?, 1)
        ON CONFLICT (day) DO UPDATE SET value = value + 1`).bind(day),
    ]);
  } catch {
    // 统计是附属功能，任何存储故障都不影响检测主流程。
  }
}

/**
 * 读取站点统计。存储未启用、未迁移或故障时返回 null，
 * 页面据此隐藏整个统计条，绝不展示虚构数字。
 */
export async function getSiteStats(
  database?: D1Database | null,
  now = Date.now(),
): Promise<SiteStats | null> {
  try {
    const db = await resolveDatabase(database);
    if (!db) return null;
    const day = new Date(now).toISOString().slice(0, 10);
    const rows = await db.batch<CounterRow>([
      db.prepare("SELECT value AS total FROM stats_counters WHERE name = 'total'"),
      db.prepare('SELECT value AS total FROM stats_daily WHERE day = ?').bind(day),
    ]);
    const total = rows[0].results?.[0]?.total;
    if (!Number.isInteger(total) || total! < 1) return null;
    const today = rows[1].results?.[0]?.total;
    return {
      totalChecks: total!,
      todayChecks: Number.isInteger(today) ? today! : 0,
      onlineSince: SITE_ONLINE_SINCE,
    };
  } catch {
    return null;
  }
}
