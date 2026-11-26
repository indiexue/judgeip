import type { D1Database } from '@cloudflare/workers-types';
import { parseIp } from './ip-utils';

export interface IpRankings {
  siteRanking: { rank: number; total: number } | null;
  percentileRanking: number | null;
  asRanking: { rank: number; total: number } | null;
}

interface RankedLookup {
  ip: string;
  asn: number | null;
  score: number | null;
  scoringVersion: string;
  isBogon: boolean;
  lookupStatus: string;
}

interface RankingCounts {
  scope: number;
  total: number;
  higher: number;
  lower: number;
}

export const EMPTY_RANKINGS: IpRankings = { siteRanking: null, percentileRanking: null, asRanking: null };
export const RANKING_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
// 样本太少时排名没有参考意义：样本仍在记录，但全站有效样本超过该数量前不返回任何排名。
export const RANKING_MIN_SAMPLE_TOTAL = 500;

export async function lookupRankings(
  info: RankedLookup,
  record: boolean,
  database?: D1Database | null,
  now = Date.now(),
  minTotal = RANKING_MIN_SAMPLE_TOTAL,
): Promise<IpRankings> {
  const parsed = parseIp(info.ip);
  if (!parsed || parsed.isBogon || info.isBogon || info.score === null || !Number.isInteger(info.score)
    || info.score < 0 || info.score > 100 || !['complete', 'partial'].includes(info.lookupStatus)) return { ...EMPTY_RANKINGS };

  try {
    if (database === undefined) {
      const { env } = await import('cloudflare:workers');
      database = env.RANKINGS_DB;
    }
    if (!database) return { ...EMPTY_RANKINGS };
    // 密钥保存在私有数据库中，避免能枚举 IPv4 的无盐哈希；不保存原始 IP 或访客身份。
    const setting = await database.prepare("SELECT value FROM ranking_settings WHERE name = 'hash_key'").first<{ value: string }>();
    if (!setting?.value) return { ...EMPTY_RANKINGS };
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(setting.value), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(parsed.normalized));
    const hash = Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
    const asn = Number.isInteger(info.asn) && info.asn! > 0 ? info.asn : null;
    const statements = [database.prepare('DELETE FROM ranked_ips WHERE updated_at <= ?').bind(now - RANKING_WINDOW_MS)];
    if (record) {
      statements.push(database.prepare(`INSERT INTO ranked_ips (ip_hash, asn, score, scoring_version, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (ip_hash) DO UPDATE SET asn = excluded.asn, score = excluded.score,
          scoring_version = excluded.scoring_version, updated_at = excluded.updated_at
        WHERE excluded.updated_at >= ranked_ips.updated_at`).bind(hash, asn, info.score, info.scoringVersion, now));
    }
    // D1 batch 是一个事务；计数由触发器维护，查询只读最多两组 101 个分数桶，不扫描全库。
    statements.push(database.prepare(`SELECT scope, SUM(count) AS total,
        SUM(CASE WHEN score > ? THEN count ELSE 0 END) AS higher,
        SUM(CASE WHEN score < ? THEN count ELSE 0 END) AS lower
      FROM ranking_counts WHERE scope IN (0, ?) AND scoring_version = ?
        AND EXISTS (SELECT 1 FROM ranked_ips WHERE ip_hash = ? AND score = ? AND scoring_version = ? AND asn IS ?)
      GROUP BY scope`).bind(info.score, info.score, asn, info.scoringVersion, hash, info.score, info.scoringVersion, asn));
    const results = await database.batch<RankingCounts>(statements);
    const counts = results[results.length - 1].results;
    const site = counts.find((row) => row.scope === 0);
    const network = counts.find((row) => row.scope === asn);
    if (!site || site.total < 1 || site.total <= minTotal) return { ...EMPTY_RANKINGS };
    return {
      siteRanking: { rank: site.higher + 1, total: site.total },
      // 排除当前 IP；同分不算优于，样本只有一个时不显示百分比。
      percentileRanking: site.total > 1 ? Math.round(site.lower / (site.total - 1) * 1000) / 10 : null,
      asRanking: network ? { rank: network.higher + 1, total: network.total } : null,
    };
  } catch {
    // 数据库未绑定、迁移未应用或服务故障都不阻断原有检测，更不能返回虚构排名。
    return { ...EMPTY_RANKINGS };
  }
}
