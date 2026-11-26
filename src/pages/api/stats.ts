import type { APIRoute } from 'astro';
import { getSiteStats } from '../../lib/site-stats';

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' };

/**
 * 站点统计：累计检测数、今日检测数（UTC）与上线日期。
 * 数据来自私有 D1 计数器；存储不可用或未积累时返回 404，前端据此隐藏统计条。
 * 短缓存 60s，避免每次页面打开都打到数据库。
 */
export const GET: APIRoute = async () => {
  const stats = await getSiteStats();
  if (!stats) {
    return new Response(JSON.stringify({ ok: false, error: 'stats_unavailable' }), { status: 404, headers: JSON_TYPE });
  }
  return new Response(JSON.stringify({ ok: true, ...stats }), {
    status: 200,
    headers: { ...JSON_TYPE, 'Cache-Control': 'public, max-age=60' },
  });
};
