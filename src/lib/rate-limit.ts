/**
 * 免密钥接口的限流：固定窗口计数，存在当前边缘节点的内存里。
 * 各节点各自计数，节点重启后清零，所以这是防止单个来源刷接口的软限制，不是精确配额。
 */
import { ipv6Groups } from './ip-utils';

/* 每个来源每分钟的请求数，API 文档页也从这里取数。
 * lookup 是跨路由共享的预算：页面、API、MCP、命令行里每次未命中缓存、真正向上游发起的全量查询都计入这里 */
export const RATE_LIMITS = {
  report: 30,
  api: 120,
  mcp: 30,
  lookup: 20,
} as const;

export type RateScope = keyof typeof RATE_LIMITS;

export interface RateResult {
  ok: boolean;
  limit: number;
  remaining: number;
  /* 距离窗口重置的秒数 */
  resetIn: number;
}

const WINDOW_MS = 60 * 1000;
const MAX_BUCKETS = 5000;
const buckets = new Map<string, { count: number; resetAt: number }>();

/* IPv6 按 /64 计，同一个用户换后 64 位不能绕过限流 */
export function rateKey(ip: string): string {
  if (!ip.includes(':')) return ip;
  const groups = ipv6Groups(ip);
  return groups ? `${groups.slice(0, 4).map((g) => g.toString(16)).join(':')}::/64` : ip;
}

export function rateLimit(scope: RateScope, ip: string, now = Date.now()): RateResult {
  const limit = RATE_LIMITS[scope];
  const key = `${scope}|${rateKey(ip)}`;
  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (buckets.size >= MAX_BUCKETS) {
      for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
      if (buckets.size >= MAX_BUCKETS) buckets.clear();
    }
    bucket = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, bucket);
  }
  bucket.count += 1;
  return {
    ok: bucket.count <= limit,
    limit,
    remaining: Math.max(0, limit - bucket.count),
    resetIn: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
  };
}

export function rateHeaders(rate: RateResult): Record<string, string> {
  const headers: Record<string, string> = {
    'RateLimit-Limit': String(rate.limit),
    'RateLimit-Remaining': String(rate.remaining),
    'RateLimit-Reset': String(rate.resetIn),
  };
  if (!rate.ok) headers['Retry-After'] = String(rate.resetIn);
  return headers;
}

/* lookup 预算用完时 JSON 接口的统一应答：429，带 Retry-After，不返回只有基础信息的结果，避免被当成完整判定 */
export function lookupLimitedResponse(retryAfter = 60, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ ok: false, error: 'rate_limited', retryAfter }), {
    status: 429,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Retry-After': String(retryAfter) },
  });
}
