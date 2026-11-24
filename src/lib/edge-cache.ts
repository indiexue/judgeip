/**
 * 按 IP 缓存按次计费或限额的上游结果（proxycheck、ipapi.is、IP2Location.io、AbuseIPDB），存在 Cloudflare 的 Cache API 里。
 * 同一机房内同一个 IP 在缓存期内再查不调上游、不耗额度。只缓存成功的结果；没有 Cache API（本地测试、Node）时直接查上游。
 */
export const UPSTREAM_CACHE_TTL_SECONDS = 6 * 3600;

/* 缓存键只用来定位条目，不会真的发出请求；必须是本站域名下的 https 地址 */
const keyUrl = (source: string, ip: string) => `https://judgeip.com/__upstream-cache/${source}/${encodeURIComponent(ip)}`;

export interface CachedResult<T> {
  value: T | null;
  /* 这次是否命中缓存，命中时没有调用上游 */
  hit: boolean;
}

export async function cachedUpstream<T>(
  source: string,
  ip: string,
  fetcher: () => Promise<T | null>,
): Promise<CachedResult<T>> {
  let cache: Cache | undefined;
  const key = keyUrl(source, ip);
  try {
    // 独立命名空间，不让普通站点请求读到原始上游响应。
    cache = await globalThis.caches?.open('judgeip-upstreams-v1');
    const res = await cache?.match(key);
    if (res) return { value: (await res.json()) as T, hit: true };
  } catch {
    /* 缓存不可用时直接查上游 */
  }
  const value = await fetcher();
  if (cache && value !== null && value !== undefined) {
    try {
      await cache.put(key, new Response(JSON.stringify(value), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': `public, max-age=${UPSTREAM_CACHE_TTL_SECONDS}` },
      }));
    } catch {
      /* 写失败不影响本次结果 */
    }
  }
  return { value, hit: false };
}
