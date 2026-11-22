/**
 * 「默认查访客自己的 IP，带 ?ip= 时查指定 IP」的页面共用这段解析。
 */
import type { Lang } from './i18n';
import { extractVisitorIp, parseIp } from './ip-utils';

export interface QueryTarget {
  visitorIp: string;
  targetIp: string;
  /* 查的是访客自己的 IP */
  isSelf: boolean;
  /* 回填到输入框里的值 */
  queryValue: string;
  errorMsg: string;
  cfMeta: Record<string, unknown> | null;
}

export function resolveQueryTarget(request: Request, url: URL, lang: Lang): QueryTarget {
  const visitorIp = extractVisitorIp(request);
  const cfMeta = (request as Request & { cf?: Record<string, unknown> }).cf || null;
  const rawQuery = (url.searchParams.get('ip') || '').trim();
  const parsed = rawQuery ? parseIp(rawQuery) : null;

  let errorMsg = '';
  if (rawQuery && !parsed) {
    const shown = rawQuery.slice(0, 60);
    errorMsg =
      lang === 'en'
        ? `"${shown}" is not a valid IPv4 or IPv6 address. Showing your own IP instead.`
        : `「${shown}」不是有效的 IPv4 或 IPv6 地址，已显示你的本机 IP。`;
  }

  const targetIp = parsed ? parsed.normalized : visitorIp;
  return {
    visitorIp,
    targetIp,
    isSelf: targetIp === visitorIp,
    queryValue: parsed ? parsed.normalized : rawQuery,
    errorMsg,
    cfMeta,
  };
}
