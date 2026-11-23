import { defineMiddleware } from 'astro:middleware';
import { extractVisitorIp, parseIp } from './lib/ip-utils';
import { localePath, splitLocale } from './lib/i18n';
import { lookupIpFull } from './lib/ipcx-lookup';
import { localizeLookup } from './lib/lookup-en';
import { rateHeaders, rateLimit } from './lib/rate-limit';
import { renderTextReport } from './lib/text-report';

const CLI_UA_REGEX = /^(curl|wget|httpie|xh|fetch|libcurl)\b/i;
/* 只有一段、且只含 IP 地址字符的路径才交给 parseIp 判断，其余路径不受影响 */
const IP_PATH_REGEX = /^\/[0-9a-fA-F:.]+$/;

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

const TEXT_HEADERS = {
  'Content-Type': 'text/plain; charset=utf-8',
  'Cache-Control': 'no-store',
  'Access-Control-Allow-Origin': '*',
  ...SECURITY_HEADERS,
};

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(k)) headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Allows `curl judgeip.com` to immediately return the plain-text visitor IP (`1.2.3.4\n`)
 * without loading full HTML, while normal browsers render the web interface.
 * `curl judgeip.com/<ip>` returns a plain-text report for that IP.
 */
export const onRequest = defineMiddleware(async (context, next) => {
  const { request, url } = context;

  /* 统一将 www.judgeip.com 301 规范化重定向到主域名 judgeip.com */
  if (url.hostname === 'www.judgeip.com') {
    const canonical = new URL(url.toString());
    canonical.hostname = 'judgeip.com';
    return new Response(null, {
      status: 301,
      headers: { Location: canonical.toString(), ...SECURITY_HEADERS },
    });
  }

  const isRead = request.method === 'GET' || request.method === 'HEAD';
  const isHead = request.method === 'HEAD';
  const isCli =
    isRead && CLI_UA_REGEX.test(request.headers.get('user-agent') || '') && !(request.headers.get('accept') || '').includes('text/html');

  if (url.pathname === '/' && isCli) {
    return new Response(isHead ? null : `${extractVisitorIp(request)}\n`, { status: 200, headers: TEXT_HEADERS });
  }

  /* /en 与 /en/xxx 改写到同一个页面，语言经 locals 传给页面；中文页不带前缀 */
  const { lang, path } = splitLocale(url.pathname);

  /* /8.8.8.8 与 /en/8.8.8.8：命令行拿到纯文本报告，浏览器跳到完整报告页 */
  if (isRead && IP_PATH_REGEX.test(path)) {
    const parsed = parseIp(path.slice(1));
    if (parsed) {
      if (!isCli) return withSecurityHeaders(context.redirect(localePath(`/ip/${parsed.normalized}`, lang), 302));
      if (isHead) return new Response(null, { status: 200, headers: TEXT_HEADERS });
      const outLang = url.searchParams.get('lang') === 'en' ? 'en' : lang;
      const rate = rateLimit('report', extractVisitorIp(request));
      if (!rate.ok) {
        const wait = outLang === 'en' ? `Too many requests. Try again in ${rate.resetIn}s.` : `请求过于频繁，请在 ${rate.resetIn} 秒后重试。`;
        return new Response(`${wait}\n`, { status: 429, headers: { ...TEXT_HEADERS, ...rateHeaders(rate) } });
      }
      try {
        const info = localizeLookup(await lookupIpFull(parsed.normalized, null, false, null, { visitorIp: extractVisitorIp(request) }), outLang);
        if (info.lookupStatus === 'limited') {
          const retry = info.retryAfter || 60;
          const wait = outLang === 'en' ? `Too many lookups. Try again in ${retry}s.` : `查询过于频繁，请在 ${retry} 秒后重试。`;
          return new Response(`${wait}\n`, { status: 429, headers: { ...TEXT_HEADERS, 'Retry-After': String(retry) } });
        }
        return new Response(renderTextReport(info, outLang), { status: 200, headers: { ...TEXT_HEADERS, ...rateHeaders(rate) } });
      } catch {
        return new Response(outLang === 'en' ? 'Lookup failed. Try again later.\n' : '查询失败，请稍后重试。\n', { status: 502, headers: TEXT_HEADERS });
      }
    }
  }

  if (lang === 'en') {
    context.locals.lang = 'en';
    return withSecurityHeaders(await next(path + url.search));
  }
  /* 改写后的请求若再次经过这里，不要把已定的 en 覆盖回 zh */
  if (!context.locals.lang) context.locals.lang = 'zh';
  return withSecurityHeaders(await next());
});
