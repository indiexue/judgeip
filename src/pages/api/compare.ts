import type { APIRoute } from 'astro';
import { compareColumn } from '../../lib/compare';
import { extractVisitorIp, parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';
import { localizeLookup } from '../../lib/lookup-en';
import { rateHeaders, rateLimit } from '../../lib/rate-limit';

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' };

/* /compare 页面逐个 IP 调这个接口，每次取对比表里的一列 */
export const GET: APIRoute = async ({ url, request }) => {
  const visitorIp = extractVisitorIp(request);
  const parsed = parseIp(url.searchParams.get('ip')?.trim() || visitorIp);
  if (!parsed) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_ip' }), { status: 400, headers: JSON_TYPE });
  }

  const rate = rateLimit('api', visitorIp);
  if (!rate.ok) {
    return new Response(JSON.stringify({ ok: false, error: 'rate_limited', retryAfter: rate.resetIn }), {
      status: 429,
      headers: { ...JSON_TYPE, ...rateHeaders(rate) },
    });
  }

  try {
    const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'zh';
    const info = localizeLookup(await lookupIpFull(parsed.normalized, null, false), lang);
    return new Response(JSON.stringify({ ok: true, column: compareColumn(info, lang) }), {
      status: 200,
      headers: { ...JSON_TYPE, 'Cache-Control': 'private, max-age=300', ...rateHeaders(rate) },
    });
  } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 500, headers: JSON_TYPE });
  }
};
