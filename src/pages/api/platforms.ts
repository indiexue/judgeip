import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';
import { localizeLookup } from '../../lib/lookup-en';
import { judgePlatforms } from '../../lib/platforms';
import { rateHeaders, rateLimit } from '../../lib/rate-limit';

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' };

/* /platforms 页面读到某个平台看到的出口与页面上的 IP 不同时，用这个接口按那个出口重新判定 */
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
    const body = {
      ok: true,
      ip: info.ip,
      score: info.score,
      grade: info.grade,
      type: info.ipTypeLabel,
      countryCode: info.countryCode,
      verdicts: judgePlatforms(info, lang),
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { ...JSON_TYPE, 'Cache-Control': 'private, max-age=300', ...rateHeaders(rate) },
    });
  } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 500, headers: JSON_TYPE });
  }
};
