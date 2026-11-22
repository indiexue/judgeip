import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';
import { localizeLookup } from '../../lib/lookup-en';
import { rateHeaders, rateLimit } from '../../lib/rate-limit';

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' };

export const GET: APIRoute = async ({ url, request }) => {
  const visitorIp = extractVisitorIp(request);
  /* 不带 ip 参数或 ip=me 时查请求方自己的 IP */
  const raw = url.searchParams.get('ip')?.trim() || '';
  const isSelf = raw === '' || raw === 'me';
  const parsed = parseIp(isSelf ? visitorIp : raw);
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
    return new Response(JSON.stringify({ ok: true, info }), {
      status: 200,
      headers: {
        ...JSON_TYPE,
        'Cache-Control': isSelf ? 'no-store' : 'private, max-age=300',
        ...rateHeaders(rate),
      },
    });
  } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 500, headers: JSON_TYPE });
  }
};
