import type { APIRoute } from 'astro';
import { parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';
import { localizeLookup } from '../../lib/lookup-en';

export const GET: APIRoute = async ({ url }) => {
  const raw = url.searchParams.get('ip')?.trim() || '';
  const parsed = parseIp(raw);
  if (!parsed) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_ip' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }

  try {
    const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'zh';
    const info = localizeLookup(await lookupIpFull(parsed.normalized, null, false), lang);
    return new Response(JSON.stringify({ ok: true, info }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'private, max-age=300',
      },
    });
  } catch {
    return new Response(JSON.stringify({ ok: false }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }
};
