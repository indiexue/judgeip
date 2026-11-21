import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';
import { localizeLookup } from '../../lib/lookup-en';
import { getLang } from '../../lib/i18n';

async function fetchJsonSafe(url: string, timeoutMs = 3500): Promise<{ status: number; data: any } | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'JudgeIP/1.0 (+https://judgeip.com)',
      },
    });
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
    return { status: res.status, data };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function cleanField(val: unknown): string {
  if (typeof val !== 'string') return '';
  const t = val.trim();
  return t === '-' ? '' : t.slice(0, 120);
}

export const GET: APIRoute = async ({ request, url, locals }) => {
  // 1. ?me=1 mode used by /cloudflare and /cdn pages for distance calculation
  if (url.searchParams.get('me') === '1') {
    const ip = extractVisitorIp(request);
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf || null;
    try {
      const lang = url.searchParams.get('lang') === 'en' ? 'en' : getLang(locals);
      const info = localizeLookup(await lookupIpFull(ip, cf, true), lang);
      return new Response(
        JSON.stringify({
          ok: true,
          ip: info.ip,
          country: info.countryCode,
          region: info.region === '—' ? '' : info.region,
          city: info.city === '—' ? '' : info.city,
          lat: info.latitude,
          lon: info.longitude,
          asn: info.asn,
          org: info.org,
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        }
      );
    } catch {
      return new Response(JSON.stringify({ ok: false }), {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
  }

  // 2. Multi-database Geo fallback/manual lookup (?ip=...&only=ip2location,dbip,ipinfo,maxmind)
  const rawIp = url.searchParams.get('ip') || extractVisitorIp(request);
  const parsed = parseIp(rawIp);
  if (!parsed || parsed.isBogon) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_ip' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }

  const targetIp = parsed.normalized;
  const onlyParam = url.searchParams.get('only');
  const requestedKeys = onlyParam
    ? onlyParam.split(',').map((s) => s.trim()).filter(Boolean)
    : ['ip2location', 'dbip', 'ipinfo', 'maxmind'];

  const sources: Record<string, { status: string; country?: string; region?: string; city?: string; reason?: string }> = {};

  await Promise.all(
    requestedKeys.map(async (key) => {
      if (key === 'ip2location') {
        const r = await fetchJsonSafe(`https://api.ip2location.io/?ip=${encodeURIComponent(targetIp)}&format=json`);
        if (r && r.status === 200 && r.data && !r.data.error) {
          sources[key] = {
            status: 'ok',
            country: cleanField(r.data.country_code).toUpperCase(),
            region: cleanField(r.data.region_name),
            city: cleanField(r.data.city_name),
          };
        } else {
          sources[key] = { status: 'fail', reason: r?.status === 429 ? 'limited' : 'error' };
        }
      } else if (key === 'dbip') {
        const r = await fetchJsonSafe(`https://api.db-ip.com/v2/free/${encodeURIComponent(targetIp)}`);
        if (r && r.status === 200 && r.data && !r.data.errorCode && !r.data.error) {
          sources[key] = {
            status: 'ok',
            country: cleanField(r.data.countryCode).toUpperCase(),
            region: cleanField(r.data.stateProv),
            city: cleanField(r.data.city),
          };
        } else {
          sources[key] = { status: 'fail', reason: 'limited' };
        }
      } else if (key === 'ipinfo') {
        const r = await fetchJsonSafe(`https://ipinfo.io/${encodeURIComponent(targetIp)}/json`);
        if (r && r.status === 200 && r.data && r.data.country && !r.data.error) {
          sources[key] = {
            status: 'ok',
            country: cleanField(r.data.country).toUpperCase(),
            region: cleanField(r.data.region),
            city: cleanField(r.data.city),
          };
        } else {
          sources[key] = { status: 'fail', reason: r?.status === 429 ? 'limited' : 'error' };
        }
      } else if (key === 'maxmind') {
        // Query GeoJS (powered by MaxMind GeoLite2) for authentic MaxMind DB comparison
        const r = await fetchJsonSafe(`https://get.geojs.io/v1/ip/geo/${encodeURIComponent(targetIp)}.json`);
        if (r && r.status === 200 && r.data && r.data.country_code) {
          sources[key] = {
            status: 'ok',
            country: cleanField(r.data.country_code).toUpperCase(),
            region: cleanField(r.data.region),
            city: cleanField(r.data.city),
          };
        } else {
          sources[key] = { status: 'fail', reason: 'error' };
        }
      }
    })
  );

  return new Response(
    JSON.stringify({
      ok: true,
      ip: targetIp,
      sources,
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'public, max-age=1800',
      },
    }
  );
};
