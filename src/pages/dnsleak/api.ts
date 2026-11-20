import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../lib/ip-utils';
import { lookupIpFull } from '../../lib/ipcx-lookup';

const PUBLIC_DNS_PROVIDERS: Record<number, string> = {
  15169: 'Google Public DNS',
  13335: 'Cloudflare 1.1.1.1',
  19281: 'Quad9 DNS',
  36692: 'Cisco OpenDNS',
  4788: 'TM Net',
  37963: '阿里公共 DNS',
  45102: '阿里云 DNS',
  45090: '腾讯 DNSPod',
  132203: '腾讯云 DNS',
  38365: '百度公共 DNS',
  9498: 'Bharti Airtel',
  3462: '中华电信 HiNet',
  4134: '中国电信',
  4837: '中国联通',
  9808: '中国移动',
};

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = (await request.json()) as {
      clientIp?: string;
      resolvers?: Array<{ ip?: string; queries?: number; ecs?: string }>;
    };

    const visitorIp = parseIp(body.clientIp)?.normalized || extractVisitorIp(request);
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf || null;
    const clientInfo = await lookupIpFull(visitorIp, cf, true);

    const rawResolvers = Array.isArray(body.resolvers) ? body.resolvers.slice(0, 12) : [];
    const enriched = await Promise.all(
      rawResolvers.map(async (item) => {
        const parsed = parseIp(item.ip || '');
        if (!parsed) return null;
        try {
          const info = await lookupIpFull(parsed.normalized, null, false);
          const provider = (info.asn && PUBLIC_DNS_PROVIDERS[info.asn]) || '';
          let resolverType = 'hosting';
          if (provider && /(Google|Cloudflare|Quad9|OpenDNS|阿里公共|DNSPod|百度公共)/.test(provider)) {
            resolverType = 'public';
          } else if (!info.isDatacenter) {
            resolverType = 'isp';
          }
          return {
            ip: info.ip,
            country_code: info.countryCode,
            country: info.countryZh,
            asn: info.asn ? `AS${info.asn}` : '',
            isp: info.isp,
            provider,
            type: resolverType,
            queries: Math.max(1, Number(item.queries) || 1),
            ecs: item.ecs || '',
          };
        } catch {
          return null;
        }
      })
    );

    return new Response(
      JSON.stringify({
        ok: true,
        client: {
          ip: clientInfo.ip,
          country_code: clientInfo.countryCode,
          country: clientInfo.countryZh,
          asn: clientInfo.asn ? `AS${clientInfo.asn}` : '',
          isp: clientInfo.isp,
        },
        resolvers: enriched.filter(Boolean),
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
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }
};
