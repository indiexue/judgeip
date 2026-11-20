import type { APIRoute } from 'astro';
import { extractVisitorIp } from '../lib/ip-utils';

/**
 * Fast zero-upstream edge JSON summary: `curl https://judgeip.com/json`
 */
export const GET: APIRoute = async ({ request }) => {
  const ip = extractVisitorIp(request);
  const cf = (request as Request & { cf?: Record<string, unknown> }).cf || {};

  return new Response(
    JSON.stringify(
      {
        ip,
        asn: cf.asn ? `AS${cf.asn}` : null,
        isp: (cf.asOrganization as string) || null,
        country: (cf.country as string) || null,
        region: (cf.region as string) || null,
        city: (cf.city as string) || null,
        timezone: (cf.timezone as string) || null,
        colo: (cf.colo as string) || null,
        tlsVersion: (cf.tlsVersion as string) || null,
        httpProtocol: (cf.httpProtocol as string) || null,
        reportUrl: `https://judgeip.com/ip/${ip}`,
      },
      null,
      2
    ) + '\n',
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
};
