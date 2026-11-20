import type { APIRoute } from 'astro';
import { extractVisitorIp } from '../../../lib/ip-utils';

/**
 * Lightweight edge handshake & RTT probe endpoint.
 * Returns visitor IP, TLS version, HTTP protocol, CF Ray/Colo, and server timestamp
 * for client-side latency and header leak triangulation.
 */
export const GET: APIRoute = async ({ request }) => {
  const ip = extractVisitorIp(request);
  const cf = (request as Request & { cf?: Record<string, unknown> }).cf || {};

  const proxyHeadersPresent = [
    'via',
    'forwarded',
    'x-forwarded-host',
    'proxy-connection',
    'x-proxy-id',
  ].filter((h) => request.headers.has(h));

  return new Response(
    JSON.stringify({
      ok: true,
      ip,
      ts: Date.now(),
      colo: (cf.colo as string) || 'LOCAL',
      httpProtocol: (cf.httpProtocol as string) || 'HTTP/1.1',
      tlsVersion: (cf.tlsVersion as string) || 'TLSv1.3',
      clientTcpRtt: typeof cf.clientTcpRtt === 'number' ? cf.clientTcpRtt : null,
      userAgent: request.headers.get('user-agent') || '',
      acceptLanguage: request.headers.get('accept-language') || '',
      proxyHeadersPresent,
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Access-Control-Allow-Origin': '*',
      },
    }
  );
};
