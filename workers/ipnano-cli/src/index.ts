/**
 * IPNano.io — Ultra-lightweight Edge CLI & Dual-Stack Probe Worker
 * Companion edge service for JudgeIP.com:
 *   - `curl ipnano.io`        -> returns plain-text visitor IP (`1.2.3.4\n`)
 *   - `curl ipnano.io/json`   -> returns zero-latency CF edge JSON + JudgeIP report link
 *   - `curl ipnano.io/8.8.8.8`-> proxies explainable verdict summary from JudgeIP.com
 *   - Browser visit           -> redirects to `https://judgeip.com` with full UI
 */

export interface Env {
  JUDGEIP_ORIGIN?: string;
}

const CLI_UA_REGEX = /(curl|wget|httpie|fetch|go-http-client|python-requests|python-httpx|aiohttp|powershell|libwww-perl|xh|insomnia)/i;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+|\/+$/g, '');
    const ua = request.headers.get('user-agent') || '';
    const isCli = CLI_UA_REGEX.test(ua);
    const ip =
      request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-real-ip') ||
      '0.0.0.0';
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf || {};
    const judgeOrigin = env.JUDGEIP_ORIGIN || 'https://judgeip.com';

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    };

    // 1. Root path
    if (!path) {
      if (isCli || url.searchParams.get('format') === 'text') {
        return new Response(`${ip}\n`, {
          headers: { ...corsHeaders, 'Content-Type': 'text/plain; charset=utf-8' },
        });
      }
      if (url.searchParams.get('format') === 'json') {
        return jsonEdgeSummary(ip, cf, ua, judgeOrigin, corsHeaders);
      }
      // Browser visitors get redirected straight to JudgeIP flagship portal
      return Response.redirect(`${judgeOrigin}/`, 302);
    }

    // 2. /ip -> plain text always (great for frontend JS v4.ipnano.io/ip & v6.ipnano.io/ip probes)
    if (path === 'ip') {
      return new Response(`${ip}\n`, {
        headers: { ...corsHeaders, 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    // 3. /json -> instant edge telemetry
    if (path === 'json' || path === 'me') {
      return jsonEdgeSummary(ip, cf, ua, judgeOrigin, corsHeaders);
    }

    // 4. /<target-ip> -> proxy JudgeIP Verdict API
    if (/^[0-9a-fA-F:.]{3,45}$/.test(path)) {
      const apiResp = await fetch(`${judgeOrigin}/api/v1/verdict?ip=${encodeURIComponent(path)}`, {
        headers: { Accept: 'application/json' },
      });
      return new Response(apiResp.body, {
        status: apiResp.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' },
      });
    }

    return new Response('Not Found — Powered by JudgeIP.com\n', {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'text/plain; charset=utf-8' },
    });
  },
};

function jsonEdgeSummary(
  ip: string,
  cf: Record<string, unknown>,
  ua: string,
  judgeOrigin: string,
  corsHeaders: Record<string, string>
): Response {
  return new Response(
    JSON.stringify(
      {
        ip,
        asn: cf.asn ? `AS${cf.asn}` : null,
        isp: cf.asOrganization || null,
        country: cf.country || null,
        region: cf.region || null,
        city: cf.city || null,
        timezone: cf.timezone || null,
        colo: cf.colo || null,
        tlsVersion: cf.tlsVersion || null,
        httpProtocol: cf.httpProtocol || null,
        clientTcpRttMs: cf.clientTcpRtt ?? null,
        userAgent: ua,
        verdictReportUrl: `${judgeOrigin}/ip/${ip}`,
        poweredBy: 'JudgeIP.com',
      },
      null,
      2
    ) + '\n',
    {
      headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8' },
    }
  );
}
