import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../../lib/ip-utils';
import { evaluateIpVerdict } from '../../../lib/verdict-engine';
import { getEdgeEnv } from '../../../lib/edge-env';

export const GET: APIRoute = async ({ request, url }) => {
  const targetParam = url.searchParams.get('ip')?.trim();
  const visitorIp = extractVisitorIp(request);
  const targetIp = targetParam && targetParam !== 'me' ? targetParam : visitorIp;

  const parsed = parseIp(targetIp);
  if (!parsed) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: 'Invalid IPv4 or IPv6 address format.',
      }),
      {
        status: 400,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
        },
      }
    );
  }

  const cfMeta = (request as Request & { cf?: Record<string, unknown> }).cf || null;
  const isDirectVisitor = parsed.normalized === visitorIp;
  const kvNamespace = getEdgeEnv().IP_CACHE;

  try {
    const report = await evaluateIpVerdict(parsed.normalized, {
      cfMetadata: cfMeta,
      isDirectVisitor,
      kvNamespace,
    });

    return new Response(
      JSON.stringify(
        {
          ok: true,
          isVisitor: isDirectVisitor,
          report,
        },
        null,
        2
      ),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': isDirectVisitor ? 'private, no-store' : 'public, s-maxage=900, stale-while-revalidate=3600',
          'Access-Control-Allow-Origin': '*',
        },
      }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({
        ok: false,
        error: err instanceof Error ? err.message : 'Failed to evaluate IP verdict',
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      }
    );
  }
};
