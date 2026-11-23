import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../../lib/ip-utils';
import { lookupIpFull, STREAM_SOURCES } from '../../../lib/ipcx-lookup';
import { localizeLookup } from '../../../lib/lookup-en';
import { rateHeaders, rateLimit } from '../../../lib/rate-limit';

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' };

/**
 * Real-time NDJSON streaming IP lookup endpoint.
 * Streams each upstream source completion (`{"type":"source", ...}`) as soon as that feed responds,
 * followed by the final aggregated & localized report (`{"type":"done","ok":true,"info":{...}}`).
 */
export const GET: APIRoute = async ({ url, request }) => {
  const visitorIp = extractVisitorIp(request);
  const raw = url.searchParams.get('ip')?.trim() || '';
  const isSelf = raw === '' || raw === 'me';
  const fresh = url.searchParams.get('fresh') === '1';
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

  const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'zh';
  const cfMeta = isSelf ? ((request as Request & { cf?: Record<string, unknown> }).cf || null) : null;
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const send = (payload: Record<string, unknown>) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
        } catch {
          closed = true;
        }
      };

      const startedAt = Date.now();
      send({
        type: 'start',
        ip: parsed.normalized,
        total: STREAM_SOURCES.length,
        sources: STREAM_SOURCES,
      });

      try {
        const rawInfo = await lookupIpFull(parsed.normalized, cfMeta, isSelf, null, {
          bypassCache: fresh,
          visitorIp,
          onSource(ev) {
            send({
              type: 'source',
              id: ev.id,
              label: ev.label,
              status: ev.status,
              elapsedMs: Date.now() - startedAt,
            });
          },
        });
        const info = localizeLookup(rawInfo, lang);
        send({
          type: 'done',
          ok: true,
          elapsedMs: Date.now() - startedAt,
          info,
        });
      } catch {
        send({ type: 'error', ok: false, error: 'lookup_failed' });
      } finally {
        if (!closed) {
          closed = true;
          controller.close();
        }
      }
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Accel-Buffering': 'no',
      ...rateHeaders(rate),
    },
  });
};
