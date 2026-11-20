import type { APIRoute } from 'astro';
import { getEdgeEnv } from '../../lib/edge-env';

/**
 * Verifies Cloudflare Turnstile widget tokens via siteverify.
 * Defaults to Cloudflare's public dummy secret key (`1x0000000000000000000000000000000AA`)
 * when TURNSTILE_SECRET_KEY is not set, matching the public dummy sitekey (`1x00000000000000000000AA`).
 */
export const POST: APIRoute = async ({ request }) => {
  try {
    /* 页面以表单编码提交（不触发预检）；也兼容 JSON */
    const type = request.headers.get('content-type') || '';
    const body: { token?: string; action?: string; mode?: string; lang?: string } = type.includes('application/json')
      ? await request.json()
      : Object.fromEntries(new URLSearchParams(await request.text()));
    const en = body?.lang === 'en';
    const token = String(body?.token || '').trim();
    const expectedAction = String(body?.action || '').trim();
    if (!token) {
      return new Response(JSON.stringify({ ok: false, error: 'missing_token', message: en ? 'Missing token' : '缺少验证令牌' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }

    const envObj = getEdgeEnv() as Record<string, string | undefined>;
    const secret = envObj.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';
    const host = new URL(request.url).hostname;

    const form = new URLSearchParams();
    form.set('secret', secret);
    form.set('response', token);
    const remoteIp = request.headers.get('cf-connecting-ip');
    if (remoteIp) form.set('remoteip', remoteIp);

    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
    });
    const data = (await verifyRes.json()) as {
      success?: boolean;
      hostname?: string;
      challenge_ts?: string;
      action?: string;
      cdata?: string;
      'error-codes'?: string[];
      metadata?: Record<string, unknown>;
    };

    const actualHostname = data.hostname || host;
    const actualAction = data.action || expectedAction;

    return new Response(
      JSON.stringify({
        ok: true,
        success: Boolean(data.success),
        hostname: actualHostname,
        hostname_expected: host,
        hostname_ok: actualHostname === host || actualHostname === 'example.com',
        challenge_ts: data.challenge_ts || new Date().toISOString(),
        action: actualAction,
        action_expected: expectedAction,
        action_ok: !expectedAction || actualAction === expectedAction,
        cdata: data.cdata || '',
        error_codes: data['error-codes'] || [],
        metadata: data.metadata || null,
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
    return new Response(JSON.stringify({ ok: false, error: 'verify_failed', message: 'Verification endpoint error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }
};
