import type { EdgeEnv } from './edge-env';

export const TURNSTILE_WIDGETS = {
  mg: { sitekey: '0x4AAAAAAGKTUfiotw71uea9', action: 'cf-test-mg', secret: 'TURNSTILE_SECRET_KEY_MANAGED' },
  ni: { sitekey: '0x4AAAAAAGKTZRRCizCj3kt3', action: 'cf-test-ni', secret: 'TURNSTILE_SECRET_KEY_NON_INTERACTIVE' },
} as const;

export async function verifyTurnstile(request: Request, env: EdgeEnv): Promise<Response> {
  let en = false;
  const reply = (body: Record<string, unknown>, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
  const fail = (error: string, zh: string, english: string, status: number, details: Record<string, unknown> = {}) => reply({ ok: false, error, message: en ? english : zh, ...details }, status);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const body = (request.headers.get('content-type') || '').includes('application/json')
      ? await request.json()
      : Object.fromEntries(new URLSearchParams(await request.text()));
    if (!body || typeof body !== 'object' || Array.isArray(body)) return fail('invalid_body', '请求格式无效', 'Invalid request body', 400);
    en = body.lang === 'en';
    if (body.mode !== 'mg' && body.mode !== 'ni') return fail('invalid_mode', '未知的验证模式', 'Unknown verification mode', 400);
    const widget = TURNSTILE_WIDGETS[body.mode as keyof typeof TURNSTILE_WIDGETS];
    const token = typeof body.token === 'string' ? body.token.trim() : '';
    if (!token || token.length > 2048) return fail('invalid_token', '验证令牌为空或过长', 'Token is missing or too long', 400);
    if (body.action !== widget.action) return fail('invalid_action', '验证动作与模式不匹配', 'Action does not match the selected mode', 400);
    const secret = env[widget.secret]?.trim();
    if (!secret) return fail('not_configured', '本站尚未配置此模式的验证密钥', 'This verification mode is not configured on this site', 503);

    const form = new URLSearchParams({ secret, response: token });
    const remoteIp = request.headers.get('cf-connecting-ip');
    if (remoteIp) form.set('remoteip', remoteIp);
    const ctl = new AbortController();
    timer = setTimeout(() => ctl.abort(), 6000);
    const started = Date.now();
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', body: form, signal: ctl.signal,
    });
    if (!response.ok && response.status !== 400) return fail('upstream_error', 'Cloudflare 复核接口暂不可用', 'Cloudflare verification is temporarily unavailable', 502, { upstream_status: response.status });
    // Siteverify also returns structured validation errors with HTTP 400.
    const data = await response.json();
    if (!data || typeof data.success !== 'boolean') return fail('invalid_response', 'Cloudflare 返回了无效的复核数据', 'Cloudflare returned an invalid verification response', 502);
    const knownErrors = ['missing-input-secret', 'invalid-input-secret', 'missing-input-response', 'invalid-input-response', 'bad-request', 'timeout-or-duplicate', 'internal-error'];
    const rawErrors: unknown[] = Array.isArray(data['error-codes']) ? data['error-codes'] : [];
    const errors = rawErrors.filter((v): v is string => typeof v === 'string' && knownErrors.includes(v));
    const details = { upstream_status: response.status, error_codes: errors };
    if (data.success === false && errors.some((v) => ['missing-input-secret', 'invalid-input-secret'].includes(v))) {
      return fail('configuration_error', '本站验证密钥配置有误，请联系站点管理员', 'This site has a verification key configuration error', 503, details);
    }
    if (errors.some((v) => ['internal-error', 'bad-request', 'missing-input-response'].includes(v))) return fail('upstream_error', 'Cloudflare 复核请求未完成，请重试', 'Cloudflare verification request did not complete; try again', 502, details);
    const tokenRejected = data.success === false && errors.length > 0 && errors.length === rawErrors.length
      && errors.every((v) => ['invalid-input-response', 'timeout-or-duplicate'].includes(v));
    if (!response.ok && !tokenRejected) return fail('upstream_error', 'Cloudflare 未返回可用的复核结果', 'Cloudflare did not return a usable verification result', 502, details);
    const host = new URL(request.url).hostname.toLowerCase();
    const actualHostname = typeof data.hostname === 'string' ? data.hostname.toLowerCase() : '';
    const actualAction = typeof data.action === 'string' ? data.action : '';
    const hostnameOk = actualHostname === host;
    const actionOk = actualAction === widget.action;
    const testingKey = data.metadata?.result_with_testing_key === true;
    const pass = data.success && hostnameOk && actionOk && !testingKey;
    const message = pass ? (en ? 'Verification passed' : '复核通过')
      : testingKey ? (en ? 'A testing key cannot be used for this check' : '测试密钥不能用于此检测')
        : !data.success ? (en ? 'Cloudflare rejected this token. Reset the widget and try again.' : 'Cloudflare 未接受此令牌，请重置后重试。')
          : !hostnameOk ? (en ? 'The token hostname does not match this site' : '令牌所属域名与本站不一致')
            : (en ? 'The token action does not match this mode' : '令牌动作与此模式不一致');
    return reply({
      ok: true, pass, success: data.success, message, verify_ms: Date.now() - started,
      hostname: actualHostname, hostname_expected: host, hostname_ok: hostnameOk,
      action: actualAction, action_expected: widget.action, action_ok: actionOk,
      challenge_ts: typeof data.challenge_ts === 'string' ? data.challenge_ts : '',
      cdata: typeof data.cdata === 'string' ? data.cdata : '', error_codes: errors,
      metadata: data.metadata || null,
    });
  } catch {
    return fail('verify_unavailable', '复核未完成，请稍后重试', 'Verification did not complete; try again later', 502);
  } finally {
    clearTimeout(timer);
  }
}
