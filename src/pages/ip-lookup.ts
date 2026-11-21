import type { APIRoute } from 'astro';
import { parseIp } from '../lib/ip-utils';
import { getLang, localePath } from '../lib/i18n';

export const GET: APIRoute = async ({ url, locals, redirect }) => {
  const raw = url.searchParams.get('ip')?.trim() || '';
  const requested = url.searchParams.get('lang');
  const lang = requested === 'en' || requested === 'zh' ? requested : getLang(locals);
  const parsed = parseIp(raw);
  return redirect(localePath(parsed ? `/ip/${encodeURIComponent(parsed.normalized)}` : '/', lang), 302);
};
