import type { APIRoute } from 'astro';
import { parseIp } from '../lib/ip-utils';

export const GET: APIRoute = async ({ url, redirect }) => {
  const raw = url.searchParams.get('ip')?.trim() || '';
  const lang = url.searchParams.get('lang') === 'zh' ? 'zh' : 'en';
  const parsed = parseIp(raw);

  if (!parsed) {
    return redirect(lang === 'zh' ? '/zh' : '/', 302);
  }
  const suffix = lang === 'zh' ? '?lang=zh' : '';
  return redirect(`/ip/${encodeURIComponent(parsed.normalized)}${suffix}`, 302);
};
