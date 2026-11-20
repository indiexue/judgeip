import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../lib/ip-utils';
import { lookupIpFull } from '../lib/ipcx-lookup';
import { localizeLookup } from '../lib/lookup-en';
import { getLang, pick } from '../lib/i18n';

function escXml(s: string): string {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export const GET: APIRoute = async ({ request, url, locals }) => {
  const lang = getLang(locals);
  const t = (zh: string, en: string) => pick(lang, zh, en);
  const visitorIp = extractVisitorIp(request);
  const rawIp = (url.searchParams.get('ip') || '').trim();
  const parsed = rawIp ? parseIp(rawIp) : null;
  const targetIp = parsed ? parsed.normalized : visitorIp;
  const masked = url.searchParams.get('mask') === '1';

  const cfMeta = (request as Request & { cf?: Record<string, unknown> }).cf || null;
  const info = localizeLookup(await lookupIpFull(targetIp, cfMeta, targetIp === visitorIp), lang);

  const displayIp = masked
    ? info.ip.includes(':')
      ? info.ip.split(':').slice(0, 2).join(':') + ':*:*'
      : info.ip.split('.').slice(0, 2).join('.') + '.*.*'
    : info.ip;

  const scoreColor = info.score === null ? '#94a3b8' : info.scoreTone === 'good' ? '#10b981' : info.scoreTone === 'warn' ? '#f59e0b' : '#ef4444';
  const nativeText = info.isBogon ? t('保留地址', 'Reserved') : info.isNative === null ? t('未知', 'Unknown') : info.isNative ? t('原生 IP', 'Native IP') : t('广播 IP', 'Geo-announced IP');
  const loc = [info.countryZh, info.city !== '—' ? info.city : ''].filter(Boolean).join(' · ');

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="680" height="240" viewBox="0 0 680 240">
  <rect width="680" height="240" rx="14" fill="#0f172a"/>
  <rect x="1" y="1" width="678" height="238" rx="13" fill="none" stroke="#1e293b" stroke-width="2"/>
  <text x="28" y="40" font-family="system-ui,-apple-system,sans-serif" font-size="20" font-weight="800" fill="#f8fafc">Judge<tspan fill="#3b82f6">IP</tspan></text>
  <text x="118" y="39" font-family="system-ui,-apple-system,sans-serif" font-size="12" fill="#94a3b8">judgeip.com</text>
  <text x="28" y="84" font-family="ui-monospace,Menlo,monospace" font-size="26" font-weight="700" fill="#f8fafc">${escXml(displayIp)}</text>
  <text x="28" y="110" font-family="system-ui,-apple-system,sans-serif" font-size="13" fill="#cbd5e1">${escXml(loc)} · ${escXml(info.asnCode)} · ${escXml(info.isp.slice(0, 34))}</text>
  <rect x="524" y="26" width="128" height="86" rx="12" fill="#1e293b"/>
  <text x="588" y="48" text-anchor="middle" font-family="system-ui,sans-serif" font-size="11" fill="#94a3b8">${t('纯净度评分', 'IP score')}</text>
  <text x="588" y="82" text-anchor="middle" font-family="ui-monospace,monospace" font-size="30" font-weight="800" fill="${scoreColor}">${info.score ?? '—'}</text>
  <text x="588" y="102" text-anchor="middle" font-family="system-ui,sans-serif" font-size="11" font-weight="700" fill="${scoreColor}">${info.score === null ? t('数据不足', 'Insufficient data') : t('等级 ', 'Grade ') + escXml(info.grade)}</text>
  <line x1="28" y1="132" x2="652" y2="132" stroke="#1e293b"/>
  <text x="28" y="164" font-family="system-ui,sans-serif" font-size="13" fill="#94a3b8">${t('类型：', 'Type: ')}<tspan fill="#f1f5f9" font-weight="600">${escXml(info.ipTypeLabel)} (${escXml(nativeText)})</tspan></text>
  <text x="28" y="194" font-family="system-ui,sans-serif" font-size="13" fill="#94a3b8">${t('路由：', 'Route: ')}<tspan font-family="ui-monospace,monospace" fill="#e2e8f0">${escXml(info.bgpPrefix)}</tspan> · ${escXml(info.rpkiLabel)}</text>
  <text x="360" y="164" font-family="system-ui,sans-serif" font-size="13" fill="#94a3b8">${t('代理：', 'Proxy: ')}<tspan fill="${info.isProxy === null ? '#94a3b8' : info.isProxy ? '#fbbf24' : '#34d399'}" font-weight="600">${escXml(info.proxyLabel)}</tspan></text>
  <text x="360" y="194" font-family="system-ui,sans-serif" font-size="13" fill="#94a3b8">${t('威胁：', 'Threats: ')}<tspan fill="${info.hasThreat === null ? '#94a3b8' : info.hasThreat ? '#f87171' : '#34d399'}" font-weight="600">${escXml(info.threatLabel)}</tspan></text>
</svg>`;

  return new Response(svg, {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=600',
    },
  });
};
