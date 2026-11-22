import type { APIRoute } from 'astro';
import { localePath } from '../lib/i18n';

const CORE_ROUTES = [
  '/',
  '/check',
  '/claude',
  '/ai',
  '/gpt',
  '/platforms',
  '/compare',
  '/egress',
  '/native-ip',
  '/residential-ip',
  '/tiktok-ip',
  '/webrtc',
  '/dnsleak',
  '/cloudflare',
  '/connectivity',
  '/cdn',
  '/split',
  '/ping',
  '/whois',
  '/dns-tools',
  '/ip-calc',
  '/headers',
  '/fingerprint',
  '/card',
  '/status',
  '/tools',
  '/scoring',
  '/data',
  '/api-docs',
  '/privacy',
  '/terms',
];

export const GET: APIRoute = async () => {
  const now = new Date().toISOString();
  /* 每个页面中英文各一条，用 xhtml:link 互相标注另一种语言 */
  const urls = CORE_ROUTES.flatMap((path) => {
    const zh = `https://judgeip.com${path}`;
    const en = `https://judgeip.com${localePath(path, 'en')}`;
    const alternates = `
    <xhtml:link rel="alternate" hreflang="zh-CN" href="${zh}"/>
    <xhtml:link rel="alternate" hreflang="en" href="${en}"/>`;
    return [zh, en].map(
      (loc) => `  <url>
    <loc>${loc}</loc>${alternates}
    <lastmod>${now}</lastmod>
    <changefreq>daily</changefreq>
    <priority>${path === '/' ? '1.0' : '0.8'}</priority>
  </url>`
    );
  }).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${urls}
</urlset>`;

  return new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
