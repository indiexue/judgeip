import type { APIRoute } from 'astro';

const CORE_ROUTES = [
  '/',
  '/check',
  '/claude',
  '/ai',
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
  '/privacy',
  '/terms',
];

export const GET: APIRoute = async () => {
  const now = new Date().toISOString();
  const urls = CORE_ROUTES.map(
    (path) => `  <url>
    <loc>https://judgeip.com${path}</loc>
    <lastmod>${now}</lastmod>
    <changefreq>daily</changefreq>
    <priority>${path === '/' ? '1.0' : '0.8'}</priority>
  </url>`
  ).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
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
