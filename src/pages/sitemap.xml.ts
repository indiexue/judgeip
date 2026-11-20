import type { APIRoute } from 'astro';

const CORE_ROUTES = [
  '/',
  '/zh',
  '/tiktok-ip-check',
  '/claude-ip-check',
  '/native-ip-check',
  '/ip/1.1.1.1',
  '/ip/8.8.8.8',
  '/ip/73.162.88.1',
  '/ip/45.76.12.8',
  '/ip/185.156.46.12',
];

export const GET: APIRoute = async () => {
  const now = new Date().toISOString();
  const urls = CORE_ROUTES.map(
    (path) => `  <url>
    <loc>https://judgeip.com${path}</loc>
    <lastmod>${now}</lastmod>
    <changefreq>daily</changefreq>
    <priority>${path === '/' || path === '/zh' ? '1.0' : '0.8'}</priority>
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
