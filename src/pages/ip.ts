import type { APIRoute } from 'astro';
import { extractVisitorIp } from '../lib/ip-utils';

/**
 * Plain-text visitor IP endpoint: `curl https://judgeip.com/ip` -> `1.2.3.4\n`
 */
export const GET: APIRoute = async ({ request }) => {
  const ip = extractVisitorIp(request);
  return new Response(`${ip}\n`, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  });
};
