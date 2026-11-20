import { defineMiddleware } from 'astro:middleware';
import { extractVisitorIp } from './lib/ip-utils';

const CLI_UA_REGEX = /^(curl|wget|httpie|xh|fetch|libcurl)\b/i;

/**
 * Allows `curl judgeip.com` to immediately return the plain-text visitor IP (`1.2.3.4\n`)
 * without loading full HTML, while normal browsers render the web interface.
 */
export const onRequest = defineMiddleware(async (context, next) => {
  const { request, url } = context;
  if (url.pathname === '/' && request.method === 'GET') {
    const ua = request.headers.get('user-agent') || '';
    const accept = request.headers.get('accept') || '';
    if (CLI_UA_REGEX.test(ua) && !accept.includes('text/html')) {
      const ip = extractVisitorIp(request);
      return new Response(`${ip}\n`, {
        status: 200,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  }
  return next();
});
