import type { APIRoute } from 'astro';
import { extractVisitorIp } from '../lib/ip-utils';
import { lookupIpFull } from '../lib/ipcx-lookup';
import { handleMcpMessage, type McpContext } from '../lib/mcp';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, MCP-Protocol-Version, Mcp-Session-Id',
  'Access-Control-Max-Age': '86400',
};

const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS },
  });

/**
 * MCP endpoint (Streamable HTTP, stateless): `claude mcp add --transport http judgeip https://judgeip.com/mcp`
 */
export const POST: APIRoute = async ({ request }) => {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return reply({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
  }

  const clientIp = extractVisitorIp(request);
  const ctx: McpContext = {
    clientIp,
    lookup: (ip) => lookupIpFull(ip, null, false, null, { visitorIp: clientIp }),
  };

  if (Array.isArray(body)) {
    /* 一次请求能发的上游请求有限，批量里最多带一个 tools/call */
    const calls = body.filter((message) => message?.method === 'tools/call').length;
    if (body.length === 0 || body.length > 8 || calls > 1) {
      return reply({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request: send at most 8 messages and one tools/call per batch' } }, 400);
    }
    const answers = [];
    for (const message of body) {
      const answer = await handleMcpMessage(message, ctx);
      if (answer) answers.push(answer);
    }
    return answers.length > 0 ? reply(answers) : new Response(null, { status: 202, headers: CORS });
  }

  const answer = await handleMcpMessage(body, ctx);
  return answer ? reply(answer) : new Response(null, { status: 202, headers: CORS });
};

export const OPTIONS: APIRoute = () => new Response(null, { status: 204, headers: CORS });

/* 没有服务端推送，GET / DELETE 一律 405 */
export const ALL: APIRoute = () => new Response('Method Not Allowed\n', { status: 405, headers: { Allow: 'POST, OPTIONS', ...CORS } });
