import { handle } from '@astrojs/cloudflare/handler';

/* 构建期编译的信誉索引只给服务端经 ASSETS 绑定读取；上游名单的再分发许可未核清，不对外提供下载 */
const PRIVATE_ASSET = /^\/assets\/data\/(?:ipsum|ranges-)[^/]*$/;

export default {
  async fetch(request: Request, env: Parameters<typeof handle>[1], ctx: Parameters<typeof handle>[2]): Promise<Response> {
    if (PRIVATE_ASSET.test(new URL(request.url).pathname)) {
      return new Response('Not found\n', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    return handle(request, env, ctx);
  },
};
