/**
 * MCP 服务的协议处理（Streamable HTTP，无会话）：一条 JSON-RPC 消息进，一条应答出。
 * 查询函数由调用方传入，这里不直接发上游请求。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';
import { parseIp } from './ip-utils';
import { localizeLookup } from './lookup-en';
import { rateLimit } from './rate-limit';
import { SCORE_BASE, SCORE_GRADES, SCORE_MAX, SCORE_MIN, SCORE_RULES, formatDelta } from './score-rules';
import { renderCompareText, renderTextReport } from './text-report';

/* 新版本在前；客户端要的版本不在表里时回第一个 */
export const MCP_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
/* 一次请求的子请求数有上限，每个 IP 约 11 个上游请求 */
export const MCP_COMPARE_MAX = 4;

export interface McpContext {
  clientIp: string;
  lookup: (ip: string) => Promise<HomeIpLookupResult>;
}

const LANG_PROP = {
  type: 'string',
  enum: ['en', 'zh'],
  description: 'Language of the report text. Defaults to en.',
};

const READ_ONLY = { readOnlyHint: true, openWorldHint: true };

export const MCP_TOOLS = [
  {
    name: 'check_ip',
    title: 'Check an IP address',
    description:
      'Look up one IPv4 or IPv6 address on JudgeIP: network type (residential, mobile, business, data center, CDN), Dual-ISP status, operator and ASN, location, whether registry and geolocation countries match (native IP), proxy/VPN/Tor flags, DNS blocklists, open ports, and a 5-99 purity score with confidence level and points added or subtracted for each item. Omit `ip` to check the address this request came from, which is the machine running the MCP client (for hosted clients, the provider\'s server rather than the user).',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IPv4 or IPv6 address, e.g. 8.8.8.8. Omit to check the caller\'s own address.' },
        lang: LANG_PROP,
      },
      additionalProperties: false,
    },
    annotations: READ_ONLY,
  },
  {
    name: 'compare_ips',
    title: 'Compare IP addresses',
    description: `Look up 2 to ${MCP_COMPARE_MAX} IP addresses and return score, network type, native IP, proxy, blocklist and open-port results for each, in the order given.`,
    inputSchema: {
      type: 'object',
      properties: {
        ips: { type: 'array', items: { type: 'string' }, minItems: 2, maxItems: MCP_COMPARE_MAX, description: 'IPv4 or IPv6 addresses.' },
        lang: LANG_PROP,
      },
      required: ['ips'],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
  },
  {
    name: 'scoring_rules',
    title: 'JudgeIP scoring rules',
    description: 'Return the published JudgeIP scoring rules: base score, points for each item, grade thresholds, and when no score is given. Makes no upstream requests.',
    inputSchema: {
      type: 'object',
      properties: { lang: LANG_PROP },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
];

export function renderRulesText(lang: Lang): string {
  const en = lang === 'en';
  const lines = [
    en
      ? `Every IP starts at ${SCORE_BASE}. The items below add or subtract points; the result is kept within ${SCORE_MIN}-${SCORE_MAX}.`
      : `每个 IP 从 ${SCORE_BASE} 分起算，按下列各项加减，结果限制在 ${SCORE_MIN}–${SCORE_MAX} 之间。`,
  ];
  for (const rule of SCORE_RULES) {
    lines.push('', rule.label[lang]);
    for (const row of rule.rows) lines.push(`  ${formatDelta(row.delta).padStart(3)}  ${row.when[lang]}`);
    lines.push(
      `  ${en ? 'Basis: ' : '依据：'}${rule.basis[lang]}`,
      `  ${en ? 'Sources: ' : '数据来源：'}${rule.sources.map((s) => (typeof s === 'string' ? s : s[lang])).join(en ? ', ' : '、')}`,
    );
  }
  lines.push('', en ? 'Grades' : '等级');
  SCORE_GRADES.forEach((g, i) => lines.push(`  ${g.grade.padEnd(2)}  ${Math.max(g.min, SCORE_MIN)}-${i === 0 ? SCORE_MAX : SCORE_GRADES[i - 1].min - 1}`));
  lines.push(
    '',
    en
      ? 'Scores carry a confidence level: high (all IPv4 feeds answered), medium (IPv6 or partial secondary feeds), or low. No score is given only when core network or security feeds all fail, or for reserved addresses.'
      : '评分附带置信度（高 / 中 / 低）：全部 IPv4 数据源齐备为高置信度；IPv6（免测端口与传统邮件黑名单）或个别次要源未答复时照常出分并标为中/低置信度；仅在基础归属与安全数据源全部不可达或保留地址时不出分。',
    en ? 'These are JudgeIP\'s own rules, not any platform\'s official risk score.' : '这是 JudgeIP 自己的规则，不是任何平台的官方风控分。',
    `https://judgeip.com${en ? '/en' : ''}/scoring`,
  );
  return `${lines.join('\n')}\n`;
}

const textResult = (text: string, isError = false) => ({ content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) });

async function callTool(name: string, args: Record<string, unknown>, ctx: McpContext) {
  const lang: Lang = args.lang === 'zh' ? 'zh' : 'en';
  if (name === 'scoring_rules') return textResult(renderRulesText(lang));

  const raw = name === 'check_ip' ? [args.ip === undefined || args.ip === '' ? ctx.clientIp : args.ip] : args.ips;
  if (!Array.isArray(raw) || raw.some((ip) => typeof ip !== 'string')) return textResult('`ips` must be an array of IP address strings.', true);
  if (name === 'compare_ips' && (raw.length < 2 || raw.length > MCP_COMPARE_MAX)) {
    return textResult(`compare_ips takes 2 to ${MCP_COMPARE_MAX} addresses; got ${raw.length}.`, true);
  }
  const ips: string[] = [];
  for (const ip of raw as string[]) {
    const parsed = parseIp(ip);
    if (!parsed) return textResult(`Not a valid IPv4 or IPv6 address: ${ip.slice(0, 64)}`, true);
    if (!ips.includes(parsed.normalized)) ips.push(parsed.normalized);
  }

  /* 按查询的 IP 个数计数 */
  for (let i = 0; i < ips.length; i += 1) {
    const rate = rateLimit('mcp', ctx.clientIp);
    if (!rate.ok) return textResult(`Rate limit reached (${rate.limit} lookups per minute). Try again in ${rate.resetIn} seconds.`, true);
  }

  try {
    const infos = (await Promise.all(ips.map((ip) => ctx.lookup(ip)))).map((info) => localizeLookup(info, lang));
    return textResult(name === 'check_ip' ? renderTextReport(infos[0], lang) : renderCompareText(infos, lang));
  } catch {
    return textResult('Lookup failed. Try again later.', true);
  }
}

const rpcError = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });

/** 处理一条 JSON-RPC 消息。通知（没有 id）不需要应答，返回 null。 */
export async function handleMcpMessage(message: unknown, ctx: McpContext): Promise<Record<string, unknown> | null> {
  if (!message || typeof message !== 'object' || Array.isArray(message)) return rpcError(null, -32600, 'Invalid Request');
  const { jsonrpc, id, method, params } = message as { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: Record<string, unknown> };
  if (jsonrpc !== '2.0' || typeof method !== 'string') return id === undefined ? null : rpcError(id, -32600, 'Invalid Request');
  if (id === undefined || id === null) return null;

  const result = (value: unknown) => ({ jsonrpc: '2.0', id, result: value });
  switch (method) {
    case 'initialize': {
      const wanted = params?.protocolVersion;
      return result({
        protocolVersion: typeof wanted === 'string' && MCP_PROTOCOL_VERSIONS.includes(wanted) ? wanted : MCP_PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: 'judgeip', title: 'JudgeIP', version: '1.0.0' },
        instructions:
          'IP address lookups from judgeip.com. Scores follow published rules (see scoring_rules) and are JudgeIP\'s own heuristics, not any platform\'s official risk score. Data comes from free public sources and is rate limited; do not bulk query.',
      });
    }
    case 'ping':
      return result({});
    case 'tools/list':
      return result({ tools: MCP_TOOLS });
    case 'tools/call': {
      const name = params?.name;
      if (typeof name !== 'string' || !MCP_TOOLS.some((tool) => tool.name === name)) return rpcError(id, -32602, `Unknown tool: ${String(name).slice(0, 64)}`);
      const args = params?.arguments && typeof params.arguments === 'object' ? (params.arguments as Record<string, unknown>) : {};
      return result(await callTool(name, args, ctx));
    }
    default:
      return rpcError(id, -32601, `Method not found: ${method.slice(0, 64)}`);
  }
}
