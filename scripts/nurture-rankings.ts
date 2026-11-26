import { buildSeedPool } from './seed-ips.ts';

// 排名样本养成：每天对代表性 IP 发起真实全量查询，让近 30 天滚动样本持续积累并刷新有效期。
// 由 .github/workflows/nurture-rankings.yml 每日运行。查询是真实的（消耗上游配额，但量小），
// 所以样本里的评分和真实用户查询完全一致——这正是排名有参考意义的前提。
//
// 节奏设计：
// - 每次运行查询 batch 个 IP（默认 24），seed 清单约 275 个，11 天半完成一轮全覆盖；
//   一轮结束后从头再来，老样本的 30 天有效期因此被持续刷新，不会自然过期。
// - 同一批次内串行 + 间隔 sleep，避免触发站内 rate limit（每节点每分钟 20 次全量查询）。
// - 已缓存的 IP（20 分钟内查过）会命中边缘缓存，不消耗上游，但也不重新记录排名；
//   所以每天固定错开时段运行，并依赖 fresh=1 绕过缓存保证记录。
//
// 安全与降级：
// - 单个 IP 失败（429/超时/网络错误）只跳过，不影响其余；整批失败率过半时以非零码退出，便于 Actions 告警。
// - 不伪造任何数据：所有样本都来自 judgeip.com 自己的真实评分结果。

const SITE = process.env.NURTURE_BASE_URL || 'https://judgeip.com';
const BATCH = Number(process.env.NURTURE_BATCH || '24');
const SPACING_MS = Number(process.env.NURTURE_SPACING_MS || '8000');
const TIMEOUT_MS = 90_000;

const pool = buildSeedPool().all;

// 用当天日期做确定性的轮转偏移：同一天重跑（workflow_dispatch 调试）查的是同一批，不会反复消耗配额。
function batchForToday(): string[] {
  const dayIndex = Math.floor(Date.now() / 86_400_000) + Number(process.env.NURTURE_DAY_OFFSET || '0');
  const start = (dayIndex * BATCH) % pool.length;
  const out: string[] = [];
  for (let i = 0; i < BATCH; i++) out.push(pool[(start + i) % pool.length]);
  return out;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface Outcome {
  ip: string;
  ok: boolean;
  score: number | null;
  status: string;
  reason: string;
}

async function probe(ip: string): Promise<Outcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(`${SITE}/api/ipinfo/stream?ip=${encodeURIComponent(ip)}&fresh=1`, {
      headers: { 'User-Agent': 'judgeip-nurture/1.0', Accept: 'application/x-ndjson' },
      signal: controller.signal,
    });
    if (response.status === 429) {
      return { ip, ok: false, score: null, status: 'rate_limited', reason: 'HTTP 429' };
    }
    if (!response.ok || !response.body) {
      return { ip, ok: false, score: null, status: 'http_error', reason: `HTTP ${response.status}` };
    }
    const text = await response.text();
    let done: Record<string, unknown> | null = null;
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        if (event.type === 'done') done = event;
      } catch { /* 忽略残缺行 */ }
    }
    const info = (done as { info?: Record<string, unknown> } | null)?.info;
    if (!info) return { ip, ok: false, score: null, status: 'no_result', reason: 'stream ended without done event' };
    const lookupStatus = String(info.lookupStatus || 'unknown');
    const scored = typeof info.score === 'number';
    return {
      ip,
      ok: scored && ['complete', 'partial'].includes(lookupStatus),
      score: scored ? (info.score as number) : null,
      status: lookupStatus,
      reason: scored ? '' : 'unscored',
    };
  } catch (error) {
    return { ip, ok: false, score: null, status: 'error', reason: error instanceof Error ? error.message.slice(0, 80) : 'unknown' };
  } finally {
    clearTimeout(timer);
  }
}

const batch = batchForToday();
console.log(`Nurturing rankings: ${batch.length} IPs against ${SITE}, spacing ${SPACING_MS / 1000}s`);
const outcomes: Outcome[] = [];
for (const ip of batch) {
  const outcome = await probe(ip);
  outcomes.push(outcome);
  console.log(`${outcome.ok ? '✓' : '✗'} ${ip} — score ${outcome.score ?? '—'} (${outcome.status})${outcome.reason ? ` [${outcome.reason}]` : ''}`);
  if (ip !== batch[batch.length - 1]) await sleep(SPACING_MS);
}

const succeeded = outcomes.filter((o) => o.ok).length;
console.log(`Done: ${succeeded}/${outcomes.length} recorded`);
if (succeeded * 2 < outcomes.length) {
  console.error('More than half of the batch failed — check upstream quota and site health');
  process.exit(1);
}
