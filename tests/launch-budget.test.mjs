import test from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './load-ts.mjs';

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });

/* 记录每个上游被请求的次数；overrides 按 URL 片段替换应答 */
function upstream(calls, overrides = {}) {
  const table = {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    internetdb: { ports: [], tags: [], vulns: [], hostnames: [] },
    'network-info': { data: { prefix: '73.162.0.0/16', asns: ['7922'] } },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
    ...overrides,
  };
  return async (url) => {
    const str = String(url);
    for (const [needle, body] of Object.entries(table)) {
      if (!str.includes(needle)) continue;
      calls[needle] = (calls[needle] || 0) + 1;
      const answer = typeof body === 'function' ? body(str) : body;
      return answer instanceof Response ? answer : json(answer);
    }
    return json({ data: { result: [] } });
  };
}

async function withFetch(fetcher, fn) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await fn(); } finally { globalThis.fetch = previous; }
}

test('fresh lookups share one per-visitor budget; over budget returns basic info without touching upstreams', async () => {
  const { RATE_LIMITS } = await loadTs('../src/lib/rate-limit.ts');
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const calls = {};
  await withFetch(upstream(calls), async () => {
    const visitorIp = '73.170.1.7';
    for (let i = 1; i <= RATE_LIMITS.lookup; i += 1) {
      const info = await lookupIpFull(`73.162.88.${i}`, null, false, null, { visitorIp });
      assert.notEqual(info.lookupStatus, 'limited', `lookup ${i}`);
    }
    const before = calls['ipwho.is'];
    const limited = await lookupIpFull('73.162.88.200', { country: 'US', asn: 7922 }, false, null, { visitorIp });
    assert.equal(limited.lookupStatus, 'limited');
    assert.ok(limited.retryAfter > 0 && limited.retryAfter <= 60);
    assert.equal(limited.score, null);
    assert.equal(limited.hasThreat, null);
    assert.equal(limited.countryCode, '', 'Cloudflare metadata belongs to the visitor, not to another queried IP');
    assert.equal(calls['ipwho.is'], before, 'no upstream request once the budget is spent');

    // 缓存命中不消耗预算，超出后仍能看到已查过的结果
    const cached = await lookupIpFull('73.162.88.1', null, false, null, { visitorIp });
    assert.notEqual(cached.lookupStatus, 'limited');

    // 预算按访客区分
    const other = await lookupIpFull('73.162.88.201', null, false, null, { visitorIp: '73.170.1.8' });
    assert.notEqual(other.lookupStatus, 'limited');

    // 访客自己的 IP 超出时保留 Cloudflare 给出的基础归属
    const self = await lookupIpFull(visitorIp, { country: 'US', asn: 7922, asOrganization: 'Comcast Cable', timezone: 'America/New_York' }, true, null, { visitorIp });
    assert.equal(self.lookupStatus, 'limited');
    assert.equal(self.countryCode, 'US');
    assert.equal(self.asn, 7922);
    assert.equal(self.isp, 'Comcast Cable');
  });
});

test('concurrent lookups of the same IP make one set of upstream requests', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const calls = {};
  await withFetch(upstream(calls), async () => {
    const results = await Promise.all([1, 2, 3].map(() => lookupIpFull('73.162.90.1', null, false, null, { visitorIp: '73.170.1.20' })));
    assert.equal(calls['ipwho.is'], 1);
    assert.ok(results.every((info) => info.ip === '73.162.90.1'));
  });
});

test('an upstream that answers 429 is paused for its Retry-After window', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const calls = {};
  await withFetch(upstream(calls, { 'ipwho.is': () => json({ success: false }, 429, { 'Retry-After': '120' }) }), async () => {
    await lookupIpFull('73.162.91.1');
    await lookupIpFull('73.162.91.2');
    const info = await lookupIpFull('73.162.91.3');
    assert.equal(calls['ipwho.is'], 1, 'later lookups skip the rate-limited upstream');
    assert.notEqual(info.lookupStatus, 'complete');
  });
});

test('three consecutive upstream failures start a cooldown', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const calls = {};
  await withFetch(upstream(calls, { 'ipwho.is': () => json({}, 503) }), async () => {
    for (let i = 1; i <= 5; i += 1) await lookupIpFull(`73.162.92.${i}`);
    assert.equal(calls['ipwho.is'], 3);
  });
});

test('JSON endpoints answer an exhausted lookup budget with 429 and Retry-After', async () => {
  const { lookupLimitedResponse } = await loadTs('../src/lib/rate-limit.ts');
  const response = lookupLimitedResponse(42);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('Retry-After'), '42');
  assert.deepEqual(await response.json(), { ok: false, error: 'rate_limited', retryAfter: 42 });
});
