import test from 'node:test';
import assert from 'node:assert/strict';
import { localizeLookup } from '../src/lib/lookup-en.ts';
import { loadTs } from './load-ts.mjs';

// 历史索引在进程内只加载一次，所以本文件用同一份索引覆盖所有情形，并单独成文件，避免被其他测试先缓存成不可用。
const json = (data) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
const ipsumIndex = () => {
  const b = Buffer.alloc(16 + 1000 * 5);
  b.write('IPSM'); b.writeDoubleBE(Date.now(), 4); b.writeUInt32BE(1000, 12);
  for (let i = 0; i < 1000; i++) { b.writeUInt32BE(11 * 2 ** 24 + i, 16 + i * 5); b.writeUInt8(1, 20 + i * 5); }
  return b;
};

test('recent IPsum history lowers the score one tier below a same-day listing; absence changes nothing', async () => {
  const { mergeHistory, compileHistoryIndex } = await loadTs('../src/lib/ipsum-history-format.ts');
  const h = mergeHistory(null, { entries: new Map([['73.162.88.1', 3], ['73.162.88.2', 6]]), updatedAt: new Date(Date.now() - 5 * 86400_000).toISOString() });
  h.updatedAt = new Date().toISOString();
  const history = compileHistoryIndex(h);
  const table = {
    'ipsum-history.bin': () => new Response(history),
    'assets/data/ipsum.bin': () => new Response(ipsumIndex()),
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    'proxycheck.io': (url) => ({ status: 'ok', [url.split('/v2/')[1].split('?')[0]]: { proxy: 'no', type: 'Residential', risk: 0 } }),
    internetdb: { ports: [], tags: [], vulns: [], hostnames: [] },
    'whois/data': { data: { authorities: ['ARIN'], records: [[{ key: 'Country', value: 'US' }]] } },
    'network-info': { data: { prefix: '73.162.0.0/16', asns: ['7922'] } },
    'rpki-validation': { data: { status: 'valid' } },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
  };
  const previous = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const str = String(url);
    for (const [needle, body] of Object.entries(table)) {
      if (!str.includes(needle)) continue;
      const answer = typeof body === 'function' ? body(str) : body;
      return answer instanceof Response ? answer : json(answer);
    }
    return json({ data: { result: [] } });
  };
  try {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const reputation = (info) => info.factors.find((f) => f.key === 'reputation');
    const sum = (info) => info.scoreBase + info.factors.reduce((n, f) => n + f.delta, 0);
    const [mild, moderate, clean] = await Promise.all(['73.162.88.1', '73.162.88.2', '73.162.88.3'].map((ip) => lookupIpFull(ip, null, false, {})));

    assert.equal(clean.score, 95);
    assert.equal(clean.hasThreat, false);
    assert.equal(clean.reputationCoverage, 'complete');

    assert.equal(mild.hasThreat, true);
    assert.equal(mild.threatLabel, '近 30 天曾被 3 个名单收录');
    assert.equal(reputation(mild).delta, -18);
    assert.equal(mild.score, 77);
    assert.ok(reputation(mild).evidence.some((e) => e.source === 'IPsum 30-day history' && e.value.endsWith('/ 3')));
    assert.equal(localizeLookup(mild, 'en').threatLabel, 'Listed by 3 lists in the last 30 days');

    assert.equal(moderate.score, 49, 'six lists within 30 days counts as moderate');
    for (const info of [mild, moderate, clean]) assert.equal(sum(info), info.score);
  } finally {
    globalThis.fetch = previous;
  }
});
