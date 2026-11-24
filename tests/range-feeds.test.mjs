import test from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './load-ts.mjs';

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

const ipsumFixture = Buffer.alloc(16 + 1000 * 5);
ipsumFixture.write('IPSM');
ipsumFixture.writeDoubleBE(Date.now(), 4);
ipsumFixture.writeUInt32BE(1000, 12);
for (let i = 0; i < 1000; i++) { ipsumFixture.writeUInt32BE(10 * 2 ** 24 + i, 16 + i * 5); ipsumFixture.writeUInt8(1, 20 + i * 5); }

const net = (third) => 11 * 2 ** 24 + third * 256;
function ranges(...thirds) {
  const buf = Buffer.alloc(16 + thirds.length * 8);
  buf.write('IPRG');
  buf.writeDoubleBE(Date.now(), 4);
  buf.writeUInt32BE(thirds.length, 12);
  thirds.forEach((t, i) => { buf.writeUInt32BE(net(t), 16 + i * 8); buf.writeUInt32BE(net(t) + 255, 20 + i * 8); });
  return buf;
}
/* 11.0.1.0/24 是 VPN 出口段，11.0.2.0/24 在 DROP 和 FireHOL 里，11.0.3.0/24 只在 FireHOL 里 */
const RANGE_FILES = { 'x4b-vpn': ranges(1), 'spamhaus-drop': ranges(2), 'firehol-l1': ranges(2, 3) };

function upstream(overrides = {}) {
  const table = {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', city: 'Dallas', postal: '75244', connection: { asn: 7922, isp: 'Comcast Cable' }, timezone: { id: 'America/Chicago' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    'assets/data/ipsum.bin': () => new Response(ipsumFixture),
    'assets/data/ranges-': (url) => new Response(RANGE_FILES[url.match(/ranges-([\w-]+)\.bin/)[1]]),
    internetdb: { ports: [], tags: [], vulns: [], hostnames: [] },
    'whois/data': { data: { authorities: ['ARIN'], records: [[{ key: 'Country', value: 'US' }]] } },
    'network-info': { data: { prefix: '11.0.0.0/16', asns: ['7922'] } },
    'rpki-validation': { data: { status: 'valid' } },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
    ...overrides,
  };
  return async (url) => {
    const str = String(url);
    for (const [needle, body] of Object.entries(table)) {
      if (!str.includes(needle)) continue;
      const answer = typeof body === 'function' ? body(str) : body;
      return answer instanceof Response ? answer : json(answer);
    }
    return json({ data: { result: [] } });
  };
}

async function lookup(ip, overrides) {
  const previous = globalThis.fetch;
  globalThis.fetch = upstream(overrides);
  try {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    return await lookupIpFull(ip);
  } finally {
    globalThis.fetch = previous;
  }
}
const factor = (info, key) => info.factors.find((f) => f.key === key);

test('range lists parse CIDRs and Spamhaus JSON lines, merge overlaps and skip IPv6', async () => {
  const { parseRangeList, compileRangeIndex, parseRangeIndex, lookupRangeIndex } = await loadTs('../src/lib/range-feeds.ts');
  const list = parseRangeList([
    '# comment',
    '1.2.3.0/24',
    '1.2.3.128/25',
    '1.2.4.0/24',
    '9.9.9.9',
    '2001:db8::/32',
    '{"cidr":"5.6.0.0/16","sblid":"SBL1","rir":"ripencc"}',
    '{"type":"metadata","timestamp":1}',
  ].join('\n'));
  assert.deepEqual(list, [[16909056, 16909567], [84279296, 84344831], [151587081, 151587081]]);
  const index = parseRangeIndex(compileRangeIndex(list, Date.now()).buffer);
  assert.equal(lookupRangeIndex(index, '1.2.4.200'), '1.2.3.0 – 1.2.4.255');
  assert.equal(lookupRangeIndex(index, '9.9.9.9'), '9.9.9.9 – 9.9.9.9');
  assert.equal(lookupRangeIndex(index, '1.2.5.0'), undefined);
  assert.equal(lookupRangeIndex(index, '1.2.3'), null);
  assert.equal(parseRangeIndex(compileRangeIndex(list, Date.now() - 9 * 86400000).buffer), null, 'stale snapshots are rejected');
});

test('VPN ranges mark the address as VPN; DROP is severe and FireHOL alone moderate', async () => {
  const vpn = await lookup('11.0.1.5');
  assert.equal(vpn.isProxy, true);
  assert.equal(vpn.proxyLabel, 'VPN 节点');
  assert.ok(factor(vpn, 'proxy').evidence.some((e) => e.source === 'X4BNet VPN ranges' && e.value === '11.0.1.0 – 11.0.1.255'));

  const drop = await lookup('11.0.2.5');
  assert.equal(drop.threatLabel, 'Spamhaus DROP 网段');
  assert.ok(drop.score <= 29);

  const firehol = await lookup('11.0.3.5');
  assert.equal(firehol.threatLabel, 'FireHOL 攻击来源网段');
  assert.ok(firehol.score <= 49 && firehol.score > 29);

  const clean = await lookup('11.0.9.9');
  assert.equal(clean.isProxy, false);
  assert.ok(clean.reputationChecks.filter((c) => c.kind).every((c) => c.status === 'not_listed'));
});

test('the postcode comes from the source that supplied the displayed city', async () => {
  const same = await lookup('11.0.9.10');
  assert.equal(same.city, 'Dallas');
  assert.equal(same.postalCode, '75244');

  // ipwho.is is down; the city comes from ipquery.io (no postcode), proxycheck.io's postcode belongs to New York
  const other = await lookup('11.0.9.11', {
    'ipwho.is': { success: false, message: 'down' },
    'ipquery.io': { ip: '11.0.9.11', isp: { asn: 'AS7922', isp: 'Comcast Cable' }, location: { country_code: 'US', city: 'Dallas', zipcode: '' }, risk: { is_datacenter: false, is_vpn: false, is_tor: false, is_proxy: false, risk_score: 0 } },
    'proxycheck.io': { status: 'ok', '11.0.9.11': { asn: 'AS7922', provider: 'Comcast Cable', city: 'New York', postcode: '10123', proxy: 'no', type: 'ISP', risk: 0 } },
  });
  assert.equal(other.city, 'Dallas');
  assert.equal(other.postalCode, '—', 'a postcode from a different city is not shown');
});

test('human / bot share comes from Cloudflare Radar for the ASN, only with a token', async () => {
  const calls = [];
  const radar = (body) => (url) => { calls.push(url); return json(body); };
  const run = async (ip, keys, body) => {
    const previous = globalThis.fetch;
    globalThis.fetch = upstream({ 'radar/http/summary/bot_class': radar(body) });
    try {
      const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
      return await lookupIpFull(ip, null, false, keys);
    } finally {
      globalThis.fetch = previous;
    }
  };
  const ok = { success: true, result: { summary_0: { human: '56.9', bot: '43.1' } } };

  const none = await run('11.0.9.20', {}, ok);
  assert.equal(none.asnTraffic, null);
  assert.equal(calls.length, 0, 'no token, no request');

  const shown = await run('11.0.9.21', { radarToken: 't' }, ok);
  assert.deepEqual(shown.asnTraffic, { asn: 7922, human: 56.9, bot: 43.1, dateRange: '7d' });
  assert.match(calls[0], /asn=7922&dateRange=7d/);
  assert.equal(shown.score, (await run('11.0.9.22', {}, ok)).score, 'the share does not change the score');
});

test('a malformed Radar answer is not shown', async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = upstream({ 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', city: 'Dallas', connection: { asn: 6079, isp: 'RCN' }, security: { proxy: false, vpn: false, tor: false, hosting: false } }, 'radar/http/summary/bot_class': { success: true, result: { summary_0: { human: '80', bot: '80' } } } });
  try {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    assert.equal((await lookupIpFull('11.0.9.23', null, false, { radarToken: 't' })).asnTraffic, null);
  } finally {
    globalThis.fetch = previous;
  }
});
