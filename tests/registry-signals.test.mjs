import test from 'node:test';
import assert from 'node:assert/strict';
import { localizeLookup } from '../src/lib/lookup-en.ts';
import { loadTs } from './load-ts.mjs';

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });

async function withFetch(fetcher, fn) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await fn(); } finally { globalThis.fetch = previous; }
}

function upstream(table, calls = {}) {
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

const org = (name, label, kind = 'org') => ({
  roles: ['registrant'],
  vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', name], ['kind', {}, 'text', kind], ...(label ? [['adr', { label }, 'text', ['', '', '', '', '', '', '']]] : [])]],
});

/* 91.108.219.230 的实际登记情况：拉脱维亚公司持有、国家字段写成 US 的段，由 2025 年新注册的 ASN 宣告 */
function leasedRange(ip, overrides = {}) {
  return {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 213541, isp: 'WS Telecom Inc', org: 'WS Telecom Inc' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    internetdb: () => json({ detail: 'No information available' }, 404),
    'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'inetnum', value: '91.108.216.0 - 91.108.219.255' }, { key: 'netname', value: 'DE2207' }, { key: 'country', value: 'US' }]] } },
    'network-info': { data: { prefix: '91.108.216.0/22', asns: ['213541'] } },
    [`rdap.db.ripe.net/ip/${ip}`]: { entities: [org('ipmen', '', 'individual'), org('SIA "Singularity Telecom"', 'Lielais prospekts 6, Jurmala, LV-2010')] },
    'rdap.db.ripe.net/autnum/213541': { entities: [org('WS Telecom Inc', '1309 Coffeen Avenue STE 1200\n82801\nSheridan\nUNITED STATES')], events: [{ eventAction: 'registration', eventDate: '2025-01-21T12:47:04Z' }] },
    peeringdb: { data: [] },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
    ...overrides,
  };
}

test('registrant parsing ignores maintainers and reads the country from the address', async () => {
  const { rdapRegistrant, sameOrganization } = await loadTs('../src/lib/ipcx-lookup.ts');
  assert.deepEqual(rdapRegistrant({ entities: [org('ru-mnt', '', 'individual'), org('SIA "Singularity Telecom"', 'Lielais prospekts 6, Jurmala, LV-2010')] }), { name: 'SIA "Singularity Telecom"', country: 'LV' });
  assert.deepEqual(rdapRegistrant({ entities: [org('Comcast IP Services, L.L.C.', '1800 Bishops Gate Blvd\nMount Laurel\nNJ\n08054\nUnited States')] }), { name: 'Comcast IP Services, L.L.C.', country: 'US' });
  assert.deepEqual(rdapRegistrant({ entities: [org('Hetzner Online GmbH', 'Industriestr. 25\n91710\nGunzenhausen\nGERMANY')] }), { name: 'Hetzner Online GmbH', country: 'DE' });
  assert.deepEqual(rdapRegistrant({ entities: [org('Deutsche Telekom AG', '')] }), { name: 'Deutsche Telekom AG', country: '' });
  assert.equal(rdapRegistrant({ entities: [org('BTNET-MNT', '', 'individual')] }), null);
  assert.equal(rdapRegistrant(null), null);

  assert.equal(sameOrganization('SIA "Singularity Telecom"', 'WS Telecom Inc'), false, 'telecom alone does not make them the same company');
  assert.equal(sameOrganization('Comcast IP Services, L.L.C.', 'Comcast Cable Communications, LLC'), true);
  assert.equal(sameOrganization('Telia Lietuva, AB', 'Telia Lietuva, AB'), true);
  assert.equal(sameOrganization('Telecom Inc', 'Network Services LLC'), null, 'no distinctive words, no verdict');
});

test('a foreign-registered leased range is not native, not residential and not Dual ISP', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const info = await withFetch(upstream(leasedRange('91.108.219.230')), () => lookupIpFull('91.108.219.230'));
  const network = info.factors.find((f) => f.key === 'network');
  const native = info.factors.find((f) => f.key === 'native');
  assert.equal(info.usageType, 'business');
  assert.equal(info.isDualIsp, false);
  assert.equal(info.isNative, false);
  assert.equal(network.status, '商业网络（租用地址段）');
  assert.equal(network.delta, -14);
  assert.ok(network.evidence.some((e) => e.field === 'registrant / ASN holder' && /2025-01-21/.test(e.value)));
  assert.equal(native.status, '登记机构在 LV，与定位不一致');
  assert.equal(native.delta, -6);
  assert.ok(native.evidence.some((e) => e.field === 'registrant' && e.value === 'SIA "Singularity Telecom" (LV)'));

  const en = localizeLookup(info, 'en');
  assert.equal(en.factors.find((f) => f.key === 'network').status, 'Business (leased range)');
  assert.equal(en.factors.find((f) => f.key === 'native').status, 'Registrant based in LV, differs from location');
});

test('a range registered to the ASN holder itself keeps its network type', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const ip = '91.108.219.231';
  const info = await withFetch(upstream(leasedRange(ip, {
    [`rdap.db.ripe.net/ip/${ip}`]: { entities: [org('WS Telecom Inc', '1309 Coffeen Avenue\nSheridan\nUNITED STATES')] },
  })), () => lookupIpFull(ip));
  assert.notEqual(info.factors.find((f) => f.key === 'network').status, '商业网络（租用地址段）');
  assert.equal(info.isNative, true);
});

test('failed sources report why, and an exhausted free quota pauses the source', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const calls = {};
  const table = {
    'ipwho.is': () => json({ success: false }, 429, { 'Retry-After': '120' }),
    'proxycheck.io': { status: 'denied', message: '1,000 free queries exhausted. Please try the API again tomorrow or purchase a higher paid plan.' },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
  };
  const events = async (ip) => {
    const seen = {};
    await withFetch(upstream(table, calls), () => lookupIpFull(ip, null, false, null, { onSource: (e) => { seen[e.id] = e; } }));
    return seen;
  };
  const first = await events('73.170.9.1');
  assert.equal(first.ipwhois.status, 'fail');
  assert.equal(first.ipwhois.detail, 'cooldown (HTTP 429)');
  assert.equal(first.proxycheck.status, 'fail');
  assert.match(first.proxycheck.detail, /^denied: 1,000 free queries exhausted/);

  const second = await events('73.170.9.2');
  assert.equal(calls['ipwho.is'], 1);
  assert.equal(calls['proxycheck.io'], 1, 'no further requests once the quota is gone');
  assert.match(second.proxycheck.detail, /^cooldown \(denied: /);
});

test('an established ASN is only treated as leasing when PeeringDB confirms it is not listed', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const established = (ip, asn, peeringdb) => leasedRange(ip, {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn, isp: 'WS Telecom Inc', org: 'WS Telecom Inc' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    'network-info': { data: { prefix: '91.108.216.0/22', asns: [String(asn)] } },
    [`rdap.db.ripe.net/autnum/${asn}`]: { entities: [org('WS Telecom Inc', 'Sheridan\nUNITED STATES')], events: [{ eventAction: 'registration', eventDate: '2010-03-01T00:00:00Z' }] },
    peeringdb: peeringdb,
  });
  const failed = await withFetch(upstream(established('91.108.219.240', 4200001, () => json({}, 503))), () => lookupIpFull('91.108.219.240'));
  assert.notEqual(failed.factors.find((f) => f.key === 'network').status, '商业网络（租用地址段）', 'a PeeringDB outage is not evidence');

  const missing = await withFetch(upstream(established('91.108.219.241', 4200002, { data: [] })), () => lookupIpFull('91.108.219.241'));
  assert.equal(missing.factors.find((f) => f.key === 'network').status, '商业网络（租用地址段）');
});

test('a single BGP origin ASN wins over a stale upstream ASN', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const ip = '91.108.219.242';
  const info = await withFetch(upstream(leasedRange(ip, {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable', org: 'Comcast Cable' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
  })), () => lookupIpFull(ip));
  assert.equal(info.asn, 213541);
  assert.equal(info.usageType, 'business');
  assert.equal(info.registrantCountry, 'LV');
});

test('curated ASN table entries are keyed by their own ASN', async () => {
  const { KNOWN_ASN_PROFILES } = await loadTs('../src/lib/asn-intelligence.ts');
  const types = new Set(['residential', 'mobile', 'hosting', 'business', 'education', 'cdn', 'reserved']);
  for (const [key, profile] of Object.entries(KNOWN_ASN_PROFILES)) {
    assert.equal(Number(key), profile.asn, `AS${key}`);
    assert.ok(types.has(profile.type), `AS${key} type`);
    assert.match(profile.registeredCountry, /^[A-Z]{2}$/, `AS${key} country`);
  }
  assert.ok(Object.keys(KNOWN_ASN_PROFILES).length >= 240);
});

test('reverse DNS tells a missing PTR apart from a failed lookup', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const ptr = async (ip, rdns) => withFetch(upstream(leasedRange(ip, { 'reverse-dns-ip': rdns })), () => lookupIpFull(ip));

  const found = await ptr('91.108.219.250', { data: { result: ['host.example.net'], error: '' } });
  assert.equal(found.ptrStatus, 'found');
  assert.equal(found.ptrRecord, 'host.example.net');

  const none = await ptr('91.108.219.251', { data: { result: null, error: "Domain name doesn't exist (NXDOMAIN): 251.219.108.91.in-addr.arpa. (PTR)" } });
  assert.equal(none.ptrStatus, 'none');
  assert.equal(none.ptrRecord, '—');

  const failed = await ptr('91.108.219.252', () => json({}, 504));
  assert.equal(failed.ptrStatus, 'failed');

  const servfail = await ptr('91.108.219.253', { data: { result: null, error: 'Server failure (SERVFAIL)' } });
  assert.equal(servfail.ptrStatus, 'failed');
});

test('several keys are used in turn and a rejected or exhausted key is skipped', async () => {
  const { lookupIpFull, splitKeys } = await loadTs('../src/lib/ipcx-lookup.ts');
  assert.deepEqual(splitKeys(' k1, k2\nk3;k1 '), ['k1', 'k2', 'k3']);
  assert.deepEqual(splitKeys(''), []);

  const used = [];
  const table = {
    'proxycheck.io': (url) => {
      const key = new URL(url).searchParams.get('key');
      used.push(key);
      if (key === 'dead') return json({ status: 'denied', message: '1,000 free queries exhausted.' });
      if (key === 'revoked') return json({ status: 'denied', message: 'Invalid API key' }, 401);
      const ip = new URL(url).pathname.split('/').pop();
      return { status: 'ok', [ip]: { asn: 'AS7922', provider: 'Comcast Cable', proxy: 'no', type: 'Residential', risk: 0 } };
    },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
  };
  const run = async (ip) => {
    const seen = {};
    const info = await withFetch(upstream(table), () => lookupIpFull(ip, null, false, { proxycheckKey: 'dead,revoked,good' }, { onSource: (e) => { seen[e.id] = e; } }));
    return { info, event: seen.proxycheck };
  };

  const first = await run('73.170.9.10');
  assert.equal(first.event.status, 'ok');
  assert.deepEqual(used, ['dead', 'revoked', 'good'], 'falls through to the working key');

  used.length = 0;
  const second = await run('73.170.9.11');
  assert.equal(second.event.status, 'ok');
  assert.deepEqual(used, ['good'], 'cooled keys are not tried again');

  const all = await withFetch(upstream({ ...table, 'proxycheck.io': () => json({ status: 'denied', message: 'exhausted' }) }),
    () => lookupIpFull('73.170.9.12', null, false, { proxycheckKey: 'x1,x2' }, { onSource: () => {} }));
  assert.equal(JSON.stringify(all).includes('x1'), false, 'keys never appear in the result');
});
