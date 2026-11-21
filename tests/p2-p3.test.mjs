import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { parseIp, parseCidr, ipv6Groups } from '../src/lib/ip-utils.ts';
import { localizeLookup } from '../src/lib/lookup-en.ts';
import { cardText, ipFontSize } from '../src/lib/card-text.ts';
import { loadTs } from './load-ts.mjs';

async function withFetch(mock, run) {
  const original = globalThis.fetch;
  globalThis.fetch = mock;
  try { return await run(); } finally { globalThis.fetch = original; }
}
const json = (data) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });

test('IPv6 numeric classification agrees across equivalent spellings', () => {
  for (const ip of ['::', '::1', '0:0:0:0:0:0:0:1', 'fe90::1', 'febf::1', 'ff02::1', 'fc00::1', 'fdff::1', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '::ffff:192.0.2.1', '2001:0db8::1', '3fff:fff::1', '100::1', 'fec0::1']) {
    const parsed = parseIp(ip);
    assert.equal(parsed?.isBogon, true, ip);
    assert.equal(parseIp(parsed.normalized).normalized, parsed.normalized);
  }
  for (const ip of ['2606:4700:4700::1111', '::ffff:8.8.8.8', '3fff:1000::1']) assert.equal(parseIp(ip)?.isBogon, false, ip);
  assert.equal(parseIp('2001:0DB8:0000:0000:0001:0000:0000:0001').normalized, '2001:db8::1:0:0:1');
  assert.equal(parseIp('[::1]').normalized, '::1');
  for (const ip of ['[::1', '::1]', '1::2::3', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '::ffff:999.1.1.1', 'fe80::1%eth0', ':::1']) assert.equal(parseIp(ip), null, ip);
});

test('mapped IPv6 preserves the full 128-bit numeric address', () => {
  assert.equal(ipv6Groups('::ffff:192.0.2.1').map((n) => n.toString(16).padStart(4, '0')).join(':'), '0000:0000:0000:0000:0000:ffff:c000:0201');
  assert.equal(parseIp('::ffff:192.0.2.1').normalized, '::ffff:c000:201');
});

test('CIDR syntax is decimal, bounded and consumes the whole input', () => {
  for (const input of ['192.168.1.0/24/garbage', '192.168.1.0/0x10', '1.1.1.1/', '1.1.1.1/-1', '1.1.1.1/+24', '1.1.1.1/33', '1.1.1.1/024', '::1/129', '::1/64abc', '::1/ 64']) assert.equal(parseCidr(input), null, input);
  assert.equal(parseCidr('1.1.1.1/0').prefix, 0);
  assert.equal(parseCidr('::1/128').prefix, 128);
  assert.equal(parseCidr('1.1.1.1').prefix, null);
});

test('Whois sends the requested CIDR to RDAP instead of querying a single IP', async () => {
  const seen = [];
  await withFetch(async (url) => { seen.push(String(url)); return json({ objectClassName: 'ip network', name: 'EXAMPLE', handle: 'EXAMPLE' }); }, async () => {
    const { queryRdap } = await loadTs('../src/lib/rdap-lookup.ts');
    assert.equal((await queryRdap('1.1.1.0/24')).ok, true);
    assert.equal(seen.pop(), 'https://rdap.org/ip/1.1.1.0/24');
    assert.equal((await queryRdap('2606:4700::/32')).ok, true);
    assert.equal(seen.pop(), 'https://rdap.org/ip/2606%3A4700%3A%3A/32');
    assert.equal((await queryRdap('1.1.1.0/0x10')).ok, false);
    assert.equal(seen.length, 0);
    await queryRdap('https://example.com/path');
    assert.equal(seen.pop(), 'https://rdap.org/domain/example.com');
    await queryRdap('AS13335');
    assert.equal(seen.pop(), 'https://rdap.org/autnum/13335');
  });
});

test('WebRTC compares same-family numeric addresses and /64 prefixes only', async () => {
  const context = { window: {}, document: { addEventListener() {} } };
  vm.runInNewContext(await readFile(new URL('../public/assets/js/probe.js', import.meta.url), 'utf8'), context);
  const P = context.window.IpcxProbe;
  assert.equal(P.compareExit('1.1.1.1', ['2606:4700::1']), 'uncompared');
  assert.equal(P.compareExit('1.1.1.1', ['2606:4700::1', '1.1.1.1']), 'match');
  assert.equal(P.compareExit('1.1.1.2', ['1.1.1.1']), 'different');
  assert.equal(P.compareExit('2606:4700:1:2::abcd', ['2606:4700:0001:0002::1234']), 'match');
  assert.equal(P.compareExit('2606:4700:1:3::abcd', ['2606:4700:1:2::1234']), 'different');
  assert.equal(P.sameIp('::ffff:192.0.2.1', '0:0:0:0:0:ffff:c000:201'), true);
  assert.equal(P.compareExit('::ffff:8.8.8.8', ['8.8.8.8']), 'match');
  assert.equal(P.compareExit('bad::ip', ['2606:4700::1']), 'uncompared');
  assert.equal(P.samePrefix64('bad::ip', 'bad::ip'), false);
});

test('status APIs distinguish invalid payloads, maintenance and outages', async () => {
  for (const [body, tone] of [
    [{}, 'muted'], [null, 'muted'], [{ status: { indicator: 'none' }, components: {} }, 'muted'],
    [{ status: { indicator: 'none' }, components: [{ status: 'unknown' }] }, 'muted'],
    [{ status: { indicator: 'none' }, components: [{ status: 'under_maintenance' }] }, 'maint'],
    [{ status: { indicator: 'maintenance' } }, 'maint'],
    [{ status: { indicator: 'none' }, components: [{ status: 'operational' }] }, 'ok'],
    [{ status: { indicator: 'none' }, components: [{ name: 'A', status: 'under_maintenance' }, { name: 'B', status: 'partial_outage' }] }, 'warn'],
    [{ status: { indicator: 'none' }, components: [{ status: 'major_outage' }] }, 'bad'],
  ]) {
    await withFetch(async () => json(body), async () => {
      const { getLiveServiceStatuses } = await loadTs('../src/lib/status-agg.ts');
      const snapshot = await getLiveServiceStatuses();
      const withApi = snapshot.groups.flatMap((g) => g.items).filter((i) => i.summaryApi);
      assert.ok(withApi.length > 10);
      assert.ok(withApi.every((i) => i.tone === tone), JSON.stringify(body));
      if (tone === 'maint') { assert.equal(snapshot.badCount, 0); assert.equal(snapshot.maintCount, withApi.length); }
      if (tone === 'warn') assert.ok(withApi.every((i) => i.note.startsWith('1 个组件异常：B')));
    });
  }
});

test('localized geography uses English source fields without mutating the cache', async () => {
  await withFetch(async (url) => {
    if (String(url).includes('ipwho.is')) { assert.match(String(url), /lang=en/); return json({ success: true, country_code: 'US', region: 'Virginia', city: 'Ashburn' }); }
    if (String(url).includes('ip-api.com')) return json({ status: 'success', countryCode: 'US', regionName: '弗吉尼亚州', city: '阿什本' });
    return json({});
  }, async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const source = await lookupIpFull('8.8.8.8');
    const en = localizeLookup(source, 'en');
    assert.equal(source.region, '弗吉尼亚州');
    assert.equal(en.region, 'Virginia');
    assert.equal(en.city, 'Ashburn');
    assert.equal((await lookupIpFull('8.8.8.8')).city, '阿什本');
    assert.equal(localizeLookup({ ...source, regionEn: undefined, cityEn: undefined }, 'en').city, '—');
  });
});

test('card text preserves long IPs and budgets metadata separately', () => {
  const ip = '2606:4700:1234:5678:abcd:ef01:2345:6789';
  assert.ok(ipFontSize(ip, 476, 30) * ip.length * 0.65 <= 476);
  assert.equal(cardText('上海市'.repeat(30), 60).length, 31);
  assert.equal(cardText('Example', 60), 'Example');
});
