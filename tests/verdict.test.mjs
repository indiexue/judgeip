import test from 'node:test';
import assert from 'node:assert/strict';

// Verify core IP parsing, bogon detection, and ASN heuristics via built/TS-compatible Node 24 native TS stripping
import { parseIp } from '../src/lib/ip-utils.ts';
import { classifyIspAndAsn } from '../src/lib/asn-intelligence.ts';

test('parseIp validates public IPv4, private RFC1918, and IPv6 addresses', () => {
  const pubV4 = parseIp('73.162.88.1');
  assert.ok(pubV4);
  assert.equal(pubV4.version, 4);
  assert.equal(pubV4.isBogon, false);

  const privV4 = parseIp('192.168.1.25');
  assert.ok(privV4);
  assert.equal(privV4.isBogon, true);

  const pubV6 = parseIp('2606:4700:4700::1111');
  assert.ok(pubV6);
  assert.equal(pubV6.version, 6);
  assert.equal(pubV6.isBogon, false);

  assert.equal(parseIp('999.999.1.1'), null);
  assert.equal(parseIp('not-an-ip'), null);
});

test('classifyIspAndAsn distinguishes residential, mobile, CDN, and datacenter ASNs', () => {
  assert.equal(classifyIspAndAsn(7922, 'Comcast Cable Communications'), 'residential');
  assert.equal(classifyIspAndAsn(21928, 'T-Mobile USA'), 'mobile');
  assert.equal(classifyIspAndAsn(20473, 'Vultr Holdings LLC'), 'hosting');
  assert.equal(classifyIspAndAsn(13335, 'Cloudflare, Inc.'), 'cdn');
  assert.equal(classifyIspAndAsn(999999, 'Some Random VPS Cloud Hosting Ltd'), 'hosting');
});
