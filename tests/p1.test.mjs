import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verifyTurnstile, TURNSTILE_WIDGETS } from '../src/lib/turnstile.ts';
import { localizeLookup } from '../src/lib/lookup-en.ts';
import { loadTs } from './load-ts.mjs';

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
const secrets = { TURNSTILE_SECRET_KEY_MANAGED: 'mock-managed', TURNSTILE_SECRET_KEY_NON_INTERACTIVE: 'mock-non-interactive' };
const turnstileRequest = (mode = 'mg', extra = {}, form = false) => {
  const body = { mode, token: 'mock-token', action: TURNSTILE_WIDGETS[mode]?.action || '', lang: 'en', ...extra };
  return new Request('https://judgeip.com/cloudflare/turnstile', {
    method: 'POST', headers: { 'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json' },
    body: form ? new URLSearchParams(body) : JSON.stringify(body),
  });
};

async function withFetch(fetcher, fn) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await fn(); } finally { globalThis.fetch = previous; }
}

test('Turnstile uses each mode secret and returns a pass boolean for valid tokens', async () => {
  for (const mode of ['mg', 'ni']) {
    await withFetch(async (url, options) => {
      assert.equal(options.body.get('secret'), secrets[TURNSTILE_WIDGETS[mode].secret]);
      return json({ success: true, hostname: 'judgeip.com', action: TURNSTILE_WIDGETS[mode].action });
    }, async () => {
      const response = await verifyTurnstile(turnstileRequest(mode, {}, mode === 'ni'), secrets);
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.pass, true);
      assert.equal(body.success, true);
      assert.equal(body.hostname_ok, true);
      assert.equal(body.action_ok, true);
      assert.equal(JSON.stringify(body).includes('mock-managed'), false);
    });
  }
});

test('Turnstile rejects missing configuration, mode/action mismatches, invalid tokens and malformed bodies without fetching', async () => {
  await withFetch(() => { throw new Error('should not fetch'); }, async () => {
    assert.equal((await verifyTurnstile(turnstileRequest(), {})).status, 503);
    assert.equal((await verifyTurnstile(turnstileRequest('invalid'), secrets)).status, 400);
    assert.equal((await verifyTurnstile(turnstileRequest('mg', { action: 'cf-test-ni' }), secrets)).status, 400);
    assert.equal((await verifyTurnstile(turnstileRequest('mg', { token: '' }), secrets)).status, 400);
    assert.equal((await verifyTurnstile(turnstileRequest('mg', { token: 'x'.repeat(2049) }), secrets)).status, 400);
    const malformed = new Request('https://judgeip.com/cloudflare/turnstile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: 'null' });
    assert.notEqual((await verifyTurnstile(malformed, secrets)).status, 200);
  });
});

test('Turnstile never passes mismatched, missing, rejected or testing-key verification data', async () => {
  for (const data of [
    { success: false, 'error-codes': ['invalid-input-response'] },
    { success: true, hostname: 'example.com', action: 'cf-test-mg' },
    { success: true, hostname: 'judgeip.com', action: 'cf-test-ni' },
    { success: true },
    { success: true, hostname: 'judgeip.com', action: 'cf-test-mg', metadata: { result_with_testing_key: true } },
  ]) {
    await withFetch(async () => json(data), async () => {
      const response = await verifyTurnstile(turnstileRequest(), secrets);
      assert.equal((await response.json()).pass, false);
    });
  }
});

test('Turnstile distinguishes upstream/configuration failures from rejected tokens', async () => {
  for (const fetcher of [async () => json({}, 500), async () => json({}), async () => { throw new Error('network'); }, async () => json({ success: false, 'error-codes': ['invalid-input-secret'] })]) {
    await withFetch(fetcher, async () => {
      const response = await verifyTurnstile(turnstileRequest(), secrets);
      assert.ok(response.status >= 500);
      assert.equal((await response.json()).ok, false);
    });
  }
});

test('Turnstile parses HTTP 400 secret errors as site configuration failures', async () => {
  for (const mode of ['mg', 'ni']) {
    for (const code of ['invalid-input-secret', 'missing-input-secret']) {
      await withFetch(async () => json({ success: false, 'error-codes': [code] }, 400), async () => {
        const response = await verifyTurnstile(turnstileRequest(mode), secrets);
        const body = await response.json();
        assert.equal(response.status, 503);
        assert.equal(body.ok, false);
        assert.equal(body.error, 'configuration_error');
        assert.deepEqual(body.error_codes, [code]);
        assert.equal(body.upstream_status, 400);
        assert.equal('pass' in body, false);
      });
    }
  }
});

test('Turnstile parses HTTP 400 rejected or expired tokens without claiming upstream failure', async () => {
  for (const code of ['invalid-input-response', 'timeout-or-duplicate']) {
    await withFetch(async () => json({ success: false, 'error-codes': [code] }, 400), async () => {
      const response = await verifyTurnstile(turnstileRequest(), secrets);
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.pass, false);
      assert.equal(body.success, false);
      assert.deepEqual(body.error_codes, [code]);
    });
  }
});

test('Turnstile never trusts success or unrecognized errors on non-2xx responses', async () => {
  for (const [status, data] of [
    [400, { success: true, hostname: 'judgeip.com', action: 'cf-test-mg' }],
    [400, { success: false }],
    [400, { success: false, 'error-codes': ['unrecognized-error'] }],
    [400, { success: false, 'error-codes': ['invalid-input-response', 'unrecognized-error'] }],
    [400, { success: false, 'error-codes': ['invalid-input-response', null] }],
    [400, { success: false, 'error-codes': ['bad-request'] }],
    [400, { success: false, 'error-codes': ['internal-error'] }],
    [500, { success: false, 'error-codes': ['invalid-input-response'] }],
    [429, { success: false, 'error-codes': ['invalid-input-response'] }],
  ]) {
    await withFetch(async () => json(data, status), async () => {
      const response = await verifyTurnstile(turnstileRequest(), secrets);
      const body = await response.json();
      assert.equal(response.status, 502);
      assert.equal(body.ok, false);
      assert.equal('pass' in body, false);
    });
  }
  await withFetch(async () => new Response('<html>Bad request</html>', { status: 400 }), async () => {
    assert.equal((await verifyTurnstile(turnstileRequest(), secrets)).status, 502);
  });
});

function completeUpstream(url) {
  const str = String(url);
  if (str.includes('ipwho.is')) return json({ success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, timezone: { id: 'America/New_York' }, security: { proxy: false, vpn: false, tor: false, hosting: false } });
  if (str.includes('internetdb')) return json({ ports: [], tags: [], vulns: [], hostnames: [] });
  if (str.includes('whois/data')) return json({ data: { authorities: ['ARIN'], records: [[{ key: 'country', value: 'US' }]] } });
  if (str.includes('network-info')) return json({ data: { prefix: '73.162.0.0/16', asns: ['7922'] } });
  if (str.includes('rpki-validation')) return json({ data: { status: 'valid' } });
  if (str.includes('dns-query')) return json({ Status: 3, Authority: [{ type: 6 }] });
  return json({ data: { result: [] } });
}

test('all upstream failures or empty payloads keep score, location, security and DNSBL unknown', async () => {
  for (const fetcher of [async () => { throw new Error('offline'); }, async () => json({})]) {
    await withFetch(fetcher, async () => {
      const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
      const info = await lookupIpFull('8.8.4.4');
      assert.equal(info.score, null);
      assert.equal(info.lookupStatus, 'unavailable');
      assert.equal(info.isProxy, null);
      assert.equal(info.hasThreat, null);
      assert.equal(info.isNative, null);
      assert.equal(info.isDatacenter, null);
      assert.equal(info.countryCode, '');
      assert.equal(info.ipTypeLabel, '未知');
      assert.equal(info.scenes.length, 0);
      assert.ok(info.dnsblChecks.every((c) => c.status === 'unknown'));
      assert.equal(info.riskChecks.some((c) => c.status.includes('全部通过')), false);
      assert.equal('humanPct' in info, false);
      assert.equal('botPct' in info, false);
      assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(localizeLookup(info, 'en'))), false);
    });
  }
});

test('basic feeds without reputation are capped and known threats remain visible', async () => {
  await withFetch(completeUpstream, async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const info = await lookupIpFull('73.162.88.1');
    assert.equal(info.lookupStatus, 'partial');
    assert.equal(info.score, 59);
    assert.equal(info.reputationCoverage, 'unavailable');
    assert.equal(info.isProxy, false);
    assert.equal(info.rpkiStatus, 'valid');
  });
  await withFetch(async (url) => String(url).includes('dns-query') ? json({ Status: 2 }) : completeUpstream(url), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const info = await lookupIpFull('73.162.88.1');
    assert.equal(info.score, null);
    assert.equal(info.lookupStatus, 'partial');
    assert.equal(info.hasThreat, null);
    assert.equal(info.isProxy, false);
  });
  await withFetch(async (url) => String(url).includes('internetdb') ? json({ ports: [1080], tags: ['malware'], vulns: ['CVE-test'] }) : json({}, 503), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const info = await lookupIpFull('73.162.88.1');
    assert.equal(info.score, null);
    assert.equal(info.isProxy, true);
    assert.equal(info.hasThreat, true);
  });
});

test('DNSBL keeps authoritative negatives, listings, provider errors and timeouts distinct', async () => {
  await withFetch(async (url) => {
    if (String(url).includes('spamcop')) return json({ Status: 3, Authority: [{ type: 6 }] });
    if (String(url).includes('dronebl')) return json({ Status: 0, Answer: [{ type: 1, data: '127.0.0.2' }] });
    if (String(url).includes('barracuda')) return json({ Status: 0, Answer: [{ type: 1, data: '127.255.255.254' }] });
    throw new Error('timeout');
  }, async () => {
    const { checkIpv4Dnsbl } = await loadTs('../src/lib/ipcx-lookup.ts');
    assert.deepEqual((await checkIpv4Dnsbl('8.8.8.8')).map((c) => c.status), ['not_listed', 'listed', 'unknown', 'unknown']);
  });
});

test('reserved addresses do not receive public reputation scores', async () => {
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  const info = await lookupIpFull('127.0.0.1');
  assert.equal(info.score, null);
  assert.equal(info.isProxy, null);
  assert.equal(info.hasThreat, null);
});

test('runtime widgets use production keys and no UI or data producer references synthetic ratios', async () => {
  assert.equal(TURNSTILE_WIDGETS.mg.sitekey, '0x4AAAAAAGKTUfiotw71uea9');
  assert.equal(TURNSTILE_WIDGETS.ni.sitekey, '0x4AAAAAAGKTZRRCizCj3kt3');
  for (const file of ['src/lib/ipcx-lookup.ts', 'src/components/IpcxHomeContent.astro', 'src/pages/card.astro', 'public/assets/js/homenet.js']) {
    const text = await readFile(new URL('../' + file, import.meta.url), 'utf8');
    assert.equal(/humanPct|botPct|humanNum|botNum/.test(text), false, file);
  }
});
