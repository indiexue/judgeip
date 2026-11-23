import test from 'node:test';
import assert from 'node:assert/strict';
import { localizeLookup } from '../src/lib/lookup-en.ts';
import { loadTs } from './load-ts.mjs';

// All upstreams are mocked; enable the optional abuse source in complete-evidence fixtures.
process.env.ABUSEIPDB_KEY = 'fixture-only';
const ipsumFixture = Buffer.alloc(16 + 1000 * 5);
ipsumFixture.write('IPSM');
ipsumFixture.writeDoubleBE(Date.now(), 4);
ipsumFixture.writeUInt32BE(1000, 12);
for (let i = 0; i < 1000; i++) { ipsumFixture.writeUInt32BE(11 * 2 ** 24 + i, 16 + i * 5); ipsumFixture.writeUInt8(1, 20 + i * 5); }

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

async function withFetch(fetcher, fn) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await fn(); } finally { globalThis.fetch = previous; }
}

/* 一个数据齐全的上游；overrides 按 URL 片段替换其中某个来源的应答 */
function upstream(overrides = {}) {
  const base = {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, timezone: { id: 'America/New_York' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    'abuseipdb.com': { data: { abuseConfidenceScore: 0, totalReports: 0 } },
    'judgeip.com/assets/data/ipsum.bin': () => new Response(ipsumFixture),
    internetdb: { ports: [], tags: [], vulns: [], hostnames: [] },
    'whois/data': { data: { authorities: ['ARIN'], records: [[{ key: 'NetRange', value: '73.0.0.0 - 73.255.255.255' }, { key: 'Country', value: 'US' }, { key: 'Comment', value: 'ignored' }]] } },
    'network-info': { data: { prefix: '73.162.0.0/16', asns: ['7922'] } },
    'rpki-validation': { data: { status: 'valid' } },
    'dns-query': { Status: 3, Authority: [{ type: 6 }] },
  };
  const table = { ...base, ...overrides };
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
  return withFetch(upstream(overrides), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    return lookupIpFull(ip);
  });
}

const sum = (info) => info.scoreBase + info.factors.reduce((n, f) => n + f.delta, 0);
const factor = (info, key) => info.factors.find((f) => f.key === key);

test('score factors add up to the displayed score for every network and risk combination', async () => {
  const hosting = { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 16509, isp: 'Amazon.com' }, security: { proxy: false, vpn: false, tor: false, hosting: true } }, 'network-info': { data: { prefix: '3.0.0.0/8', asns: ['16509'] } } };
  const cases = [
    ['residential', {}, 95, {}],
    ['hosting', hosting, 62, { network: -33 }],
    ['non-native', { 'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'country', value: 'DE' }]] } } }, 83, { native: -12 }],
    ['proxy flag', { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, security: { proxy: true, vpn: false, tor: false, hosting: false } } }, 71, { proxy: -24 }],
    ['blocklisted', { 'dns-query': (url) => url.includes('spamcop') ? { Status: 0, Answer: [{ type: 1, data: '127.0.0.2' }] } : { Status: 3, Authority: [{ type: 6 }] } }, 77, { reputation: -18 }],
    ['many ports', { internetdb: { ports: [21, 22, 25, 80, 110, 143, 443], tags: [], vulns: [], hostnames: [] } }, 90, { ports: -5 }],
    ['hosting + non-native + proxy + CVE + ports', { ...hosting, 'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'country', value: 'DE' }]] } }, internetdb: { ports: [21, 22, 25, 80, 110, 143, 443, 1080], tags: ['vpn'], vulns: ['CVE-2024-0001'], hostnames: [] } }, 5, { network: -33, native: -12, proxy: -24, reputation: -18, ports: -5, clamp: 2 }],
  ];
  for (const [name, overrides, expected, deltas] of cases) {
    const info = await lookup('73.162.88.1', overrides);
    assert.equal(info.lookupStatus, 'complete', name);
    assert.equal(info.score, expected, name);
    assert.equal(sum(info), info.score, name);
    for (const f of info.factors) assert.equal(f.delta, deltas[f.key] || 0, `${name}: ${f.key}`);
  }
});

test('each factor carries the raw upstream data it was judged on', async () => {
  const info = await lookup('73.162.88.1', {
    internetdb: { ports: [22, 1080], tags: ['vpn'], vulns: ['CVE-2024-0001'], hostnames: [] },
    'dns-query': (url) => url.includes('dronebl') ? { Status: 0, Answer: [{ type: 1, data: '127.0.0.3' }] } : url.includes('barracuda') ? { Status: 2 } : { Status: 3, Authority: [{ type: 6 }] },
  });
  const has = (key, source, field, value) => factor(info, key).evidence.some((e) => e.source === source && e.field === field && e.value === value);
  assert.ok(has('network', 'ipwho.is', 'connection.asn', '7922'));
  assert.ok(has('network', 'ipwho.is', 'security.hosting', 'false'));
  assert.ok(factor(info, 'network').evidence.some((e) => e.field === 'AS7922'));
  assert.ok(has('native', 'RIPEstat whois', 'NetRange', '73.0.0.0 - 73.255.255.255'));
  assert.ok(has('native', 'RIPEstat whois', 'Country', 'US'));
  assert.equal(factor(info, 'native').evidence.some((e) => e.field === 'Comment'), false);
  assert.ok(has('native', 'ipwho.is', 'country_code', 'US'));
  assert.ok(has('proxy', 'ipwho.is', 'security.proxy', 'false'));
  assert.ok(has('proxy', 'Shodan InternetDB', 'tags', 'vpn'));
  assert.ok(has('proxy', 'Shodan InternetDB', '代理特征端口', '1080'));
  assert.ok(has('reputation', 'DroneBL', '1.88.162.73.dnsbl.dronebl.org', 'A 127.0.0.3'));
  assert.ok(has('reputation', 'SpamCop', '1.88.162.73.bl.spamcop.net', 'NXDOMAIN'));
  assert.ok(has('reputation', 'Barracuda', '1.88.162.73.b.barracudacentral.org', 'SERVFAIL'));
  assert.ok(has('reputation', 'Shodan InternetDB', 'vulns', 'CVE-2024-0001'));
  assert.ok(has('ports', 'Shodan InternetDB', 'ports', '22, 1080'));
  // Barracuda 1 个 DNSBL 未返回时，其余 3 个 DNSBL 与 Shodan 已就绪，仍给出中置信度评分并完整保留扣分项
  assert.equal(info.score, 53);
  assert.equal(info.scoreConfidence, 'medium');
  assert.equal(factor(info, 'proxy').delta, -24);
  assert.equal(factor(info, 'reputation').delta, -18);
});

test('unknown inputs never deduct and reserved addresses have no factors', async () => {
  const offline = await withFetch(async () => { throw new Error('offline'); }, async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    return lookupIpFull('8.8.4.4');
  });
  assert.equal(offline.score, null);
  assert.ok(offline.factors.every((f) => f.delta === 0 && f.tone === 'muted'));
  assert.ok(offline.factors.every((f) => f.evidence.every((e) => e.value)));
  const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
  assert.deepEqual((await lookupIpFull('10.0.0.1')).factors, []);
});

test('English factor text has no Chinese left in it', async () => {
  const info = await lookup('73.162.88.1', {
    'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'country', value: 'DE' }]] } },
    internetdb: { ports: [21, 22, 25, 80, 110, 143, 443, 1080], tags: ['vpn'], vulns: ['CVE-2024-0001'], hostnames: [] },
    'dns-query': (url) => url.includes('spamcop') ? null : { Status: 3, Authority: [{ type: 6 }] },
  });
  const en = localizeLookup(info, 'en');
  assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(en.factors)), false, JSON.stringify(en.factors));
  assert.equal(en.factors[0].label, 'Network type');
  assert.equal(localizeLookup(info, 'zh'), info);
});

test('an IP without a Shodan record is scored as having no open ports', async () => {
  const info = await lookup('8.8.8.8', { internetdb: () => json({ detail: 'No information available' }, 404) });
  assert.equal(info.lookupStatus, 'complete');
  assert.equal(info.portsKnown, true);
  assert.equal(info.score, sum(info));
  assert.deepEqual(factor(info, 'ports').evidence, [{ source: 'Shodan InternetDB', field: 'HTTP 404', value: 'No information available' }]);

  const down = await lookup('8.8.8.8', { internetdb: () => json({}, 503) });
  assert.equal(down.score, null);
  assert.equal(down.portsKnown, false);
});

test('the text report repeats the score, grade and breakdown from the lookup', async () => {
  const { renderTextReport } = await loadTs('../src/lib/text-report.ts');
  const info = await lookup('73.162.88.1', {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 7922, isp: 'Comcast Cable' }, security: { proxy: true, vpn: false, tor: false, hosting: false } },
    internetdb: { ports: [22, 443], tags: [], vulns: [], hostnames: [] },
  });
  const zh = renderTextReport(info, 'zh');
  assert.ok(zh.startsWith('JudgeIP · 73.162.88.1\n'));
  assert.match(zh, /评分 +71 \/ 99 · B\n/);
  assert.match(zh, /开放端口 +22, 443\n/);
  assert.match(zh, /黑名单 +4 个均未列入\n/);
  assert.match(zh, /基础分 +95\n/);
  assert.match(zh, /代理 .* −24\n/);
  assert.match(zh, /最终得分 +B +71\n/);
  assert.ok(zh.endsWith('评分规则  https://judgeip.com/scoring\n'));

  const en = renderTextReport(localizeLookup(info, 'en'), 'en');
  assert.equal(/[\p{Script=Han}]/u.test(en), false, en);
  assert.match(en, /Score +71 \/ 99 · B\n/);
  assert.ok(en.includes('https://judgeip.com/en/ip/73.162.88.1\n'));
  // 标签列按显示宽度对齐：每一行的值都从同一列开始
  const cols = en.split('\n').slice(2, 8).map((line) => line.search(/ {2,}\S/));
  assert.ok(cols.every((c) => c > 0));
});

test('the text report shows medium confidence on IPv6 / partial DNSBL and keeps reserved addresses short', async () => {
  const { renderTextReport } = await loadTs('../src/lib/text-report.ts');
  const v6 = renderTextReport(await lookup('2400:3200::1'), 'zh');
  assert.match(v6, /评分 +79 \/ 99 · B · 置信度中\n/);
  assert.match(v6, /网络类型 +家庭宽带 · 双 ISP\n/);
  assert.match(v6, /开放端口 +仅支持 IPv4\n/);
  assert.match(v6, /黑名单 +仅支持 IPv4\n/);

  const partial = renderTextReport(await lookup('8.8.8.8', { 'dns-query': (url) => url.includes('spamcop') ? json({}, 500) : { Status: 3, Authority: [{ type: 6 }] } }), 'zh');
  assert.match(partial, /评分 +79 \/ 99 · B · 置信度中\n/);
  assert.match(partial, /黑名单 +3\/4 个有答复，均未列入\n/);

  const totalDown = renderTextReport(await withFetch(async () => json({}, 503), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    return lookupIpFull('8.8.4.4');
  }), 'zh');
  assert.match(totalDown, /评分 +未出分（基础归属或风险数据源未返回）\n/);
  assert.match(totalDown, /最终得分 +未出分 +—\n/);

  const bogon = renderTextReport(await lookup('192.168.1.1'), 'zh');
  assert.equal(bogon.includes('评分'), false);
  assert.equal(bogon.trimEnd().split('\n').length, 6);
});

test('the rate limiter counts per source and resets after a minute', async () => {
  const { rateLimit, rateHeaders, rateKey, RATE_LIMITS } = await loadTs('../src/lib/rate-limit.ts');
  const t0 = 1_000_000;
  for (let i = 1; i <= RATE_LIMITS.report; i += 1) {
    const r = rateLimit('report', '203.0.113.7', t0 + i);
    assert.equal(r.ok, true);
    assert.equal(r.remaining, RATE_LIMITS.report - i);
  }
  const blocked = rateLimit('report', '203.0.113.7', t0 + 30_001);
  assert.equal(blocked.ok, false);
  assert.equal(blocked.remaining, 0);
  assert.deepEqual(rateHeaders(blocked), { 'RateLimit-Limit': '30', 'RateLimit-Remaining': '0', 'RateLimit-Reset': '30', 'Retry-After': '30' });
  // 其他来源、其他接口各自计数
  assert.equal(rateLimit('report', '203.0.113.8', t0 + 30_000).ok, true);
  assert.equal(rateLimit('api', '203.0.113.7', t0 + 30_000).ok, true);
  // 窗口过后重新计数
  const fresh = rateLimit('report', '203.0.113.7', t0 + 60_001);
  assert.equal(fresh.ok, true);
  assert.equal('Retry-After' in rateHeaders(fresh), false);

  assert.equal(rateKey('2001:db8:1:2:aaaa::1'), rateKey('2001:db8:1:2:bbbb::2'));
  assert.notEqual(rateKey('2001:db8:1:2::1'), rateKey('2001:db8:1:3::1'));
  assert.equal(rateKey('203.0.113.7'), '203.0.113.7');
});

// 惰性求值：查询会临时替换全局 fetch，不能在模块加载时与别的用例并行
let sampleInfo;
const sample = () => (sampleInfo ??= lookup('73.162.88.1', { internetdb: { ports: [22, 443], tags: [], vulns: [], hostnames: [] } }));

async function mcp(message, overrides = {}) {
  const { handleMcpMessage } = await loadTs('../src/lib/mcp.ts');
  const info = await sample();
  const seen = [];
  const ctx = { clientIp: '198.51.100.9', lookup: async (ip) => { seen.push(ip); return { ...info, ip }; }, ...overrides };
  return { answer: await handleMcpMessage(message, ctx), seen };
}

test('the MCP server negotiates a version, lists tools and ignores notifications', async () => {
  const init = (await mcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } })).answer;
  assert.equal(init.result.protocolVersion, '2025-03-26');
  assert.deepEqual(init.result.capabilities, { tools: {} });
  assert.equal(init.result.serverInfo.name, 'judgeip');
  const future = (await mcp({ jsonrpc: '2.0', id: 'a', method: 'initialize', params: { protocolVersion: '2099-01-01' } })).answer;
  assert.equal(future.result.protocolVersion, '2025-11-25');
  assert.equal(future.id, 'a');

  assert.equal((await mcp({ jsonrpc: '2.0', method: 'notifications/initialized' })).answer, null);
  assert.deepEqual((await mcp({ jsonrpc: '2.0', id: 2, method: 'ping' })).answer, { jsonrpc: '2.0', id: 2, result: {} });

  const tools = (await mcp({ jsonrpc: '2.0', id: 3, method: 'tools/list' })).answer.result.tools;
  assert.deepEqual(tools.map((tool) => tool.name), ['check_ip', 'compare_ips', 'scoring_rules']);
  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, 'object');
    assert.ok(tool.description.length > 40);
  }

  assert.equal((await mcp({ jsonrpc: '2.0', id: 4, method: 'resources/list' })).answer.error.code, -32601);
  assert.equal((await mcp({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'nope' } })).answer.error.code, -32602);
  assert.equal((await mcp([])).answer.error.code, -32600);
  assert.equal((await mcp({ id: 6, method: 'ping' })).answer.error.code, -32600);
});

test('MCP tools return the same report text as the curl endpoint', async () => {
  const { renderTextReport } = await loadTs('../src/lib/text-report.ts');
  const info = await sample();
  const call = (name, args, overrides) => mcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, overrides);

  const one = await call('check_ip', { ip: '73.162.88.1' });
  assert.deepEqual(one.seen, ['73.162.88.1']);
  assert.equal(one.answer.result.isError, undefined);
  assert.equal(one.answer.result.content[0].text, renderTextReport(localizeLookup(info, 'en'), 'en'));
  assert.equal((await call('check_ip', { ip: '73.162.88.1', lang: 'zh' })).answer.result.content[0].text, renderTextReport(info, 'zh'));

  // 不带 ip 时查发起请求的地址
  assert.deepEqual((await call('check_ip', {})).seen, ['198.51.100.9']);

  const many = await call('compare_ips', { ips: ['73.162.88.1', '73.162.88.2', '73.162.88.1'] });
  assert.deepEqual(many.seen, ['73.162.88.1', '73.162.88.2']);
  const text = many.answer.result.content[0].text;
  assert.equal(/[\p{Script=Han}]/u.test(text), false, text);
  assert.match(text, /^73\.162\.88\.1\n  Score: 95 \/ 99 · A\+\n/);
  assert.match(text, /\n\n73\.162\.88\.2\n/);
  assert.match(text, /Adjustments: none\n/);

  for (const [name, args] of [['check_ip', { ip: 'not-an-ip' }], ['compare_ips', { ips: ['8.8.8.8'] }], ['compare_ips', { ips: ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'] }], ['compare_ips', { ips: 'x' }]]) {
    const bad = await call(name, args);
    assert.equal(bad.answer.result.isError, true, JSON.stringify(args));
    assert.deepEqual(bad.seen, []);
  }

  const failed = await call('check_ip', { ip: '8.8.8.8' }, { lookup: async () => { throw new Error('upstream'); } });
  assert.equal(failed.answer.result.isError, true);

  const rules = (await call('scoring_rules', { lang: 'en' })).answer.result.content[0].text;
  assert.equal(/[\p{Script=Han}]/u.test(rules), false);
  assert.match(rules, /starts at 95/);
  assert.match(rules, /−33 {2}Data center/);
  assert.match((await call('scoring_rules', { lang: 'zh' })).answer.result.content[0].text, /从 95 分起算/);
});

test('MCP lookups are rate limited per caller and counted per IP looked up', async () => {
  const { handleMcpMessage } = await loadTs('../src/lib/mcp.ts');
  const { RATE_LIMITS } = await loadTs('../src/lib/rate-limit.ts');
  const info = await sample();
  const ctx = { clientIp: '198.51.100.77', lookup: async (ip) => ({ ...info, ip }) };
  const call = (name, args) => handleMcpMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, ctx);
  for (let i = 0; i < RATE_LIMITS.mcp - 2; i += 1) assert.equal((await call('check_ip', { ip: '73.162.88.1' })).result.isError, undefined);
  assert.equal((await call('compare_ips', { ips: ['73.162.88.1', '73.162.88.2'] })).result.isError, undefined);
  const blocked = await call('check_ip', { ip: '73.162.88.1' });
  assert.equal(blocked.result.isError, true);
  assert.match(blocked.result.content[0].text, /Rate limit reached \(30 lookups per minute\)/);
  // 不查上游的工具不受限
  assert.equal((await call('scoring_rules', {})).result.isError, undefined);
});

test('the API docs sample adds up and renders without Chinese in English', async () => {
  const { SAMPLE_REPORT } = await loadTs('../src/lib/sample-report.ts');
  const { renderTextReport } = await loadTs('../src/lib/text-report.ts');
  const { SCORE_GRADES } = await loadTs('../src/lib/score-rules.ts');

  assert.equal(SAMPLE_REPORT.scoreBase + SAMPLE_REPORT.factors.reduce((a, f) => a + f.delta, 0), SAMPLE_REPORT.score);
  assert.equal(SCORE_GRADES.find((g) => SAMPLE_REPORT.score >= g.min).grade, SAMPLE_REPORT.grade);

  const en = localizeLookup(SAMPLE_REPORT, 'en');
  assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(en)), false, JSON.stringify(en));
  const text = renderTextReport(en, 'en');
  assert.equal(/[\p{Script=Han}]/u.test(text), false, text);
  assert.match(text, /^Score +38 \/ 99 · D · low confidence$/m);
});

test('platform verdicts follow the published thresholds and requirements', async () => {
  const { PLATFORMS, judgePlatform, judgePlatforms } = await loadTs('../src/lib/platforms.ts');
  const of = (id) => PLATFORMS.find((p) => p.id === id);
  const home = { isBogon: false, usageType: 'residential', isNative: true, isProxy: false, hasThreat: false, score: 95 };
  const zh = (verdict) => verdict.reasons.map((r) => r.zh);

  for (const platform of PLATFORMS) assert.deepEqual(judgePlatform(platform, home), { level: 'pass', reasons: [] }, platform.id);

  const hosting = judgePlatform(of('paypal'), { ...home, usageType: 'hosting', score: 62 });
  assert.equal(hosting.level, 'fail');
  assert.deepEqual(zh(hosting), ['数据中心 IP', '评分 62，低于门槛 75']);
  /* 不要求住宅的平台只看门槛：62 过得了 Shopify（60），过不了 Temu（65） */
  assert.equal(judgePlatform(of('shopify'), { ...home, usageType: 'hosting', score: 62 }).level, 'pass');
  assert.equal(judgePlatform(of('temu'), { ...home, usageType: 'hosting', score: 62 }).level, 'fail');

  assert.deepEqual(zh(judgePlatform(of('x'), { ...home, isProxy: true, score: 71 })), ['被标记为代理 / VPN / Tor']);
  assert.equal(judgePlatform(of('x'), { ...home, hasThreat: true, score: 77 }).level, 'pass');
  assert.equal(judgePlatform(of('reddit'), { ...home, hasThreat: true, score: 77 }).level, 'fail');

  const broadcast = judgePlatform(of('stripe'), { ...home, isNative: false, score: 83 });
  assert.equal(broadcast.level, 'warn');
  assert.deepEqual(zh(broadcast), ['广播 IP，注册地与定位不一致']);
  assert.equal(judgePlatform(of('upwork'), { ...home, usageType: 'business' }).level, 'warn');
  assert.equal(judgePlatform(of('toptal'), { ...home, usageType: 'business' }).level, 'pass');

  /* 缺数据是「无法判断」，不当作正常；已经有一项不满足时仍然是不达标 */
  const noScore = judgePlatform(of('wise'), { ...home, hasThreat: null, score: null });
  assert.equal(noScore.level, 'unknown');
  assert.deepEqual(zh(noScore), ['黑名单没查全', '没有评分']);
  assert.equal(judgePlatform(of('wise'), { ...home, isProxy: true, hasThreat: null, score: null }).level, 'fail');
  assert.equal(judgePlatform(of('paypal'), { ...home, isBogon: true, usageType: 'reserved', score: null }).level, 'unknown');

  const english = judgePlatforms({ ...home, usageType: 'hosting', isNative: false, isProxy: true, hasThreat: true, score: 5 }, 'en');
  assert.equal(english.length, PLATFORMS.length);
  assert.ok(english.every((v) => v.level === 'fail' && v.label === 'Below the bar' && v.reasons.length > 0));
  assert.ok(!/[\p{Script=Han}]/u.test(JSON.stringify(english)));
});

test('the platform table is consistent and only probes hosts with a readable trace', async () => {
  const { PLATFORMS, PLATFORM_CATEGORIES } = await loadTs('../src/lib/platforms.ts');
  const { SCORE_MIN, SCORE_MAX } = await loadTs('../src/lib/score-rules.ts');
  /* 2026-11 逐个核对过：/cdn-cgi/trace 可读且带 Access-Control-Allow-Origin: * */
  const readable = ['wise.com', 'www.revolut.com', 'payoneer.com', 'www.airwallex.com', 'www.temu.com', 'www.shopify.com', 'www.upwork.com', 'www.fiverr.com', 'www.toptal.com', 'www.linkedin.com', 'www.patreon.com', 'x.com', 'www.quora.com'];
  const categories = PLATFORM_CATEGORIES.map((c) => c.key);

  assert.equal(new Set(PLATFORMS.map((p) => p.id)).size, PLATFORMS.length);
  assert.deepEqual(PLATFORMS.map((p) => p.traceHost).filter(Boolean).sort(), [...readable].sort());
  for (const platform of PLATFORMS) {
    assert.ok(categories.includes(platform.category), platform.id);
    assert.ok(platform.minScore > SCORE_MIN && platform.minScore < SCORE_MAX, platform.id);
    assert.ok(platform.requires.length > 0 && new Set(platform.requires).size === platform.requires.length, platform.id);
  }
  for (const key of categories) assert.ok(PLATFORMS.some((p) => p.category === key), key);
});

test('a detection page resolves ?ip= to a target and falls back to the visitor', async () => {
  const { resolveQueryTarget } = await loadTs('../src/lib/query-target.ts');
  const at = (query, lang = 'zh') => resolveQueryTarget(new Request('https://judgeip.com/platforms', { headers: { 'CF-Connecting-IP': '73.162.88.1' } }), new URL(`https://judgeip.com/platforms${query}`), lang);

  assert.deepEqual({ ...at(''), cfMeta: null }, { visitorIp: '73.162.88.1', targetIp: '73.162.88.1', isSelf: true, queryValue: '', errorMsg: '', cfMeta: null });
  assert.equal(at('?ip=8.8.8.8').targetIp, '8.8.8.8');
  assert.equal(at('?ip=8.8.8.8').isSelf, false);
  assert.equal(at('?ip=73.162.88.1').isSelf, true);
  assert.equal(at('?ip=%208.8.4.4%20').queryValue, '8.8.4.4');

  const bad = at('?ip=not-an-ip');
  assert.equal(bad.targetIp, '73.162.88.1');
  assert.equal(bad.isSelf, true);
  assert.equal(bad.queryValue, 'not-an-ip');
  assert.match(bad.errorMsg, /「not-an-ip」不是有效的/);
  assert.ok(!/[\p{Script=Han}]/u.test(at('?ip=not-an-ip', 'en').errorMsg));
});

test('scenario weights add up to 100 and the levels follow the published rule', async () => {
  const { SCENARIOS, SCENARIO_FAIL_BELOW, CHECK_LABELS, CHECK_BASIS, evaluateScenario, scenarioById, scoreScenario } = await loadTs('../src/lib/scenario-profiles.ts');
  const home = { isBogon: false, usageType: 'residential', isNative: true, rirCountry: 'US', countryCode: 'US', isProxy: false, hasThreat: false, portsKnown: true, openPorts: [] };
  const run = (id, facts) => evaluateScenario(scenarioById(id), { ...home, ...facts });
  const statuses = (result) => Object.fromEntries(result.items.map((item) => [item.check, item.status]));

  assert.deepEqual(SCENARIOS.map((s) => s.path), ['/native-ip', '/residential-ip', '/tiktok-ip']);
  for (const scenario of SCENARIOS) {
    assert.equal(scenario.items.reduce((n, item) => n + item.weight, 0), 100, scenario.id);
    assert.equal(new Set(scenario.items.map((item) => item.check)).size, scenario.items.length, scenario.id);
    for (const item of scenario.items) assert.ok(CHECK_LABELS[item.check] && CHECK_BASIS[item.check], item.check);
    const clean = evaluateScenario(scenario, home);
    assert.deepEqual([clean.total, clean.level], [100, 'pass'], scenario.id);
    assert.ok(clean.items.every((item) => item.earned === item.weight));
  }

  /* 定义项不过，总分一定在及格线以下 */
  const broadcast = run('native-ip', { isNative: false, rirCountry: 'DE' });
  assert.deepEqual([broadcast.total, broadcast.level], [40, 'fail']);
  assert.equal(broadcast.items[0].detail.zh, '注册 DE，定位 US，是广播 IP');
  assert.deepEqual([run('residential-ip', { usageType: 'hosting' }).total, run('residential-ip', { usageType: 'hosting' }).level], [40, 'fail']);
  assert.deepEqual([run('tiktok-ip', { usageType: 'hosting' }).total, run('tiktok-ip', { usageType: 'hosting' }).level], [55, 'fail']);
  assert.ok(40 < SCENARIO_FAIL_BELOW && 55 < SCENARIO_FAIL_BELOW);

  /* 次要项不过是部分符合；企业、教育网络拿一半 */
  assert.deepEqual([run('native-ip', { usageType: 'cdn', isNative: false }).total, run('native-ip', { usageType: 'cdn', isNative: false }).level], [75, 'warn']);
  assert.deepEqual([run('native-ip', { isProxy: true }).total, run('native-ip', { isProxy: true }).level], [85, 'warn']);
  const business = run('residential-ip', { usageType: 'business' });
  assert.deepEqual([business.total, business.level, business.items[0].status, business.items[0].earned], [70, 'warn', 'partial', 30]);
  assert.equal(run('residential-ip', { usageType: 'mobile' }).level, 'pass');
  assert.equal(run('residential-ip', { openPorts: [1, 2, 3, 4, 5, 6] }).total, 100);
  assert.equal(run('residential-ip', { openPorts: [1, 2, 3, 4, 5, 6, 7] }).total, 90);
  assert.deepEqual([run('tiktok-ip', { isNative: false, rirCountry: 'DE' }).total, run('tiktok-ip', { isProxy: true, hasThreat: true }).total], [75, 70]);
  assert.equal(run('tiktok-ip', { usageType: 'education' }).total, 78);

  /* 缺数据不出总分，也不当作通过；缺的项全算通过也不及格时仍是不符合 */
  const v6 = run('residential-ip', { hasThreat: null, portsKnown: false });
  assert.deepEqual([v6.total, v6.level], [null, 'unknown']);
  assert.deepEqual(statuses(v6), { residential: 'pass', noProxy: 'pass', clean: 'unknown', fewPorts: 'unknown' });
  const v6Hosting = run('residential-ip', { usageType: 'hosting', hasThreat: null, portsKnown: false });
  assert.deepEqual([v6Hosting.total, v6Hosting.level], [null, 'fail']);
  assert.equal(run('native-ip', { rirCountry: '', isNative: null }).level, 'unknown');
  assert.equal(run('native-ip', { usageType: 'unknown' }).level, 'unknown');
  assert.equal(run('tiktok-ip', { isProxy: null }).level, 'unknown');
  const bogon = run('tiktok-ip', { isBogon: true, usageType: 'reserved' });
  assert.deepEqual([bogon.total, bogon.level], [null, 'unknown']);
  assert.ok(bogon.items.every((item) => item.status === 'unknown' && item.earned === 0));

  const worst = { ...home, usageType: 'hosting', isNative: false, rirCountry: 'DE', isProxy: true, hasThreat: true, openPorts: [1, 2, 3, 4, 5, 6, 7] };
  for (const scenario of SCENARIOS) {
    for (const facts of [home, worst, { ...home, usageType: 'business' }, { ...home, usageType: 'cdn', isNative: false }, { ...home, usageType: 'unknown', isNative: null, isProxy: null, hasThreat: null, portsKnown: false }, { ...home, isBogon: true }]) {
      const english = scoreScenario(scenario.id, facts, 'en');
      assert.ok(!/[\p{Script=Han}]/u.test(JSON.stringify(english)), scenario.id);
      assert.equal(english.items.length, scenario.items.length);
    }
  }
  /* 机房不是 CDN，原生 IP 那张表里只剩这一项的 25 分 */
  assert.equal(scoreScenario('native-ip', worst, 'zh').label, '不符合');
  assert.equal(scoreScenario('native-ip', worst, 'zh').total, 25);
  assert.equal(scoreScenario('residential-ip', worst, 'zh').total, 0);
});

test('scenario verdicts come from the same lookup fields the home page shows', async () => {
  const { scoreScenario } = await loadTs('../src/lib/scenario-profiles.ts');
  const hosting = { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 16509, isp: 'Amazon.com' }, security: { proxy: false, vpn: false, tor: false, hosting: true } }, 'network-info': { data: { prefix: '3.0.0.0/8', asns: ['16509'] } } };
  const home = await lookup('73.162.88.1');
  for (const id of ['native-ip', 'residential-ip', 'tiktok-ip']) assert.deepEqual([scoreScenario(id, home, 'zh').total, scoreScenario(id, home, 'zh').level], [100, 'pass'], id);
  const cloud = await lookup('73.162.88.1', hosting);
  assert.equal(scoreScenario('native-ip', cloud, 'zh').total, 100);
  assert.deepEqual([scoreScenario('residential-ip', cloud, 'zh').total, scoreScenario('tiktok-ip', cloud, 'zh').total], [40, 55]);
  const foreign = await lookup('73.162.88.1', { 'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'country', value: 'DE' }]] } } });
  assert.deepEqual([scoreScenario('native-ip', foreign, 'zh').level, scoreScenario('tiktok-ip', foreign, 'zh').total], ['fail', 75]);
  const localized = scoreScenario('tiktok-ip', localizeLookup(foreign, 'en'), 'en');
  assert.equal(localized.total, 75);
  assert.equal(scoreScenario('tiktok-ip', await lookup('192.168.1.1'), 'zh').level, 'unknown');
});

test('the compare list accepts mixed separators, drops duplicates and caps the count', async () => {
  const { parseCompareList, COMPARE_MAX } = await loadTs('../src/lib/compare.ts');
  assert.deepEqual(parseCompareList('8.8.8.8, 1.1.1.1；9.9.9.9、4.4.4.4\n208.67.222.222'), { ips: ['8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4', '208.67.222.222'], invalid: [], dropped: 0 });
  assert.deepEqual(parseCompareList(' 8.8.8.8  8.8.8.8,008.8.8.8 ').ips.slice(0, 1), ['8.8.8.8']);
  assert.deepEqual(parseCompareList('2001:4860:4860:0:0:0:0:8888 [2001:4860:4860::8888] 2001:4860:4860::8888').ips, ['2001:4860:4860::8888']);
  assert.deepEqual(parseCompareList('8.8.8.8,abc,999.1.1.1'), { ips: ['8.8.8.8'], invalid: ['abc', '999.1.1.1'], dropped: 0 });
  const many = parseCompareList(Array.from({ length: 9 }, (_, i) => `8.8.8.${i + 1}`).join(','));
  assert.equal(many.ips.length, COMPARE_MAX);
  assert.equal(many.dropped, 9 - COMPARE_MAX);
  assert.equal(parseCompareList('x'.repeat(200)).invalid[0].length, 60);
  for (const empty of [null, undefined, '', ' , ，']) assert.deepEqual(parseCompareList(empty), { ips: [], invalid: [], dropped: 0 });
  /* 保留地址是有效输入，对比表里显示为保留地址 */
  assert.deepEqual(parseCompareList('192.168.1.1').ips, ['192.168.1.1']);
});

test('a compare column carries the same score, factors and labels as the lookup', async () => {
  const { compareColumn, COMPARE_FIELDS } = await loadTs('../src/lib/compare.ts');
  const { formatDelta, SCORE_BASE } = await loadTs('../src/lib/score-rules.ts');
  const fields = COMPARE_FIELDS.map((row) => row.field).sort();
  const hosting = { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 16509, isp: 'Amazon.com' }, security: { proxy: false, vpn: false, tor: false, hosting: true } }, 'network-info': { data: { prefix: '3.0.0.0/8', asns: ['16509'] } } };

  const home = await lookup('73.162.88.1');
  const column = compareColumn(home, 'zh');
  assert.deepEqual(Object.keys(column.cells).sort(), fields);
  assert.deepEqual([column.ip, column.score, column.grade, column.base], [home.ip, home.score, home.grade, SCORE_BASE]);
  assert.deepEqual(column.cells.score, { text: `${home.score} / 99`, tone: 'ok', sub: `等级 ${home.grade}` });
  assert.deepEqual(column.cells.type, { text: home.ipTypeLabel, tone: 'ok', sub: '双 ISP' });
  assert.deepEqual(column.cells.native, { text: '是', tone: 'ok', sub: '注册 US · 定位 US' });
  assert.deepEqual([column.cells.proxy.tone, column.cells.threat.tone, column.cells.blocklists.tone], ['ok', 'ok', undefined]);
  assert.deepEqual(column.factors.map((f) => [f.key, f.delta, f.deltaText]), home.factors.map((f) => [f.key, f.delta, formatDelta(f.delta)]));
  assert.equal(column.base + column.factors.reduce((total, f) => total + f.delta, 0), home.score);

  const cloud = compareColumn(await lookup('73.162.88.1', hosting), 'zh');
  assert.deepEqual([cloud.cells.type.tone, cloud.factors.find((f) => f.key === 'network').deltaText], ['leak', '−33']);
  assert.ok(cloud.score < column.score);
  const foreign = compareColumn(await lookup('73.162.88.1', { 'whois/data': { data: { authorities: ['RIPE'], records: [[{ key: 'country', value: 'DE' }]] } } }), 'zh');
  assert.deepEqual(foreign.cells.native, { text: '否', tone: 'warn', sub: '注册 DE · 定位 US' });
  assert.equal(foreign.cells.registry.sub, '注册国家 DE');

  const v6 = compareColumn(await lookup('2001:4860:4860::8888'), 'zh');
  assert.deepEqual([v6.score, v6.cells.score.text, v6.cells.score.tone], [79, '79 / 99', 'ok']);
  assert.match(v6.cells.score.sub, /置信度中/);
  assert.ok(v6.factors.length > 0);

  const bogon = compareColumn(await lookup('192.168.1.1'), 'zh');
  assert.deepEqual([bogon.score, bogon.factors.length, bogon.cells.type.text, bogon.cells.native.text], [null, 0, '保留地址', '—']);
  assert.deepEqual(Object.keys(bogon.cells).sort(), fields);

  for (const info of [home, await lookup('73.162.88.1', hosting), await lookup('2001:4860:4860::8888'), await lookup('192.168.1.1')]) {
    const english = compareColumn(localizeLookup(info, 'en'), 'en');
    assert.ok(!/[\p{Script=Han}]/u.test(JSON.stringify(english)), info.ip);
    assert.equal(english.score, info.score);
  }
  assert.ok(COMPARE_FIELDS.every((row) => row.label.zh && row.label.en && !/[\p{Script=Han}]/u.test(row.label.en)));
});

test('RDAP and RIPEstat RIR allocation fallbacks recover score when RIPEstat whois times out', async () => {
  const fromRdap = await lookup('73.162.88.1', {
    'whois/data': () => json({}, 504),
    'rdap.org/ip/': {
      port43: 'whois.arin.net',
      name: 'BAYAREA-CPE-43',
      startAddress: '73.162.0.0',
      endAddress: '73.162.255.255',
      entities: [{ vcardArray: ['vcard', [['adr', { label: '1800 Bishops Gate Blvd\nMount Laurel\nNJ\n08054\nUnited States' }, 'text', []]]] }],
    },
  });
  assert.equal(fromRdap.lookupStatus, 'complete');
  assert.equal(fromRdap.score, 95);
  assert.equal(fromRdap.rirName, 'ARIN');
  assert.equal(fromRdap.rirCountry, 'US');
  assert.equal(fromRdap.isNative, true);
  assert.ok(factor(fromRdap, 'native').evidence.some((e) => e.source === 'RDAP' && e.value === 'US'));

  const fromRirAlloc = await lookup('73.162.88.1', {
    'whois/data': () => json({}, 504),
    'rdap.org/ip/': () => json({}, 502),
    'rir/data': { data: { rirs: [{ rir: 'ARIN', country: 'US', resource: '73.0.0.0/8' }] } },
  });
  assert.equal(fromRirAlloc.lookupStatus, 'complete');
  assert.equal(fromRirAlloc.score, 95);
  assert.equal(fromRirAlloc.rirCountry, 'US');
  assert.ok(factor(fromRirAlloc, 'native').evidence.some((e) => e.source === 'RIPEstat rir' && e.value === 'US'));
});

test('commercial networks like 154.12.35.2, PeeringDB types, proxycheck VPN flags, Dual-ISP, and Plan B optional keys score accurately', async () => {
  // 1. 154.12.35.2 (AS979 NetLab Global) + proxycheck VPN flag -> scores 65 (95 - 6 business - 24 VPN), never null!
  const netlab = await lookup('154.12.35.2', {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 979, isp: 'NetLab Global', org: 'NetLab Global' }, timezone: { id: 'America/Los_Angeles' }, security: { proxy: false, vpn: false, tor: false, hosting: false } },
    'proxycheck.io': { status: 'ok', '154.12.35.2': { asn: 'AS979', provider: 'NetLab Global', proxy: 'yes', type: 'VPN', risk: 66 } },
    internetdb: { ports: [111, 443, 2080], tags: [], vulns: [], hostnames: [] },
  });
  assert.equal(netlab.usageType, 'business');
  assert.equal(netlab.ipTypeLabel, '商业网络');
  assert.equal(netlab.isDualIsp, false);
  assert.equal(netlab.isProxy, true);
  assert.equal(netlab.proxyLabel, 'VPN 节点');
  assert.equal(netlab.score, 65);
  assert.equal(netlab.scoreConfidence, 'high');
  assert.ok(netlab.scenes.length === 8);

  // 2. Unlisted ASN classified via PeeringDB + clean ipquery -> business 89 (95 - 6)
  const regional = await lookup('154.16.10.25', {
    'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 64555, isp: 'Acme Regional Net', org: 'Acme Corp' } },
    'peeringdb.com': { data: [{ name: 'ACME-NET', info_type: 'Enterprise' }] },
    'ipquery.io': { ip: '154.16.10.25', isp: { asn: 'AS64555', org: 'Acme Corp', isp: 'Acme Regional Net' }, location: { country_code: 'US' }, risk: { is_datacenter: false, is_vpn: false, is_tor: false, is_proxy: false, risk_score: 0 } },
  });
  assert.equal(regional.usageType, 'business');
  assert.equal(regional.score, 89);
  assert.ok(factor(regional, 'network').evidence.some((e) => e.source === 'PeeringDB'));

  // 3. Plan B optional keys (ipapi.is Dual-ISP + AbuseIPDB high abuse confidence)
  await withFetch(upstream({
    'api.ipapi.is': {
      ip: '73.162.88.9',
      is_datacenter: false,
      is_proxy: false,
      is_vpn: false,
      company: { name: 'Comcast Cable', type: 'isp', abuser_score: '0.001 (Very Low)' },
      asn: { asn: 7922, org: 'Comcast Cable', type: 'isp', country: 'US' },
      location: { country_code: 'US' },
    },
    'abuseipdb.com': { data: { abuseConfidenceScore: 80, totalReports: 14, isp: 'Comcast Cable' } },
  }), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const enriched = await lookupIpFull('73.162.88.9', null, false, { ipapiIsKey: 'k1', abuseIpdbKey: 'k2' });
    assert.equal(enriched.isDualIsp, true);
    assert.equal(enriched.hasThreat, true);
    assert.equal(enriched.score, 29); // Severe abuse cannot be offset by residential identity
    assert.equal(factor(enriched, 'reputation').delta, -65);
    assert.equal(factor(enriched, 'safety').delta, -1);
    assert.ok(factor(enriched, 'reputation').evidence.some((e) => e.source === 'AbuseIPDB'));
    assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(localizeLookup(enriched, 'en'))), false);
  });
});

test('streaming lookup emits every upstream source completion and supports cache bypass', async () => {
  await withFetch(upstream({
    'ipquery.io': { ip: '82.152.6.22', isp: { asn: 'AS7922', org: 'Comcast', isp: 'Comcast Cable' }, location: { country_code: 'US' }, risk: { is_datacenter: false, is_vpn: false, is_tor: false, is_proxy: false, risk_score: 0 } },
    'proxycheck.io': { status: 'ok', '82.152.6.22': { asn: 'AS7922', provider: 'Comcast Cable', proxy: 'no', type: 'ISP', risk: 0 } },
  }), async () => {
    const { lookupIpFull, STREAM_SOURCES } = await loadTs('../src/lib/ipcx-lookup.ts');
    const seen = [];
    const info = await lookupIpFull('82.152.6.22', null, false, null, {
      onSource: (ev) => seen.push(ev),
    });
    assert.equal(info.score, 95);
    assert.equal(seen.length, STREAM_SOURCES.length);
    assert.deepEqual(new Set(seen.map((s) => s.id)), new Set(STREAM_SOURCES.map((s) => s.id)));
    assert.ok(seen.every((s) => s.status === 'ok'));

    // Cached call still fires all source events so client progress reaches 10/10
    const cachedSeen = [];
    await lookupIpFull('82.152.6.22', null, false, null, { onSource: (ev) => cachedSeen.push(ev) });
    assert.equal(cachedSeen.length, STREAM_SOURCES.length);

    // IPv6 marks IPv4-only feeds (shodan, dnsbl) as 'skip'
    const v6Seen = [];
    const v6Info = await lookupIpFull('2606:4700:4700::1111', null, false, null, {
      onSource: (ev) => v6Seen.push(ev),
    });
    assert.ok(typeof v6Info.score === 'number');
    assert.equal(v6Seen.find((s) => s.id === 'shodan').status, 'skip');
    assert.equal(v6Seen.find((s) => s.id === 'dnsbl').status, 'skip');
  });
});

test('missing reputation is capped and cannot imply a clean verdict or platform success', async () => {
  await withFetch(upstream(), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    const info = await lookupIpFull('60.249.14.38', null, false, {});
    assert.equal(info.reputationCoverage, 'limited');
    assert.equal(info.score, 79);
    assert.equal(info.scoreConfidence, 'medium');
    assert.equal(info.lookupStatus, 'partial');
    assert.equal(info.hasThreat, null);
    assert.equal(info.threatLabel, '威胁数据不完整');
    assert.equal(sum(info), info.score);
    // 未配置的付费来源不列为缺失项
    assert.equal(info.reputationChecks.some((c) => c.source === 'AbuseIPDB'), false);
    assert.ok(info.scenes.every((s) => s.tone !== 'ok'));
    assert.ok(info.scenes.some((s) => s.note === '信誉数据不完整，建议实测'));
    assert.equal(/[\p{Script=Han}]/u.test(JSON.stringify(localizeLookup(info, 'en'))), false);
    const v6 = await lookupIpFull('2001:4860:4860::8888', null, false, {});
    assert.equal(v6.reputationCoverage, 'unavailable');
    assert.equal(v6.score, 59);
    assert.equal(v6.hasThreat, null);
    assert.equal(sum(v6), v6.score);
  });
});

test('moderate and severe behavior evidence overrides residential identity without stacking correlated reports', async () => {
  for (const [reports, expected, delta] of [[30, 49, -40], [90, 29, -65]]) {
    const info = await lookup('73.162.88.1', {
      'abuseipdb.com': { data: { abuseConfidenceScore: reports, totalReports: 10 } },
      'dns-query': () => ({ Status: 0, Answer: [{ type: 1, data: '127.0.0.2' }] }),
    });
    assert.equal(info.usageType, 'residential');
    assert.equal(info.isNative, true);
    assert.equal(info.hasThreat, true);
    assert.equal(info.score, expected);
    assert.equal(factor(info, 'reputation').delta, delta);
    assert.equal(sum(info), info.score);
    const strict = ['ecommerce', 'payment', 'ads', 'social'];
    assert.ok(info.scenes.every((s) => (reports >= 75 || strict.includes(s.key) ? s.tone === 'leak' : s.tone === 'warn')));
  }
});

test('incomplete baseline evidence cannot receive a high score even with reputation available', async () => {
  const info = await lookup('73.162.88.1', { 'dns-query': (url) => url.includes('barracuda') ? { Status: 2 } : { Status: 3, Authority: [{ type: 6 }] } });
  assert.equal(info.reputationCoverage, 'complete');
  assert.equal(info.score, 79);
  assert.equal(factor(info, 'coverage').status, '基础检查不完整');
  assert.equal(sum(info), 79);
});


test('legacy verdict API shares the evidence engine and never publishes a fraud probability', async () => {
  await withFetch(upstream(), async () => {
    const { GET } = await loadTs('../src/pages/api/v1/verdict.ts');
    const url = new URL('https://judgeip.com/api/v1/verdict?ip=73.162.88.1');
    const response = await GET({ request: new Request(url, { headers: { 'cf-connecting-ip': '1.1.1.1' } }), url });
    const { report } = await response.json();
    assert.equal(response.status, 200);
    assert.equal(report.score, 95);
    assert.equal(report.fraudRisk, null);
    assert.equal(report.scoringVersion, '2026-11-23');
    assert.equal(report.scoreBase + report.factors.reduce((sum, f) => sum + f.delta, 0), report.score);
    assert.ok(report.platforms.every((item) => item.status === 'warn'));
  });
});

/* 只用免费来源（不配置任何密钥）的查询 */
async function freeLookup(ip, overrides) {
  return withFetch(upstream(overrides), async () => {
    const { lookupIpFull } = await loadTs('../src/lib/ipcx-lookup.ts');
    return lookupIpFull(ip, null, false, {});
  });
}
const riskFeeds = { 'proxycheck.io': (url) => ({ status: 'ok', [url.split('/v2/')[1].split('?')[0]]: { proxy: 'no', type: 'Residential', risk: 0 } }) };

test('free sources alone give complete reputation coverage and a clean verdict', async () => {
  const info = await freeLookup('73.162.88.1', riskFeeds);
  assert.equal(info.reputationCoverage, 'complete');
  assert.equal(info.hasThreat, false);
  assert.equal(info.scoreConfidence, 'high');
  assert.equal(info.score, 95);
  assert.equal(sum(info), info.score);
  assert.equal(info.reputationChecks.some((c) => c.status === 'not_configured'), false);
  assert.ok(info.scenes.every((s) => s.tone === 'ok'));
});

test('a proxycheck VPN flag alone does not mark a data center IP as VPN; on broadband it still counts', async () => {
  const pcVpn = { 'proxycheck.io': (url) => ({ status: 'ok', [url.split('/v2/')[1].split('?')[0]]: { proxy: 'yes', type: 'VPN', risk: 33 } }) };
  const hosting = { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 16509, isp: 'Amazon.com' }, security: { proxy: false, vpn: false, tor: false, hosting: true } }, 'network-info': { data: { prefix: '3.0.0.0/8', asns: ['16509'] } } };
  const cloud = await freeLookup('3.5.140.2', { ...hosting, ...pcVpn });
  assert.equal(cloud.isProxy, false);
  assert.equal(cloud.proxyLabel, '已查来源未见代理');
  const broadband = await freeLookup('73.162.88.1', pcVpn);
  assert.equal(broadband.isProxy, true);
  assert.equal(broadband.proxyLabel, 'VPN 节点');
});

test('web and panel ports are not treated as proxy ports', async () => {
  const info = await freeLookup('73.162.88.1', { ...riskFeeds, internetdb: { ports: [80, 443, 2083, 2087, 8080, 8888], tags: [], vulns: [], hostnames: [] } });
  assert.equal(info.isProxy, false);
  assert.deepEqual(info.proxyPorts, []);
});

test('scene verdicts follow network type, proxy status and region', async () => {
  const hosting = { 'ipwho.is': { success: true, country_code: 'US', continent_code: 'NA', connection: { asn: 16509, isp: 'Amazon.com' }, security: { proxy: false, vpn: false, tor: false, hosting: true } }, 'network-info': { data: { prefix: '3.0.0.0/8', asns: ['16509'] } } };
  const dc = await freeLookup('3.5.140.2', { ...hosting, ...riskFeeds });
  const scene = (info, key) => info.scenes.find((s) => s.key === key);
  assert.equal(scene(dc, 'streaming').tone, 'leak');
  assert.equal(scene(dc, 'ecommerce').tone, 'leak');
  assert.equal(scene(dc, 'ai').tone, 'warn');
  assert.equal(scene(dc, 'gaming').tone, 'ok');
  assert.ok(new Set(dc.scenes.map((s) => s.tone)).size > 1, 'scenes must not all share one verdict');

  const hk = await freeLookup('112.120.1.1', { ...riskFeeds, 'ipwho.is': { success: true, country_code: 'HK', continent_code: 'AS', connection: { asn: 4760, isp: 'HKT Limited' }, security: { proxy: false, vpn: false, tor: false, hosting: false } }, 'whois/data': { data: { authorities: ['APNIC'], records: [[{ key: 'country', value: 'HK' }]] } } });
  assert.equal(scene(hk, 'ai').tone, 'leak');
  assert.equal(scene(hk, 'ai').note, '所在地区不在官方支持范围');
});
