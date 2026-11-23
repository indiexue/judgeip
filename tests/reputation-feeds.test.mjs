import test from 'node:test';
import assert from 'node:assert/strict';
import { loadTs } from './load-ts.mjs';

const feed = (date = new Date(), extra = '') => '# IPsum Threat Intelligence Feed\n# Last update: ' + date.toUTCString() + '\n' +
  Array.from({ length: 1000 }, (_, i) => `11.0.${Math.floor(i / 256)}.${i % 256}\t1`).join('\n') + extra;
function index(date = Date.now()) {
  const buffer = new ArrayBuffer(16 + 1000 * 5), view = new DataView(buffer);
  view.setUint32(0, 0x4950534d); view.setFloat64(4, date); view.setUint32(12, 1000);
  for (let i = 0; i < 1000; i++) { view.setUint32(16 + i * 5, 11 * 2 ** 24 + i); view.setUint8(20 + i * 5, 4); }
  return buffer;
}
async function withFetch(fetcher, fn) {
  const previous = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await fn(); } finally { globalThis.fetch = previous; }
}

test('build parser validates freshness, minimum size, structure and duplicate addresses', async () => {
  const { parseIpsumFeed } = await loadTs('../src/lib/ipsum-format.ts');
  assert.equal(parseIpsumFeed(feed()).entries.size, 1000);
  assert.equal(parseIpsumFeed(feed(new Date(Date.now() - 73 * 3600_000))), null);
  assert.equal(parseIpsumFeed(feed(new Date(Date.now() + 25 * 3600_000))), null);
  for (const bad of ['<html>Error</html>', '# IPsum Threat Intelligence Feed\n11.0.0.1\t1', feed() + '\n11.0.0.1\t2', feed() + '\n999.0.0.1\t2', feed() + '\n11.4.0.1\t0']) assert.equal(parseIpsumFeed(bad), null);
});

test('compact runtime index validates freshness/length and binary lookup boundaries', async () => {
  const { parseIpsumIndex, lookupIpsumIndex } = await loadTs('../src/lib/reputation-feeds.ts');
  const parsed = parseIpsumIndex(index());
  for (const ip of ['11.0.0.0', '11.0.0.1', '11.0.3.231']) assert.equal(lookupIpsumIndex(parsed, ip), 4);
  for (const ip of ['8.8.8.8', '11.0.3.232', '255.255.255.255']) assert.equal(lookupIpsumIndex(parsed, ip), 0);
  assert.equal(lookupIpsumIndex(parsed, '999.0.0.1'), null);
  assert.equal(parseIpsumIndex(index(Date.now() - 73 * 3600_000)), null);
  assert.equal(parseIpsumIndex(index(Date.now() + 25 * 3600_000)), null);
  assert.equal(parseIpsumIndex(new ArrayBuffer(0)), null);
  assert.equal(parseIpsumIndex(index().slice(0, -1)), null);
});

test('IPsum shares asset requests, preserves aggregate count, and never treats IPv6 as clean', async () => {
  let calls = 0;
  await withFetch(async () => { calls++; return new Response(index()); }, async () => {
    const { checkPublicReputation } = await loadTs('../src/lib/reputation-feeds.ts');
    const [a, b] = await Promise.all([checkPublicReputation('11.0.0.0'), checkPublicReputation('8.8.8.8')]);
    assert.equal(a.status, 'listed'); assert.equal(a.count, 4);
    assert.ok(a.updatedAt && a.checkedAt && a.url.startsWith('https://'));
    assert.equal(b.status, 'not_listed');
    assert.equal((await checkPublicReputation('2001:4860:4860::8888')).status, 'unavailable');
    await checkPublicReputation('9.9.9.9'); assert.equal(calls, 1);
  });
});

test('invalid/failed index remains unavailable with retry cooldown', async () => {
  for (const fetcher of [async () => new Response('<html>Error</html>'), async () => new Response('', { status: 429 }), async () => { throw new Error('offline'); }]) {
    let calls = 0;
    await withFetch(async (...args) => { calls++; return fetcher(...args); }, async () => {
      const { checkPublicReputation } = await loadTs('../src/lib/reputation-feeds.ts');
      assert.equal((await checkPublicReputation('8.8.8.8')).status, 'unavailable');
      assert.equal((await checkPublicReputation('9.9.9.9')).status, 'unavailable'); assert.equal(calls, 1);
    });
  }
});

test('index body deadline settles even if a transport ignores AbortSignal', async () => {
  await withFetch(async () => new Response(new ReadableStream({ start() {} })), async () => {
    const { checkPublicReputation } = await loadTs('../src/lib/reputation-feeds.ts');
    const started = Date.now();
    assert.equal((await checkPublicReputation('8.8.8.8')).status, 'unavailable');
    assert.ok(Date.now() - started < 2000);
  });
});

const day = (offset) => new Date(Date.now() + offset * 86400_000).toISOString().slice(0, 10);
const feedOf = (entries, offset = 0) => ({ entries: new Map(entries), updatedAt: new Date(Date.parse(day(offset))).toISOString() });

test('history keeps addresses listed by at least two lists for 30 days and tracks first/last seen and max lists', async () => {
  const { mergeHistory, parseHistoryTsv, serializeHistoryTsv } = await loadTs('../src/lib/ipsum-history-format.ts');
  let h = mergeHistory(null, feedOf([['11.0.0.1', 3], ['11.0.0.2', 1], ['11.0.0.3', 2]], -40));
  assert.deepEqual([...h.entries.keys()], ['11.0.0.1', '11.0.0.3'], 'single-list addresses are not kept');
  h = mergeHistory(h, feedOf([['11.0.0.3', 6]], -10));
  h = mergeHistory(h, feedOf([['11.0.0.3', 2]], 0));
  assert.equal(h.entries.has('11.0.0.1'), false, 'last seen more than 30 days ago is dropped');
  // 第 -40 天那次记录在第 -10 天合并时已超过 30 天被删除，所以首次出现从 -10 天重新算
  assert.deepEqual(h.entries.get('11.0.0.3'), { firstSeen: day(-10), lastSeen: day(0), maxLists: 6 });
  const round = parseHistoryTsv(serializeHistoryTsv(h));
  assert.deepEqual([...round.entries], [...h.entries]);
  assert.equal(round.updatedAt, h.updatedAt);
  assert.equal(parseHistoryTsv('# updated: 2026-11-23T00:00:00Z\n11.0.0.1\tbad\t2026-11-23\t2\n'), null);
});

test('compiled history index answers recent listings and expires old ones at runtime', async () => {
  const { mergeHistory, compileHistoryIndex } = await loadTs('../src/lib/ipsum-history-format.ts');
  let h = mergeHistory(null, feedOf([['11.0.0.9', 5]], -31));
  h = mergeHistory(h, feedOf([['11.0.0.5', 4]], -3));
  h.updatedAt = new Date().toISOString();
  h.entries.set('11.0.0.9', { firstSeen: day(-31), lastSeen: day(-31), maxLists: 5 });
  const bin = compileHistoryIndex(h);
  await withFetch(async (url) => (String(url).includes('ipsum-history.bin') ? new Response(bin) : new Response(index())), async () => {
    const { checkReputationHistory } = await loadTs('../src/lib/reputation-feeds.ts');
    const hit = await checkReputationHistory('11.0.0.5');
    assert.equal(hit.status, 'listed');
    assert.equal(hit.lastSeen, day(-3));
    assert.equal(hit.maxLists, 4);
    assert.equal((await checkReputationHistory('11.0.0.9')).status, 'not_listed', 'older than 30 days');
    assert.equal((await checkReputationHistory('8.8.8.8')).status, 'not_listed');
    assert.equal((await checkReputationHistory('2001:db8::1')).status, 'unavailable');
  });
  await withFetch(async () => new Response(new ArrayBuffer(0)), async () => {
    const { checkReputationHistory } = await loadTs('../src/lib/reputation-feeds.ts');
    assert.equal((await checkReputationHistory('11.0.0.5')).status, 'unavailable');
  });
});
