import test, { before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { loadTs } from './load-ts.mjs';

const { lookupRankings, EMPTY_RANKINGS, RANKING_WINDOW_MS, RANKING_MIN_SAMPLE_TOTAL } = await loadTs('../src/lib/ip-rankings.ts');
const now = Date.UTC(2026, 10, 24);
const info = (ip = '8.8.8.8', score = 80, asn = 15169, extra = {}) => ({
  ip, score, asn, scoringVersion: 'test-v1', isBogon: false, lookupStatus: 'complete', ...extra,
});

let mf;
let db;

before(async () => {
  mf = new Miniflare(convertV4MiniflareOptions({
    modules: true,
    script: 'export default { fetch() { return new Response("local ranking tests"); } };',
    compatibilityDate: '2025-04-01',
    d1Databases: ['RANKINGS_DB', 'UNMIGRATED_DB'],
  }));
  db = await mf.getD1Database('RANKINGS_DB');
  const sql = await readFile(new URL('../migrations/0001_rankings.sql', import.meta.url), 'utf8');
  // Keep trigger bodies intact; their internal semicolons are not statement boundaries.
  const statements = sql.match(/CREATE TRIGGER[\s\S]*?END;|(?:CREATE TABLE|CREATE INDEX|INSERT INTO)[\s\S]*?;/g);
  for (const statement of statements) await db.prepare(statement).run();
});
beforeEach(async () => { await db.prepare('DELETE FROM ranked_ips').run(); });
after(async () => { await mf?.dispose(); });

// 排名算法用例关闭展示门槛（minTotal = 0），与门槛上线前的行为一致；门槛本身由专项用例覆盖。
const record = (data, time = now, minTotal = 0) => lookupRankings(data, true, db, time, minTotal);
const read = (data, time = now, minTotal = 0) => lookupRankings(data, false, db, time, minTotal);
const rows = async (sql) => (await db.prepare(sql).all()).results;

async function assertBuckets() {
  const actual = await rows('SELECT * FROM ranking_counts ORDER BY scope, scoring_version, score');
  const expected = await rows(`SELECT scope, scoring_version, score, COUNT(*) AS count FROM (
    SELECT 0 AS scope, scoring_version, score FROM ranked_ips
    UNION ALL SELECT asn AS scope, scoring_version, score FROM ranked_ips WHERE asn IS NOT NULL
  ) GROUP BY scope, scoring_version, score ORDER BY scope, scoring_version, score`);
  assert.deepEqual(actual, expected, 'trigger buckets must match the underlying deduplicated sample');
}

test('one real sample ranks first, but cannot have a percentile', async () => {
  assert.deepEqual(await record(info()), {
    siteRanking: { rank: 1, total: 1 }, percentileRanking: null, asRanking: { rank: 1, total: 1 },
  });
  await assertBuckets();
});

test('the production default threshold is 100', () => {
  assert.equal(RANKING_MIN_SAMPLE_TOTAL, 100);
});

test('rankings stay hidden until the site sample exceeds the minimum, while recording continues', async () => {
  // 基数行放在不同的分数桶（0 分），不影响被测 IP（80 分）的高低计数，只抬高全站总数。
  const padTotal = async (extra) => {
    await db.prepare('DELETE FROM ranking_counts WHERE score = 0 AND scope = 0').run();
    if (extra > 0) await db.prepare('INSERT INTO ranking_counts (scope, scoring_version, score, count) VALUES (0, ?, 0, ?)').bind('test-v1', extra).run();
  };
  // 500 个样本（1 条真实记录 + 499 条基数）时仍不展示，但查询照常写入去重记录。
  await padTotal(499);
  assert.deepEqual(await record(info(), now, 500), EMPTY_RANKINGS);
  assert.equal((await rows('SELECT * FROM ranked_ips')).length, 1, 'recording continues below the threshold');
  // 501 个样本时开始展示。
  await padTotal(500);
  assert.deepEqual((await read(info(), now, 500)).siteRanking, { rank: 1, total: 501 });
  // 缓存命中路径同样遵守门槛。
  await padTotal(100);
  assert.deepEqual(await read(info(), now, 500), EMPTY_RANKINGS);
  await db.prepare('DELETE FROM ranking_counts WHERE score = 0 AND scope = 0').run();
  await assertBuckets();
});

test('higher scores rank first; ties share a rank and do not count as lower', async () => {
  await record(info('8.8.8.8', 90));
  await record(info('8.8.4.4', 90));
  await record(info('1.1.1.1', 80, 13335));
  await record(info('9.9.9.9', 70, 19281));
  assert.deepEqual(await read(info('8.8.8.8', 90)), {
    siteRanking: { rank: 1, total: 4 }, percentileRanking: 66.7, asRanking: { rank: 1, total: 2 },
  });
  assert.deepEqual(await read(info('1.1.1.1', 80, 13335)), {
    siteRanking: { rank: 3, total: 4 }, percentileRanking: 33.3, asRanking: { rank: 1, total: 1 },
  });
  assert.equal((await read(info('9.9.9.9', 70, 19281))).percentileRanking, 0);
  await assertBuckets();
});

test('repeated queries deduplicate normalized IPv4 and IPv6 targets, not query counts', async () => {
  await record(info());
  await record(info(), now + 1);
  await record(info('2606:4700:4700::1111', 90, 13335));
  const repeated = await record(info('2606:4700:4700:0000:0000:0000:0000:1111', 90, 13335), now + 1);
  assert.deepEqual(repeated.siteRanking, { rank: 1, total: 2 });
  assert.equal(repeated.percentileRanking, 100);
  const stored = await rows('SELECT ip_hash, updated_at FROM ranked_ips');
  assert.equal(stored.length, 2);
  assert.ok(stored.every((row) => /^[a-f0-9]{64}$/.test(row.ip_hash)));
  assert.deepEqual((await rows('PRAGMA table_info(ranked_ips)')).map((row) => row.name),
    ['ip_hash', 'asn', 'score', 'scoring_version', 'updated_at']);
  await assertBuckets();
});

test('score, ASN and scoring-version changes remove old buckets without adding IPs', async () => {
  await record(info('8.8.8.8', 80));
  await record(info('8.8.4.4', 90));
  const moved = info('8.8.8.8', 95, 13335);
  assert.deepEqual((await record(moved, now + 1)).asRanking, { rank: 1, total: 1 });
  assert.deepEqual((await read(info('8.8.4.4', 90), now + 1)).asRanking, { rank: 1, total: 1 });
  assert.deepEqual(await read(info('8.8.8.8', 80), now + 1), EMPTY_RANKINGS, 'stale cached scores cannot claim a current rank');
  await assertBuckets();
  const v2 = { ...moved, scoringVersion: 'test-v2' };
  assert.deepEqual((await record(v2, now + 2)).siteRanking, { rank: 1, total: 1 });
  assert.deepEqual((await read(info('8.8.4.4', 90), now + 2)).siteRanking, { rank: 1, total: 1 });
  assert.equal((await rows('SELECT * FROM ranked_ips')).length, 2);
  await assertBuckets();
});

test('an older write cannot overwrite a newer score or renew its timestamp', async () => {
  await record(info('8.8.8.8', 90), now + 10);
  assert.deepEqual(await record(info('8.8.8.8', 70, 13335), now), EMPTY_RANKINGS);
  assert.deepEqual(await rows('SELECT asn, score, updated_at FROM ranked_ips'), [{ asn: 15169, score: 90, updated_at: now + 10 }]);
  await assertBuckets();
});

test('unknown ASN permits a site rank but never fabricates an AS rank', async () => {
  await record(info());
  for (const asn of [null, 0, -1, 1.5]) {
    const result = await record(info('1.1.1.1', 90, asn));
    assert.deepEqual(result.siteRanking, { rank: 1, total: 2 });
    assert.equal(result.asRanking, null);
  }
  await assertBuckets();
});

test('a cached report with an old ASN cannot claim a rank in the old network', async () => {
  await record(info('8.8.8.8', 80));
  await record(info('8.8.4.4', 90));
  await record(info('8.8.8.8', 80, 13335), now + 1);
  assert.deepEqual(await read(info('8.8.8.8', 80), now + 1), EMPTY_RANKINGS);
  await assertBuckets();
});

test('the 30-day boundary expires targets and trigger buckets, including on cache reads', async () => {
  await record(info('8.8.8.8', 90), now - RANKING_WINDOW_MS + 1);
  await record(info('8.8.4.4', 80), now);
  assert.deepEqual((await read(info('8.8.4.4', 80), now)).siteRanking, { rank: 2, total: 2 });
  assert.deepEqual((await read(info('8.8.4.4', 80), now + 1)).siteRanking, { rank: 1, total: 1 });
  assert.deepEqual(await read(info('8.8.8.8', 90), now + 1), EMPTY_RANKINGS);
  await assertBuckets();
  assert.deepEqual(await read(info('8.8.4.4', 80), now + RANKING_WINDOW_MS), EMPTY_RANKINGS);
  assert.deepEqual(await rows('SELECT * FROM ranking_counts'), []);
});

test('cache reads see current rankings without rewriting or extending the sample', async () => {
  await record(info('8.8.8.8', 80));
  const before = await rows('SELECT * FROM ranked_ips');
  assert.deepEqual((await read(info(), now + 100)).siteRanking, { rank: 1, total: 1 });
  assert.deepEqual(await rows('SELECT * FROM ranked_ips'), before);
  await record(info('8.8.4.4', 90), now + 100);
  assert.deepEqual((await read(info(), now + 200)).siteRanking, { rank: 2, total: 2 });
  assert.equal((await rows('SELECT * FROM ranked_ips WHERE score = 80'))[0].updated_at, now);
  assert.deepEqual(await read(info('1.1.1.1', 80, 13335)), EMPTY_RANKINGS, 'reads never create missing samples');
  await assertBuckets();
});

test('unscored, invalid, reserved and rate-limited lookups do not access storage', async () => {
  const forbidden = { prepare() { throw new Error('ineligible lookups must not access D1'); } };
  const cases = [
    info('not-an-ip'), info('10.0.0.1'), info('::1'), info('8.8.8.8', null),
    info('8.8.8.8', 80.1), info('8.8.8.8', NaN), info('8.8.8.8', -1), info('8.8.8.8', 101),
    info('8.8.8.8', 80, 15169, { isBogon: true }),
    info('8.8.8.8', 80, 15169, { lookupStatus: 'limited' }),
    info('8.8.8.8', 80, 15169, { lookupStatus: 'unavailable' }),
  ];
  let storageCalls = 0;
  forbidden.prepare = () => { storageCalls++; throw new Error('unexpected D1 access'); };
  for (const data of cases) assert.deepEqual(await lookupRankings(data, true, forbidden, now), EMPTY_RANKINGS);
  assert.equal(storageCalls, 0);
  assert.deepEqual(await rows('SELECT * FROM ranked_ips'), []);
  assert.deepEqual((await record(info('8.8.8.8', 80, 15169, { lookupStatus: 'partial' }))).siteRanking, { rank: 1, total: 1 });
});

test('missing binding, migration, key or a failed D1 batch returns no invented values', async () => {
  assert.deepEqual(await lookupRankings(info(), true, null, now), EMPTY_RANKINGS);
  assert.deepEqual(await lookupRankings(info(), true, undefined, now), EMPTY_RANKINGS);
  assert.deepEqual(await lookupRankings(info(), true, await mf.getD1Database('UNMIGRATED_DB'), now), EMPTY_RANKINGS);
  assert.deepEqual(await lookupRankings(info(), true, { prepare() { return { first: async () => null }; } }, now), EMPTY_RANKINGS);
  const failed = {
    prepare: db.prepare.bind(db),
    batch: async () => { throw new Error('database unavailable'); },
  };
  assert.deepEqual(await lookupRankings(info(), true, failed, now), EMPTY_RANKINGS);
  assert.deepEqual(await rows('SELECT * FROM ranked_ips'), []);
});

test('concurrent writes remain deduplicated and keep score buckets consistent', async () => {
  await Promise.all(Array.from({ length: 12 }, (_, i) => record(info(`8.8.8.${i % 3 + 1}`, 70 + i, 15169), now + i)));
  assert.equal((await rows('SELECT * FROM ranked_ips')).length, 3);
  await assertBuckets();
});
