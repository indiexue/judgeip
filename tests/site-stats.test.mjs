import test, { before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { loadTs } from './load-ts.mjs';

const { recordLookupStat, getSiteStats, EMPTY_STATS, SITE_ONLINE_SINCE } = await loadTs('../src/lib/site-stats.ts');
const now = Date.UTC(2026, 10, 26, 12, 0, 0);
const info = (ip = '8.8.8.8', extra = {}) => ({ ip, isBogon: false, lookupStatus: 'complete', ...extra });
let mf;
let db;

before(async () => {
  mf = new Miniflare(convertV4MiniflareOptions({
    modules: true,
    script: 'export default { fetch() { return new Response("site stats tests"); } };',
    compatibilityDate: '2025-04-01',
    d1Databases: ['RANKINGS_DB', 'UNMIGRATED_DB'],
  }));
  db = await mf.getD1Database('RANKINGS_DB');
  const sql = await readFile(new URL('../migrations/0002_stats.sql', import.meta.url), 'utf8');
  const statements = sql.match(/CREATE TABLE[\s\S]*?\);/g) || [];
  for (const statement of statements) await db.prepare(statement).run();
});
beforeEach(async () => {
  await db.prepare('DELETE FROM stats_counters').run();
  await db.prepare('DELETE FROM stats_daily').run();
});
after(async () => { await mf?.dispose(); });

test('scored public lookups increment total and today counters, including repeats of the same IP', async () => {
  await recordLookupStat(info(), db, now);
  await recordLookupStat(info(), db, now + 1000);
  await recordLookupStat(info('1.1.1.1'), db, now + 2000);
  const stats = await getSiteStats(db, now + 3000);
  assert.deepEqual(stats, { totalChecks: 3, todayChecks: 3, onlineSince: SITE_ONLINE_SINCE });
});

test('today counter follows the UTC day, not the request clock of previous days', async () => {
  const yesterday = Date.UTC(2026, 10, 25, 23, 59, 0);
  await recordLookupStat(info(), db, yesterday);
  await recordLookupStat(info(), db, now);
  const stats = await getSiteStats(db, now);
  assert.equal(stats.totalChecks, 2);
  assert.equal(stats.todayChecks, 1, 'only the same-day lookup counts towards today');
});

test('bogons, invalid IPs, unscored and rate-limited lookups never touch storage', async () => {
  let storageCalls = 0;
  const forbidden = { prepare() { storageCalls++; throw new Error('must not access D1'); }, batch() { storageCalls++; throw new Error('must not access D1'); } };
  for (const data of [
    info('not-an-ip'), info('10.0.0.1'), info('::1'), info('192.168.1.1'),
    info('8.8.8.8', { isBogon: true }),
    info('8.8.8.8', { lookupStatus: 'limited' }),
    info('8.8.8.8', { lookupStatus: 'unavailable' }),
  ]) {
    await recordLookupStat(data, forbidden, now);
  }
  assert.equal(storageCalls, 0);
  assert.equal(await getSiteStats(db, now), null);
});

test('partial lookups count towards the stats just like complete ones', async () => {
  await recordLookupStat(info('8.8.8.8', { lookupStatus: 'partial' }), db, now);
  const stats = await getSiteStats(db, now);
  assert.equal(stats.totalChecks, 1);
});

test('stats read returns null when storage is missing, unmigrated or empty — never invented numbers', async () => {
  assert.equal(await getSiteStats(null, now), null);
  assert.equal(await getSiteStats(undefined, now), null);
  assert.equal(await getSiteStats(await mf.getD1Database('UNMIGRATED_DB'), now), null);
  assert.equal(await getSiteStats(db, now), null, 'empty counters hide the strip');
  const failed = { prepare: db.prepare.bind(db), batch: async () => { throw new Error('database unavailable'); } };
  assert.equal(await getSiteStats(failed, now), null);
  assert.deepEqual(EMPTY_STATS, { totalChecks: 0, todayChecks: 0, onlineSince: null });
});

test('recording continues silently even when one write fails', async () => {
  const failed = { prepare: db.prepare.bind(db), batch: async () => { throw new Error('database unavailable'); } };
  await recordLookupStat(info(), failed, now);
  assert.equal(await getSiteStats(db, now), null, 'failed writes record nothing but do not throw');
});
