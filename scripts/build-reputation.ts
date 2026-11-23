import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { parseIpsumFeed } from '../src/lib/ipsum-format.ts';
import { compileHistoryIndex, parseHistoryTsv } from '../src/lib/ipsum-history-format.ts';

const root = new URL('../public/assets/data/', import.meta.url);
const url = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt';
try {
  const response = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error(`IPsum HTTP ${response.status}`);
  const feed = parseIpsumFeed(await response.text());
  if (!feed) throw new Error('Invalid or stale IPsum feed');
  const rows = [...feed.entries].map(([ip, count]) => ({ ip: ip.split('.').reduce((n, octet) => n * 256 + Number(octet), 0), count })).sort((a, b) => a.ip - b.ip);
  // Fixed-width sorted records allow O(log n) lookups without parsing the full feed in Workers.
  const binary = Buffer.alloc(16 + rows.length * 5);
  binary.write('IPSM', 0);
  binary.writeDoubleBE(Date.parse(feed.updatedAt), 4);
  binary.writeUInt32BE(rows.length, 12);
  rows.forEach((row, i) => { binary.writeUInt32BE(row.ip, 16 + i * 5); binary.writeUInt8(row.count, 20 + i * 5); });
  await mkdir(root, { recursive: true });
  await writeFile(new URL('ipsum.bin', root), binary);
  await writeFile(new URL('ipsum-meta.json', root), JSON.stringify({ source: 'IPsum', url, license: 'Unlicense', updatedAt: feed.updatedAt, builtAt: new Date().toISOString(), entries: rows.length }));
  console.log(`IPsum compiled: ${rows.length} entries, ${binary.length} bytes, updated ${feed.updatedAt}`);
} catch (error) {
  // An upstream outage must not publish false negatives or make all unrelated deployments impossible.
  // Preserve the previous index if one exists; the runtime rejects snapshots older than 72 hours.
  try { await readFile(new URL('ipsum.bin', root)); }
  catch { await mkdir(root, { recursive: true }); await writeFile(new URL('ipsum.bin', root), Buffer.alloc(0)); }
  console.warn('IPsum unavailable during build; runtime will validate the previous snapshot or show unavailable.', error instanceof Error ? error.message : 'unknown error');
}

// The 30-day history is committed daily by GitHub Actions; without it the runtime reports history as unavailable.
try {
  const history = parseHistoryTsv(await readFile(new URL('../data/ipsum-history.tsv', import.meta.url), 'utf8'));
  if (!history) throw new Error('malformed data/ipsum-history.tsv');
  const index = compileHistoryIndex(history);
  await writeFile(new URL('ipsum-history.bin', root), index);
  console.log(`IPsum history compiled: ${history.entries.size} entries, ${index.length} bytes, updated ${history.updatedAt}`);
} catch (error) {
  await writeFile(new URL('ipsum-history.bin', root), Buffer.alloc(0));
  console.warn('IPsum history unavailable during build.', error instanceof Error ? error.message : 'unknown error');
}
