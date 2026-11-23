import { readFile, writeFile } from 'node:fs/promises';
import { parseIpsumFeed } from '../src/lib/ipsum-format.ts';
import { mergeHistory, parseHistoryTsv, serializeHistoryTsv } from '../src/lib/ipsum-history-format.ts';

// Run daily by .github/workflows/ipsum-history.yml. Fails loudly and leaves the file untouched when the feed is unusable.
const file = new URL('../data/ipsum-history.tsv', import.meta.url);
const response = await fetch('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', { signal: AbortSignal.timeout(30_000) });
if (!response.ok) throw new Error(`IPsum HTTP ${response.status}`);
const feed = parseIpsumFeed(await response.text());
if (!feed) throw new Error('Invalid or stale IPsum feed');

let previous = null;
try {
  previous = parseHistoryTsv(await readFile(file, 'utf8'));
  if (!previous) throw new Error('data/ipsum-history.tsv is malformed; refusing to overwrite it');
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
}
const merged = mergeHistory(previous, feed);
await writeFile(file, serializeHistoryTsv(merged));
console.log(`IPsum history: ${merged.entries.size} addresses (was ${previous?.entries.size ?? 0}), feed updated ${feed.updatedAt}`);
