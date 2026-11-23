const MAX_AGE_MS = 72 * 3600 * 1000;
const MAX_BYTES = 8 * 1024 * 1024;
export interface Feed { entries: Map<string, number>; updatedAt: string }

// IPsum is an aggregate, not a count of independent observations by JudgeIP.
export function parseIpsumFeed(text: string, now = Date.now()): Feed | null {
  if (text.length > MAX_BYTES || !text.startsWith('# IPsum Threat Intelligence Feed')) return null;
  const stamp = text.match(/^# Last update:\s*(.+)$/m)?.[1];
  const timestamp = stamp ? Date.parse(stamp) : NaN;
  if (!Number.isFinite(timestamp) || timestamp > now + 24 * 3600 * 1000 || now - timestamp > MAX_AGE_MS) return null;
  const entries = new Map<string, number>();
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const match = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\t([1-9]\d?)$/);
    if (!match || !match[1].split('.').every((part) => String(Number(part)) === part && Number(part) <= 255)) return null;
    if (entries.has(match[1])) return null;
    entries.set(match[1], Number(match[2]));
  }
  return entries.size >= 1000 ? { entries, updatedAt: new Date(timestamp).toISOString() } : null;
}
