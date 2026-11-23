export interface ReputationCheck {
  source: string;
  status: 'listed' | 'not_listed' | 'unavailable' | 'not_configured';
  checkedAt: string;
  updatedAt?: string;
  url?: string;
  count?: number;
}

const MAX_AGE_MS = 72 * 3600 * 1000;
interface Index { view: DataView; count: number; updatedAt: string }
let cached: Index | null = null;
let pending: Promise<Index | null> | null = null;
let retryAt = 0;

export function parseIpsumIndex(data: ArrayBuffer, now = Date.now()): Index | null {
  if (data.byteLength < 16 || data.byteLength > 2 * 1024 * 1024) return null;
  const view = new DataView(data);
  if (view.getUint32(0) !== 0x4950534d) return null;
  const timestamp = view.getFloat64(4);
  const count = view.getUint32(12);
  if (!Number.isFinite(timestamp) || timestamp > now + 24 * 3600 * 1000 || now - timestamp > MAX_AGE_MS) return null;
  if (count < 1000 || data.byteLength !== 16 + count * 5) return null;
  return { view, count, updatedAt: new Date(timestamp).toISOString() };
}

async function loadIndex(): Promise<Index | null> {
  if (cached && Date.now() - Date.parse(cached.updatedAt) <= MAX_AGE_MS) return cached;
  if (pending) return pending;
  if (Date.now() < retryAt) return null;
  pending = (async () => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error('Index deadline')); }, 1200);
      });
      const task = (async () => {
        // Static assets bypass Worker request dispatch and consume no account KV operations.
        let readAsset: typeof fetch;
        try {
          const { env } = await import('cloudflare:workers');
          const assets = (env as { ASSETS?: { fetch: typeof fetch } }).ASSETS;
          if (!assets) return null;
          readAsset = assets.fetch.bind(assets);
        } catch {
          // Node-based regression tests provide their own fetch implementation.
          readAsset = fetch;
        }
        const response = await readAsset('https://judgeip.com/assets/data/ipsum.bin', { signal: controller.signal });
        if (!response.ok) return null;
        return parseIpsumIndex(await response.arrayBuffer());
      })();
      cached = await Promise.race([task, deadline]);
      if (!cached) retryAt = Date.now() + 60_000;
      return cached;
    } catch {
      retryAt = Date.now() + 60_000;
      return null;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  })().finally(() => { pending = null; });
  return pending;
}

export function lookupIpsumIndex(index: Index, ip: string): number | null {
  const octets = ip.split('.');
  if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || String(Number(part)) !== part || Number(part) > 255)) return null;
  const value = octets.reduce((n, part) => n * 256 + Number(part), 0);
  let lo = 0, hi = index.count - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const current = index.view.getUint32(16 + mid * 5);
    if (current === value) return index.view.getUint8(20 + mid * 5);
    if (current < value) lo = mid + 1;
    else hi = mid - 1;
  }
  return 0;
}

export async function checkPublicReputation(ip: string): Promise<ReputationCheck> {
  const base = { source: 'IPsum', checkedAt: new Date().toISOString(), url: 'https://github.com/stamparm/ipsum' };
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return { ...base, status: 'unavailable' };
  const index = await loadIndex();
  if (!index) return { ...base, status: 'unavailable' };
  const count = lookupIpsumIndex(index, ip);
  if (count === null) return { ...base, status: 'unavailable' };
  return { ...base, status: count ? 'listed' : 'not_listed', updatedAt: index.updatedAt, ...(count ? { count } : {}) };
}
