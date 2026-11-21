export interface ServiceItemConfig {
  id: string;
  mark: string;
  name: string;
  faviconDomain: string;
  pageUrl: string;
  summaryApi?: string;
}

export interface ServiceGroupConfig {
  id: string;
  title: string;
  items: ServiceItemConfig[];
}

export interface LiveServiceStatus {
  id: string;
  mark: string;
  name: string;
  faviconDomain: string;
  pageUrl: string;
  tone: 'ok' | 'warn' | 'bad' | 'maint' | 'muted';
  tagText: string;
  note: string;
}

const SERVICE_GROUPS: ServiceGroupConfig[] = [
  {
    id: 'status-ai',
    title: 'AI 服务',
    items: [
      { id: 'svc-openai', mark: 'OA', name: 'ChatGPT / OpenAI', faviconDomain: 'openai.com', pageUrl: 'https://status.openai.com', summaryApi: 'https://status.openai.com/api/v2/summary.json' },
      { id: 'svc-claude', mark: 'Cl', name: 'Claude', faviconDomain: 'claude.ai', pageUrl: 'https://status.claude.com', summaryApi: 'https://status.claude.com/api/v2/summary.json' },
      { id: 'svc-perplexity', mark: 'Px', name: 'Perplexity', faviconDomain: 'perplexity.ai', pageUrl: 'https://status.perplexity.com' },
      { id: 'svc-groq', mark: 'Gq', name: 'Groq', faviconDomain: 'groq.com', pageUrl: 'https://groqstatus.com', summaryApi: 'https://groqstatus.com/api/v2/summary.json' },
      { id: 'svc-cursor', mark: 'Cu', name: 'Cursor', faviconDomain: 'cursor.com', pageUrl: 'https://status.cursor.com', summaryApi: 'https://status.cursor.com/api/v2/summary.json' },
      { id: 'svc-elevenlabs', mark: '11', name: 'ElevenLabs', faviconDomain: 'elevenlabs.io', pageUrl: 'https://status.elevenlabs.io' },
    ],
  },
  {
    id: 'status-cloud',
    title: '云与网络',
    items: [
      { id: 'svc-cloudflare', mark: 'CF', name: 'Cloudflare', faviconDomain: 'cloudflare.com', pageUrl: 'https://www.cloudflarestatus.com', summaryApi: 'https://www.cloudflarestatus.com/api/v2/summary.json' },
      { id: 'svc-vercel', mark: 'Ve', name: 'Vercel', faviconDomain: 'vercel.com', pageUrl: 'https://www.vercel-status.com', summaryApi: 'https://www.vercel-status.com/api/v2/summary.json' },
      { id: 'svc-netlify', mark: 'Nl', name: 'Netlify', faviconDomain: 'netlify.com', pageUrl: 'https://www.netlifystatus.com', summaryApi: 'https://www.netlifystatus.com/api/v2/summary.json' },
      { id: 'svc-flyio', mark: 'Fl', name: 'Fly.io', faviconDomain: 'fly.io', pageUrl: 'https://status.flyio.net', summaryApi: 'https://status.flyio.net/api/v2/summary.json' },
      { id: 'svc-supabase', mark: 'Sb', name: 'Supabase', faviconDomain: 'supabase.com', pageUrl: 'https://status.supabase.com', summaryApi: 'https://status.supabase.com/api/v2/summary.json' },
      { id: 'svc-digitalocean', mark: 'DO', name: 'DigitalOcean', faviconDomain: 'digitalocean.com', pageUrl: 'https://status.digitalocean.com', summaryApi: 'https://status.digitalocean.com/api/v2/summary.json' },
    ],
  },
  {
    id: 'status-dev',
    title: '开发与协作',
    items: [
      { id: 'svc-github', mark: 'GH', name: 'GitHub', faviconDomain: 'github.com', pageUrl: 'https://www.githubstatus.com', summaryApi: 'https://www.githubstatus.com/api/v2/summary.json' },
      { id: 'svc-npm', mark: 'np', name: 'npm', faviconDomain: 'npmjs.com', pageUrl: 'https://status.npmjs.org', summaryApi: 'https://status.npmjs.org/api/v2/summary.json' },
      { id: 'svc-python', mark: 'Py', name: 'PyPI / Python', faviconDomain: 'pypi.org', pageUrl: 'https://status.python.org' },
      { id: 'svc-atlassian', mark: 'At', name: 'Atlassian', faviconDomain: 'atlassian.com', pageUrl: 'https://status.atlassian.com', summaryApi: 'https://status.atlassian.com/api/v2/summary.json' },
      { id: 'svc-sentry', mark: 'Se', name: 'Sentry', faviconDomain: 'sentry.io', pageUrl: 'https://status.sentry.io', summaryApi: 'https://status.sentry.io/api/v2/summary.json' },
      { id: 'svc-postman', mark: 'Pm', name: 'Postman', faviconDomain: 'postman.com', pageUrl: 'https://status.postman.com', summaryApi: 'https://status.postman.com/api/v2/summary.json' },
      { id: 'svc-stripe', mark: 'St', name: 'Stripe', faviconDomain: 'stripe.com', pageUrl: 'https://www.stripestatus.com' },
      { id: 'svc-twilio', mark: 'Tw', name: 'Twilio', faviconDomain: 'twilio.com', pageUrl: 'https://status.twilio.com', summaryApi: 'https://status.twilio.com/api/v2/summary.json' },
      { id: 'svc-discord', mark: 'Dc', name: 'Discord', faviconDomain: 'discord.com', pageUrl: 'https://discordstatus.com', summaryApi: 'https://discordstatus.com/api/v2/summary.json' },
      { id: 'svc-linear', mark: 'Ln', name: 'Linear', faviconDomain: 'linear.app', pageUrl: 'https://linearstatus.com' },
      { id: 'svc-figma', mark: 'Fi', name: 'Figma', faviconDomain: 'figma.com', pageUrl: 'https://status.figma.com', summaryApi: 'https://status.figma.com/api/v2/summary.json' },
    ],
  },
];

let cachedSnapshot: { exp: number; data: Awaited<ReturnType<typeof loadLiveStatusesUncached>> } | null = null;

async function checkOneService(cfg: ServiceItemConfig): Promise<LiveServiceStatus> {
  /* 没有公开接口、或这一次没读到的，如实标「暂无数据」，不替对方报正常 */
  if (!cfg.summaryApi) {
    return {
      ...cfg,
      tone: 'muted',
      tagText: '暂无数据',
      note: '没有公开的状态接口，点击服务名查看官方状态页',
    };
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 2800);
  try {
    const res = await fetch(cfg.summaryApi, {
      signal: ctl.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'JudgeIP-Status/1.0' },
    });
    if (!res.ok) throw new Error('bad_status');
    const json = (await res.json()) as {
      status?: { indicator?: string; description?: string };
      components?: Array<{ name?: string; status?: string; group?: boolean }>;
    };

    const indicator = typeof json?.status?.indicator === 'string' ? json.status.indicator.toLowerCase() : '';
    const validIndicators = ['none', 'minor', 'major', 'critical', 'maintenance'];
    if (!validIndicators.includes(indicator) || (json.components !== undefined && !Array.isArray(json.components))) throw new Error('invalid_summary');
    if (json.components?.some((c) => !c || typeof c !== 'object')) throw new Error('invalid_components');
    const comps = (json.components || []).filter((c) => !c.group);
    const knownStates = ['operational', 'degraded_performance', 'partial_outage', 'major_outage', 'under_maintenance'];
    if (comps.some((c) => !knownStates.includes(c.status || ''))) throw new Error('invalid_components');
    const maintenance = comps.filter((c) => c.status === 'under_maintenance');
    const abnormal = comps.filter((c) => c.status !== 'operational' && c.status !== 'under_maintenance');

    if (indicator === 'none' && abnormal.length === 0 && maintenance.length === 0) {
      return {
        ...cfg,
        tone: 'ok',
        tagText: '正常运行',
        note: comps.length ? `${comps.length} 个组件全部正常` : 'All Systems Operational',
      };
    }

    if (abnormal.length === 0 && (indicator === 'maintenance' || (indicator === 'none' && maintenance.length > 0))) {
      return {
        ...cfg,
        tone: 'maint',
        tagText: '维护中',
        note: json.status?.description || '计划维护进行中',
      };
    }

    const isMajor = indicator === 'major' || indicator === 'critical' || abnormal.some((c) => c.status === 'major_outage');
    const names = abnormal.slice(0, 3).map((c) => c.name).filter(Boolean).join('、');
    return {
      ...cfg,
      tone: isMajor ? 'bad' : 'warn',
      tagText: isMajor ? '严重故障' : '轻微故障',
      note: abnormal.length
        ? `${abnormal.length} 个组件异常：${names}${abnormal.length > 3 ? ' 等' : ''}`
        : json.status?.description || '部分服务异常',
    };
  } catch {
    return {
      ...cfg,
      tone: 'muted',
      tagText: '暂无数据',
      note: '这次没能读取官方状态页',
    };
  } finally {
    clearTimeout(timer);
  }
}

async function loadLiveStatusesUncached() {
  const groups = await Promise.all(
    SERVICE_GROUPS.map(async (g) => {
      const items = await Promise.all(g.items.map(checkOneService));
      return { id: g.id, title: g.title, items };
    })
  );

  const flat = groups.flatMap((g) => g.items);
  const okCount = flat.filter((i) => i.tone === 'ok').length;
  const badItems = flat.filter((i) => i.tone === 'warn' || i.tone === 'bad');
  const maintCount = flat.filter((i) => i.tone === 'maint').length;
  const mutedCount = flat.filter((i) => i.tone === 'muted').length;

  return {
    groups,
    total: flat.length,
    okCount,
    badCount: badItems.length,
    badItems,
    maintCount,
    mutedCount,
  };
}

type Snapshot = Awaited<ReturnType<typeof loadLiveStatusesUncached>>;

export async function getLiveServiceStatuses(lang: 'zh' | 'en' = 'zh'): Promise<Snapshot> {
  let data: Snapshot;
  if (cachedSnapshot && cachedSnapshot.exp > Date.now()) {
    data = cachedSnapshot.data;
  } else {
    data = await loadLiveStatusesUncached();
    cachedSnapshot = { exp: Date.now() + 5 * 60 * 1000, data };
  }
  return lang === 'en' ? localizeSnapshot(data) : data;
}

/* 快照按中文生成并缓存，英文页在取出后换文案 */
const GROUP_TITLES_EN: Record<string, string> = {
  'status-ai': 'AI services',
  'status-cloud': 'Cloud and network',
  'status-dev': 'Developer and collaboration',
};

const TAGS_EN: Record<string, string> = {
  正常运行: 'Operational',
  维护中: 'Maintenance',
  严重故障: 'Major outage',
  轻微故障: 'Minor issue',
  暂无数据: 'No data',
};

function noteEn(note: string): string {
  let m = note.match(/^(\d+) 个组件全部正常$/);
  if (m) return `All ${m[1]} components operational`;
  m = note.match(/^(\d+) 个组件异常：(.*?)( 等)?$/);
  if (m) return `${m[1]} components affected: ${m[2].split('、').join(', ')}${m[3] ? ' and more' : ''}`;
  const fixed: Record<string, string> = {
    计划维护进行中: 'Scheduled maintenance in progress',
    部分服务异常: 'Some services affected',
    '没有公开的状态接口，点击服务名查看官方状态页': 'No public status API; click the name to open the official status page',
    这次没能读取官方状态页: 'Could not read the official status page this time',
  };
  return fixed[note] || note;
}

function localizeSnapshot(data: Snapshot): Snapshot {
  const item = (i: LiveServiceStatus): LiveServiceStatus => ({ ...i, tagText: TAGS_EN[i.tagText] || i.tagText, note: noteEn(i.note) });
  return {
    ...data,
    groups: data.groups.map((g) => ({ ...g, title: GROUP_TITLES_EN[g.id] || g.title, items: g.items.map(item) })),
    badItems: data.badItems.map(item),
  };
}
