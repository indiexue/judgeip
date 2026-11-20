import { parseIp } from './ip-utils';

export type RdapQueryKind = 'domain' | 'ip' | 'autnum';

export interface StatusBadgeItem {
  code: string;
  label: string;
  tone: 'green' | 'gray' | 'amber';
  note: string;
}

export interface RdapLookupView {
  ok: boolean;
  error?: string;
  kind: RdapQueryKind;
  query: string;
  displayName: string;
  eyebrow: string;
  subline: string;
  sourceHost: string;
  badges: Array<{ text: string; tone: 'green' | 'gray' | 'amber' | 'danger' }>;
  life?: {
    regDate: string;
    expDate: string;
    pct: number;
    tone: 'good' | 'warn' | 'bad';
    caption: string;
  };
  statuses: StatusBadgeItem[];
  dates: Array<{ label: string; date: string; hint: string }>;
  nameservers: string[];
  details: Array<{ label: string; value: string; mono?: boolean; isMail?: boolean; badgeTone?: 'green' | 'gray' | 'amber' }>;
  rawJson: string;
  rawSizeKb: string;
}

const STATUS_MAP: Record<string, { label: string; tone: 'green' | 'gray' | 'amber'; note: string }> = {
  active: { label: '正常生效', tone: 'green', note: '当前记录处于正常活跃状态。' },
  ok: { label: '正常', tone: 'green', note: '没有任何限制，可以正常解析、续费、修改和转移。' },
  'client transfer prohibited': {
    label: '注册商转移锁',
    tone: 'gray',
    note: '注册商禁止把域名转出到其他注册商，防止被恶意转走。绝大多数域名默认开启，属于正常保护。',
  },
  'server transfer prohibited': {
    label: '注册局转移锁',
    tone: 'gray',
    note: '注册局层面禁止转移，级别高于注册商锁，常见于高价值域名或争议处理期间。',
  },
  'client update prohibited': {
    label: '注册商更新锁',
    tone: 'gray',
    note: '注册商禁止修改联系人、DNS 服务器等注册信息，防止信息被篡改。',
  },
  'server update prohibited': {
    label: '注册局更新锁',
    tone: 'gray',
    note: '注册局层面禁止修改任何注册信息，需要先由注册局解锁。',
  },
  'client delete prohibited': {
    label: '注册商删除锁',
    tone: 'gray',
    note: '注册商禁止删除域名，防止误删或被恶意删除。',
  },
  'server delete prohibited': {
    label: '注册局删除锁',
    tone: 'gray',
    note: '注册局层面禁止删除，保护级别更高。',
  },
  'client hold': {
    label: '暂停解析',
    tone: 'amber',
    note: '注册商暂停了域名的 DNS 解析，网站和邮箱都会失效。常见原因是欠费、未完成实名或投诉处理。',
  },
  'server hold': {
    label: '注册局暂停解析',
    tone: 'amber',
    note: '注册局暂停了域名的解析，常见于未完成实名认证或违规处置，需要联系注册商核实。',
  },
  'auto renew period': {
    label: '自动续费宽限期',
    tone: 'gray',
    note: '到期后注册局已自动续费一年，约 45 天内注册商仍可撤销这次续费。',
  },
  'redemption period': {
    label: '赎回期',
    tone: 'amber',
    note: '域名已过期并被删除，原持有人约 30 天内可以支付赎回费找回，逾期进入删除流程。',
  },
  'pending delete': {
    label: '等待删除',
    tone: 'amber',
    note: '域名即将被注册局删除并重新开放注册，通常持续约 5 天，这个阶段已无法赎回。',
  },
};

function toCamelStatusCode(raw: string): string {
  const parts = raw.trim().toLowerCase().split(/\s+/);
  return parts
    .map((w, i) => (i === 0 ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join('');
}

function formatYmd(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toISOString().slice(0, 10);
}

function relativeDateHint(iso: string, futurePrefix = '还有'): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const diffMs = d.getTime() - Date.now();
  const absDays = Math.floor(Math.abs(diffMs) / 86400000);
  if (absDays === 0) {
    const absHours = Math.max(1, Math.floor(Math.abs(diffMs) / 3600000));
    return diffMs < 0 ? `${absHours} 小时前` : `${futurePrefix} ${absHours} 小时`;
  }
  if (diffMs < 0) {
    if (absDays >= 365) return `${(absDays / 365).toFixed(1)} 年前`;
    return `${absDays} 天前`;
  }
  return `${futurePrefix} ${absDays} 天`;
}

function extractVcardField(vcardArray: any, fieldName: string): string {
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return '';
  for (const row of vcardArray[1]) {
    if (Array.isArray(row) && String(row[0]).toLowerCase() === fieldName.toLowerCase()) {
      const val = row[3];
      if (typeof val === 'string' && val.trim()) return val.trim();
    }
  }
  return '';
}

export async function queryRdap(rawInput: string): Promise<RdapLookupView> {
  const cleaned = rawInput.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  if (!cleaned) {
    return emptyError('请输入要查询的域名、IP 地址或 ASN。');
  }

  let kind: RdapQueryKind = 'domain';
  let target = cleaned;
  let rdapUrl = '';

  const asnMatch = cleaned.match(/^(?:AS)?(\d{1,10})$/i);
  const cidrMatch = cleaned.split('/')[0];
  const parsedIp = parseIp(cidrMatch);

  if (asnMatch) {
    kind = 'autnum';
    target = asnMatch[1];
    rdapUrl = `https://rdap.org/autnum/${encodeURIComponent(target)}`;
  } else if (parsedIp) {
    kind = 'ip';
    target = cleaned.includes('/') ? cleaned : parsedIp.normalized;
    rdapUrl = `https://rdap.org/ip/${encodeURIComponent(target)}`;
  } else {
    kind = 'domain';
    target = cleaned.toLowerCase();
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target)) {
      return emptyError('输入格式无法识别，请输入有效的域名（如 judgeip.com）、IP 地址或 AS 号。');
    }
    rdapUrl = `https://rdap.org/domain/${encodeURIComponent(target)}`;
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 7500);
  try {
    const res = await fetch(rdapUrl, {
      signal: ctl.signal,
      redirect: 'follow',
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'JudgeIP-RDAP/1.0 (+https://judgeip.com)',
      },
    });
    clearTimeout(timer);

    if (res.status === 404) {
      return emptyError(
        kind === 'domain'
          ? `注册局返回未找到「${target}」的记录（该域名可能尚未注册，或该顶级域暂未开放 RDAP）。`
          : `未在注册局 RDAP 中查到「${target}」的记录。`
      );
    }
    if (!res.ok) {
      return emptyError(`上游注册局返回 HTTP ${res.status}，请稍后重试。`);
    }

    const data = await res.json();
    const finalUrl = res.url || rdapUrl;
    let sourceHost = 'rdap.org';
    try {
      sourceHost = new URL(finalUrl).hostname;
    } catch {
      sourceHost = 'rdap.org';
    }
    if (sourceHost === 'rdap.org' && Array.isArray(data.links)) {
      const selfLink = data.links.find((l: any) => l?.rel === 'self' && typeof l?.href === 'string');
      if (selfLink) {
        try {
          sourceHost = new URL(selfLink.href).hostname;
        } catch {
          // ignore
        }
      }
    }

    const rawJson = JSON.stringify(data, null, 2);
    const rawSizeKb = `${Math.max(0.1, rawJson.length / 1024).toFixed(1)} KB`;

    // Extract entities (registrar, registrant/org, abuse email)
    let registrarName = '';
    let registrarIana = '';
    let abuseEmail = '';
    let orgName = '';

    const walkEntities = (entities: any[]) => {
      for (const ent of entities || []) {
        const roles: string[] = Array.isArray(ent?.roles) ? ent.roles.map((r: string) => r.toLowerCase()) : [];
        const fn = extractVcardField(ent?.vcardArray, 'fn');
        const mail = extractVcardField(ent?.vcardArray, 'email');

        if (roles.includes('registrar') && fn && !registrarName) {
          registrarName = fn;
          if (Array.isArray(ent.publicIds)) {
            const iana = ent.publicIds.find((p: any) => /iana/i.test(p?.type || ''));
            if (iana?.identifier) registrarIana = String(iana.identifier);
          }
        }
        if ((roles.includes('registrant') || roles.includes('administrative')) && fn && !orgName) {
          orgName = fn;
        }
        if (roles.includes('abuse') && mail && !abuseEmail) {
          abuseEmail = mail;
        }
        if (!abuseEmail && mail && roles.includes('noc')) {
          abuseEmail = mail;
        }
        if (Array.isArray(ent?.entities)) {
          walkEntities(ent.entities);
        }
      }
    };
    walkEntities(data.entities || []);

    // Events
    let regIso = '';
    let expIso = '';
    let updIso = '';
    for (const ev of data.events || []) {
      const act = String(ev?.eventAction || '').toLowerCase();
      const dt = String(ev?.eventDate || '');
      if (!dt) continue;
      if (act === 'registration' && !regIso) regIso = dt;
      else if (act === 'expiration' && !expIso) expIso = dt;
      else if ((act === 'last changed' || act === 'last update of rdap database') && !updIso) updIso = dt;
    }

    const dates: Array<{ label: string; date: string; hint: string }> = [];
    if (regIso) dates.push({ label: '注册时间', date: formatYmd(regIso), hint: relativeDateHint(regIso) });
    if (expIso) dates.push({ label: '到期时间', date: formatYmd(expIso), hint: relativeDateHint(expIso) });
    if (updIso) dates.push({ label: '最近更新', date: formatYmd(updIso), hint: relativeDateHint(updIso) });

    let life: RdapLookupView['life'];
    if (regIso && expIso) {
      const t0 = new Date(regIso).getTime();
      const t1 = new Date(expIso).getTime();
      const now = Date.now();
      if (t1 > t0) {
        const pct = Math.max(0, Math.min(100, Math.round(((now - t0) / (t1 - t0)) * 100)));
        const daysLeft = Math.floor((t1 - now) / 86400000);
        const tone: 'good' | 'warn' | 'bad' = daysLeft < 45 ? 'bad' : daysLeft < 90 ? 'warn' : 'good';
        const caption =
          daysLeft >= 0
            ? `距到期还有 ${daysLeft} 天 · 生命周期已走过 ${pct}%`
            : `已过期 ${Math.abs(daysLeft)} 天`;
        life = {
          regDate: formatYmd(regIso),
          expDate: formatYmd(expIso),
          pct,
          tone,
          caption,
        };
      }
    }

    // Statuses
    const rawStatuses: string[] = Array.isArray(data.status) ? data.status : [];
    const statuses: StatusBadgeItem[] = rawStatuses.map((st) => {
      const key = st.trim().toLowerCase();
      const known = STATUS_MAP[key];
      return {
        code: toCamelStatusCode(st),
        label: known ? known.label : st,
        tone: known ? known.tone : 'gray',
        note: known ? known.note : '注册局返回的状态标记。',
      };
    });

    // Nameservers
    const nameservers: string[] = Array.isArray(data.nameservers)
      ? data.nameservers
          .map((ns: any) => String(ns?.ldhName || ns?.unicodeName || '').toLowerCase())
          .filter(Boolean)
      : [];

    // Badges & Details
    const badges: RdapLookupView['badges'] = [];
    const details: RdapLookupView['details'] = [];

    let displayName = target;
    let eyebrow = '域名';
    let subline = '';

    if (kind === 'domain') {
      displayName = String(data.ldhName || target).toLowerCase();
      eyebrow = '域名';
      subline = [registrarName, registrarIana ? `IANA #${registrarIana}` : ''].filter(Boolean).join(' · ') || sourceHost;
      const hasHold = rawStatuses.some((s) => /hold|redemption|pending delete/i.test(s));
      badges.push({
        text: hasHold ? '解析受限 / 异常状态' : '已注册 · 状态正常',
        tone: hasHold ? 'amber' : 'green',
      });
      if (regIso) {
        const ageDays = Math.max(0, Math.floor((Date.now() - new Date(regIso).getTime()) / 86400000));
        badges.push({
          text: ageDays >= 365 ? `域名年龄 ${(ageDays / 365).toFixed(1)} 年` : `域名年龄 ${ageDays} 天`,
          tone: 'gray',
        });
      }
      if (registrarName) details.push({ label: '注册商', value: registrarName });
      if (registrarIana) details.push({ label: '注册商 IANA ID', value: registrarIana, mono: true });
      const dnssec = Boolean(data.secureDNS?.delegationSigned);
      details.push({ label: 'DNSSEC', value: dnssec ? '已签名' : '未启用', badgeTone: dnssec ? 'green' : 'gray' });
      if (abuseEmail) details.push({ label: '滥用举报', value: abuseEmail, mono: true, isMail: true });
      if (data.handle) details.push({ label: '注册局句柄', value: String(data.handle), mono: true });
    } else if (kind === 'ip') {
      displayName = data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : target;
      eyebrow = 'IP 地址段';
      subline = [data.name, orgName || registrarName].filter(Boolean).join(' · ') || sourceHost;
      badges.push({ text: 'RIR 已分配网段', tone: 'green' });
      if (data.ipVersion) badges.push({ text: String(data.ipVersion).toUpperCase(), tone: 'gray' });
      if (data.name) details.push({ label: '网络名称', value: String(data.name), mono: true });
      if (orgName) details.push({ label: '持有机构', value: orgName });
      if (data.country) details.push({ label: '注册国家/地区', value: String(data.country).toUpperCase(), mono: true });
      if (data.type) details.push({ label: '分配类型', value: String(data.type) });
      if (abuseEmail) details.push({ label: '滥用举报', value: abuseEmail, mono: true, isMail: true });
      if (data.handle) details.push({ label: 'RIR 句柄', value: String(data.handle), mono: true });
    } else {
      const startAs = data.startAutnum || target;
      displayName = `AS${startAs}`;
      eyebrow = '自治系统号 (ASN)';
      subline = [data.name, orgName].filter(Boolean).join(' · ') || sourceHost;
      badges.push({ text: '已分配 ASN', tone: 'green' });
      if (data.name) details.push({ label: 'AS 标识', value: String(data.name), mono: true });
      if (orgName) details.push({ label: '持有机构', value: orgName });
      if (data.country) details.push({ label: '注册国家/地区', value: String(data.country).toUpperCase(), mono: true });
      if (abuseEmail) details.push({ label: '滥用举报', value: abuseEmail, mono: true, isMail: true });
      if (data.handle) details.push({ label: 'RIR 句柄', value: String(data.handle), mono: true });
    }

    return {
      ok: true,
      kind,
      query: cleaned,
      displayName,
      eyebrow,
      subline,
      sourceHost,
      badges,
      life,
      statuses,
      dates,
      nameservers,
      details,
      rawJson,
      rawSizeKb,
    };
  } catch {
    clearTimeout(timer);
    return emptyError('连接注册局 RDAP 服务超时或网络异常，请稍后再试。');
  }
}

function emptyError(error: string): RdapLookupView {
  return {
    ok: false,
    error,
    kind: 'domain',
    query: '',
    displayName: '',
    eyebrow: '',
    subline: '',
    sourceHost: '',
    badges: [],
    statuses: [],
    dates: [],
    nameservers: [],
    details: [],
    rawJson: '',
    rawSizeKb: '0 KB',
  };
}
