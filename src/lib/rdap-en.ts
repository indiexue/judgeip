import type { RdapLookupView } from './rdap-lookup';
import type { Lang } from './i18n';

const LABELS: Record<string, string> = {
  '域名': 'Domain',
  'IP 地址段': 'IP range',
  '自治系统号 (ASN)': 'Autonomous system (ASN)',
  '注册时间': 'Registered',
  '到期时间': 'Expires',
  '最近更新': 'Last updated',
  '注册商': 'Registrar',
  '注册商 IANA ID': 'Registrar IANA ID',
  '已签名': 'Signed',
  '未启用': 'Not enabled',
  '滥用举报': 'Abuse contact',
  '注册局句柄': 'Registry handle',
  '网络名称': 'Network name',
  '持有机构': 'Organization',
  '注册国家/地区': 'Registered country / region',
  '分配类型': 'Allocation type',
  'RIR 句柄': 'RIR handle',
  'AS 标识': 'AS name',
  'RIR 已分配网段': 'RIR-allocated range',
  '已分配 ASN': 'Allocated ASN',
  '解析受限 / 异常状态': 'Resolution restricted / status warning',
  '已注册 · 状态正常': 'Registered · no status warnings',
  '正常生效': 'Active',
  '正常': 'OK',
  '注册商转移锁': 'Registrar transfer lock',
  '注册局转移锁': 'Registry transfer lock',
  '注册商更新锁': 'Registrar update lock',
  '注册局更新锁': 'Registry update lock',
  '注册商删除锁': 'Registrar delete lock',
  '注册局删除锁': 'Registry delete lock',
  '暂停解析': 'Resolution on hold',
  '注册局暂停解析': 'Registry hold',
  '自动续费宽限期': 'Auto-renew grace period',
  '赎回期': 'Redemption period',
  '等待删除': 'Pending deletion',
  '当前记录处于正常活跃状态。': 'This record is active.',
  '没有任何限制，可以正常解析、续费、修改和转移。': 'No status restrictions on resolution, renewal, updates or transfer.',
  '注册商禁止把域名转出到其他注册商，防止被恶意转走。绝大多数域名默认开启，属于正常保护。': 'The registrar has locked transfers to another registrar. This is a common security setting.',
  '注册局层面禁止转移，级别高于注册商锁，常见于高价值域名或争议处理期间。': 'The registry has locked transfers. This may be a security measure or part of a dispute.',
  '注册商禁止修改联系人、DNS 服务器等注册信息，防止信息被篡改。': 'The registrar has locked changes to registration data, including contacts and nameservers.',
  '注册局层面禁止修改任何注册信息，需要先由注册局解锁。': 'Registration data cannot be changed until the registry removes this lock.',
  '注册商禁止删除域名，防止误删或被恶意删除。': 'The registrar has locked domain deletion.',
  '注册局层面禁止删除，保护级别更高。': 'The registry has locked domain deletion.',
  '注册商暂停了域名的 DNS 解析，网站和邮箱都会失效。常见原因是欠费、未完成实名或投诉处理。': 'The registrar has suspended DNS resolution. Website and email service may be unavailable; contact the registrar for the reason.',
  '注册局暂停了域名的解析，常见于未完成实名认证或违规处置，需要联系注册商核实。': 'The registry has suspended DNS resolution. Contact the registrar for details.',
  '到期后注册局已自动续费一年，约 45 天内注册商仍可撤销这次续费。': 'The registry has auto-renewed the domain after expiry. The registrar can usually reverse this within about 45 days.',
  '域名已过期并被删除，原持有人约 30 天内可以支付赎回费找回，逾期进入删除流程。': 'The expired domain has been deleted. The previous registrant usually has about 30 days to restore it for a fee.',
  '域名即将被注册局删除并重新开放注册，通常持续约 5 天，这个阶段已无法赎回。': 'The domain is awaiting deletion, usually for about five days. Restoration is no longer available at this stage.',
  '注册局返回的状态标记。': 'Status returned by the registry.',
  '请输入要查询的域名、IP 地址或 ASN。': 'Enter a domain, IP address or ASN.',
  '输入格式无法识别，请输入有效的域名（如 judgeip.com）、IP 地址或 AS 号。': 'Enter a valid domain (such as judgeip.com), IP address or ASN.',
  '连接注册局 RDAP 服务超时或网络异常，请稍后再试。': 'The registry RDAP request timed out or failed. Try again later.',
};

const PATTERNS: Array<[RegExp, (...m: string[]) => string]> = [
  [/^(\d+) 小时前$/, (_, n) => `${n} hour${n === '1' ? '' : 's'} ago`],
  [/^还有 (\d+) 小时$/, (_, n) => `In ${n} hour${n === '1' ? '' : 's'}`],
  [/^([\d.]+) 年前$/, (_, n) => `${n} years ago`],
  [/^(\d+) 天前$/, (_, n) => `${n} day${n === '1' ? '' : 's'} ago`],
  [/^还有 (\d+) 天$/, (_, n) => `In ${n} day${n === '1' ? '' : 's'}`],
  [/^距到期还有 (\d+) 天 · 生命周期已走过 (\d+)%$/, (_, n, pct) => `${n} days until expiry · ${pct}% of registration period elapsed`],
  [/^已过期 (\d+) 天$/, (_, n) => `Expired ${n} days ago`],
  [/^域名年龄 ([\d.]+) 年$/, (_, n) => `Domain age: ${n} years`],
  [/^域名年龄 (\d+) 天$/, (_, n) => `Domain age: ${n} days`],
  [/^注册局返回未找到「(.*)」的记录（该域名可能尚未注册，或该顶级域暂未开放 RDAP）。$/, (_, q) => `No registry record found for “${q}”. The domain may be unregistered, or its TLD may not support RDAP.`],
  [/^未在注册局 RDAP 中查到「(.*)」的记录。$/, (_, q) => `No registry RDAP record found for “${q}”.`],
  [/^上游注册局返回 HTTP (\d+)，请稍后重试。$/, (_, code) => `The registry returned HTTP ${code}. Try again later.`],
];

function translate(text: string): string {
  if (LABELS[text]) return LABELS[text];
  for (const [pattern, render] of PATTERNS) {
    const match = text.match(pattern);
    if (match) return render(...match);
  }
  return text;
}

/** Translate generated UI text only; registry data and raw JSON remain unchanged. */
export function localizeRdap(result: RdapLookupView, lang: Lang): RdapLookupView {
  if (lang !== 'en') return result;
  return {
    ...result,
    error: result.error ? translate(result.error) : undefined,
    eyebrow: translate(result.eyebrow),
    badges: result.badges.map((b) => ({ ...b, text: translate(b.text) })),
    life: result.life ? { ...result.life, caption: translate(result.life.caption) } : undefined,
    statuses: result.statuses.map((s) => ({ ...s, label: translate(s.label), note: translate(s.note) })),
    dates: result.dates.map((d) => ({ ...d, label: translate(d.label), hint: translate(d.hint) })),
    details: result.details.map((d) => ({
      ...d,
      label: translate(d.label),
      value: d.label === 'DNSSEC' ? translate(d.value) : d.value,
    })),
  };
}
