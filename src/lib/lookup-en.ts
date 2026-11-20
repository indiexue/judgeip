/**
 * 首页 IP 查询结果的英文版。lookupIpFull 按中文生成并缓存结果；英文页在渲染前把其中的
 * 展示文案换成英文，查询与缓存逻辑不必知道语言。新增中文标签时在 LABELS 里补一条即可，
 * 漏掉的只会原样显示中文，不会出错。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';

const LABELS: Record<string, string> = {
  // 网络类型
  家庭宽带: 'Residential',
  数据中心: 'Data center',
  'CDN / 任播': 'CDN / anycast',
  移动网络: 'Mobile',
  教育网: 'Education',
  企业专线: 'Business',
  保留地址: 'Reserved',
  '本地 / 内网保留网段': 'Local / private reserved range',
  '内网 / 保留地址': 'Private / reserved',
  未知: 'Unknown',
  其他: 'Other',
  // 威胁与代理
  扫描活动记录: 'Scanning activity',
  存在风险记录: 'Risk records found',
  无威胁记录: 'No threat records',
  'Tor 出口': 'Tor exit',
  'VPN 节点': 'VPN node',
  公开代理: 'Public proxy',
  非代理: 'Not a proxy',
  不适用: 'N/A',
  'RPKI 有效 (Valid)': 'RPKI valid',
  'RPKI 异常 (Invalid)': 'RPKI invalid',
  '未签发 ROA': 'No ROA',
  // 风险细项
  '代理 / VPN 隧道': 'Proxy / VPN tunnel',
  '命中 VPN': 'VPN detected',
  疑似代理: 'Possible proxy',
  未发现: 'Not found',
  'Tor 匿名节点': 'Tor node',
  代理特征端口: 'Proxy ports',
  '仅支持 IPv4': 'IPv4 only',
  无暴露: 'None open',
  'DNSBL 邮件/垃圾黑名单': 'DNSBL spam blocklists',
  扫描器与自动化标记: 'Scanner / automation flags',
  存在扫描行为: 'Scanning seen',
  无记录: 'No records',
  '失陷主机 / 漏洞暴露': 'Compromise / exposed CVEs',
  失陷标记: 'Compromised',
  正常: 'OK',
  // 场景适配
  跨境电商: 'Cross-border e-commerce',
  '仅买家/慎登店': 'Buyer only / careful with seller login',
  高风险: 'High risk',
  'Amazon / Shopee / TikTok Shop / Temu 卖家后台环境要求': 'Seller-center requirements on Amazon / Shopee / TikTok Shop / Temu',
  跨境支付: 'Cross-border payments',
  适配: 'Good fit',
  '需 3DS 验证': 'Needs 3DS',
  易拒付: 'Likely declined',
  'Stripe / PayPal 账单地址与欺诈分风控': 'Stripe / PayPal billing address and fraud scoring',
  'AI 应用': 'AI apps',
  'API 可用/网页慎用': 'API OK / web risky',
  易弹验证: 'Frequent verification',
  'ChatGPT / Claude / Gemini 地区与网络类型参考': 'ChatGPT / Claude / Gemini region and network-type indicators',
  社媒运营: 'Social media',
  原生适配: 'Native fit',
  广播偏区注意: 'Region skew possible',
  限流风险: 'Throttling risk',
  'TikTok / X / Facebook / Instagram 推流权重与注册验证': 'TikTok / X / Facebook / Instagram reach and sign-up verification',
  广告投放: 'Ad accounts',
  需防关联: 'Watch account linking',
  易封户: 'Likely banned',
  'Meta Ads / Google Ads 投放账户登录安全': 'Meta Ads / Google Ads account sign-in safety',
  流媒体解锁: 'Streaming',
  完整版权库: 'Full catalog',
  '仅自制剧/偏移': 'Originals only / wrong region',
  机房受限: 'Hosting IP blocked',
  'Netflix / Disney+ / Spotify 本土版权识别': 'Netflix / Disney+ / Spotify regional catalog detection',
  游戏联机: 'Online gaming',
  可用: 'Usable',
  反作弊受限: 'Anti-cheat limits',
  'Steam / 主机联机跨区与反作弊节点限制': 'Steam / console cross-region and anti-cheat limits',
  加密货币: 'Crypto',
  '易触发 KYC': 'Likely KYC',
  '主流交易所地区合规限制与异常 IP 二次验证': 'Exchange region compliance and extra verification for unusual IPs',
  // 大洲
  亚洲: 'Asia',
  北美洲: 'North America',
  欧洲: 'Europe',
  南美洲: 'South America',
  大洋洲: 'Oceania',
  非洲: 'Africa',
  南极洲: 'Antarctica',
};

/* 带参数的标签：中文模板 → 英文模板 */
const PATTERNS: Array<[RegExp, (...m: string[]) => string]> = [
  [/^命中黑名单 \((.*)\)$/, (_, l) => `Blocklisted (${l})`],
  [/^地区受限 \((.*)\)$/, (_, c) => `Region blocked (${c})`],
  [/^合规受限 \((.*)\)$/, (_, c) => `Compliance limits (${c})`],
  [/^暴露 \((.*)\)$/, (_, p) => `Open (${p})`],
  [/^命中 (\d+)\/(\d+) \((.*)\)$/, (_, a, b, l) => `Listed ${a}/${b} (${l})`],
  [/^0\/(\d+) 全部通过$/, (_, b) => `0/${b} clean`],
  [/^(\d+) 个历史 CVE$/, (_, n) => `${n} past CVEs`],
];

const SHORT_COUNTRY_EN: Record<string, string> = { CN: 'Mainland China', HK: 'Hong Kong', MO: 'Macau', TW: 'Taiwan' };

export function labelEn(text: string): string {
  if (!text) return text;
  if (LABELS[text]) return LABELS[text];
  for (const [re, fn] of PATTERNS) {
    const m = text.match(re);
    if (m) return fn(...m);
  }
  return text;
}

export function countryNameEn(cc: string, fallback = ''): string {
  const up = (cc || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(up)) return fallback || 'Unknown';
  if (SHORT_COUNTRY_EN[up]) return SHORT_COUNTRY_EN[up];
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(up) || fallback || up;
  } catch {
    return fallback || up;
  }
}

export function localizeLookup(info: HomeIpLookupResult, lang: Lang): HomeIpLookupResult {
  if (lang !== 'en') return info;
  return {
    ...info,
    ipTypeLabel: labelEn(info.ipTypeLabel),
    isp: labelEn(info.isp),
    org: labelEn(info.org),
    threatLabel: labelEn(info.threatLabel),
    proxyLabel: labelEn(info.proxyLabel),
    rpkiLabel: labelEn(info.rpkiLabel),
    countryZh: info.isBogon ? labelEn(info.countryZh) : countryNameEn(info.countryCode, info.countryZh),
    continentZh: labelEn(info.continentZh),
    scenes: info.scenes.map((s) => ({ ...s, label: labelEn(s.label), status: labelEn(s.status), note: labelEn(s.note) })),
    riskChecks: info.riskChecks.map((r) => ({ ...r, label: labelEn(r.label), status: labelEn(r.status) })),
  };
}
