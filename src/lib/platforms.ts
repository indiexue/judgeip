/**
 * 平台检测页（/platforms）的平台表和判定规则。页面上公布的门槛、要求和实际判定用的是同一份。
 * 门槛和要求是 JudgeIP 自己定的经验值，不是任何平台的官方规则。
 */
import type { HomeIpLookupResult } from './ipcx-lookup';
import type { Lang } from './i18n';

export type PlatformCategory = 'payment' | 'ecommerce' | 'freelance' | 'social';
export type PlatformRequirement = 'residential' | 'native' | 'noProxy' | 'clean';
export type PlatformLevel = 'pass' | 'warn' | 'fail' | 'unknown';

type Text = { zh: string; en: string };

export interface Platform {
  id: string;
  name: string;
  category: PlatformCategory;
  /* 能读到 /cdn-cgi/trace 的主机名；留空表示看不到这家平台眼里的出口，只能按当前 IP 推断 */
  traceHost: string;
  minScore: number;
  requires: PlatformRequirement[];
}

export interface PlatformVerdict {
  level: PlatformLevel;
  reasons: Text[];
}

export const PLATFORM_CATEGORIES: Array<{ key: PlatformCategory; label: Text }> = [
  { key: 'payment', label: { zh: '支付与收款', en: 'Payments' } },
  { key: 'ecommerce', label: { zh: '跨境电商', en: 'E-commerce' } },
  { key: 'freelance', label: { zh: '接单平台', en: 'Freelance' } },
  { key: 'social', label: { zh: '社交与内容', en: 'Social and content' } },
];

export const REQUIREMENT_LABELS: Record<PlatformRequirement, Text> = {
  residential: { zh: '住宅或移动网络', en: 'Residential or mobile' },
  native: { zh: '原生 IP', en: 'Native IP' },
  noProxy: { zh: '无代理标记', en: 'No proxy flag' },
  clean: { zh: '未上黑名单', en: 'Not blocklisted' },
};

export const LEVEL_LABELS: Record<PlatformLevel, Text> = {
  pass: { zh: '达标', en: 'Meets the bar' },
  warn: { zh: '有风险', en: 'At risk' },
  fail: { zh: '不达标', en: 'Below the bar' },
  unknown: { zh: '无法判断', en: 'Undetermined' },
};

export const PLATFORMS: Platform[] = [
  { id: 'paypal', name: 'PayPal', category: 'payment', traceHost: '', minScore: 75, requires: ['residential', 'native', 'noProxy', 'clean'] },
  { id: 'stripe', name: 'Stripe', category: 'payment', traceHost: '', minScore: 70, requires: ['native', 'noProxy', 'clean'] },
  { id: 'wise', name: 'Wise', category: 'payment', traceHost: 'wise.com', minScore: 70, requires: ['native', 'noProxy', 'clean'] },
  { id: 'revolut', name: 'Revolut', category: 'payment', traceHost: 'www.revolut.com', minScore: 70, requires: ['native', 'noProxy', 'clean'] },
  { id: 'payoneer', name: 'Payoneer', category: 'payment', traceHost: 'payoneer.com', minScore: 70, requires: ['noProxy', 'clean'] },
  { id: 'airwallex', name: 'Airwallex', category: 'payment', traceHost: 'www.airwallex.com', minScore: 65, requires: ['noProxy', 'clean'] },

  { id: 'amazon', name: 'Amazon', category: 'ecommerce', traceHost: '', minScore: 80, requires: ['residential', 'native', 'noProxy', 'clean'] },
  { id: 'tiktok-shop', name: 'TikTok Shop', category: 'ecommerce', traceHost: '', minScore: 80, requires: ['residential', 'native', 'noProxy', 'clean'] },
  { id: 'ebay', name: 'eBay', category: 'ecommerce', traceHost: '', minScore: 75, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'etsy', name: 'Etsy', category: 'ecommerce', traceHost: '', minScore: 75, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'temu', name: 'Temu', category: 'ecommerce', traceHost: 'www.temu.com', minScore: 65, requires: ['noProxy', 'clean'] },
  { id: 'shopify', name: 'Shopify', category: 'ecommerce', traceHost: 'www.shopify.com', minScore: 60, requires: ['noProxy', 'clean'] },

  { id: 'upwork', name: 'Upwork', category: 'freelance', traceHost: 'www.upwork.com', minScore: 75, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'fiverr', name: 'Fiverr', category: 'freelance', traceHost: 'www.fiverr.com', minScore: 70, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'freelancer', name: 'Freelancer', category: 'freelance', traceHost: '', minScore: 65, requires: ['noProxy', 'clean'] },
  { id: 'toptal', name: 'Toptal', category: 'freelance', traceHost: 'www.toptal.com', minScore: 60, requires: ['noProxy'] },

  { id: 'tiktok', name: 'TikTok', category: 'social', traceHost: '', minScore: 80, requires: ['residential', 'native', 'noProxy'] },
  { id: 'facebook', name: 'Facebook', category: 'social', traceHost: '', minScore: 75, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'instagram', name: 'Instagram', category: 'social', traceHost: '', minScore: 75, requires: ['residential', 'noProxy', 'clean'] },
  { id: 'linkedin', name: 'LinkedIn', category: 'social', traceHost: 'www.linkedin.com', minScore: 65, requires: ['noProxy', 'clean'] },
  { id: 'patreon', name: 'Patreon', category: 'social', traceHost: 'www.patreon.com', minScore: 65, requires: ['noProxy', 'clean'] },
  { id: 'x', name: 'X', category: 'social', traceHost: 'x.com', minScore: 60, requires: ['noProxy'] },
  { id: 'reddit', name: 'Reddit', category: 'social', traceHost: '', minScore: 60, requires: ['noProxy', 'clean'] },
  { id: 'quora', name: 'Quora', category: 'social', traceHost: 'www.quora.com', minScore: 60, requires: ['noProxy'] },
];

type Facts = Pick<HomeIpLookupResult, 'isBogon' | 'usageType' | 'isNative' | 'isProxy' | 'hasThreat' | 'score'>;

/**
 * 按一个 IP 的查询结果判定它在某个平台上够不够格。
 * 有一项不满足就是不达标；没有不满足的、但缺数据时是无法判断，缺的数据不当作正常。
 */
export function judgePlatform(platform: Platform, info: Facts): PlatformVerdict {
  if (info.isBogon) {
    return { level: 'unknown', reasons: [{ zh: '保留地址，不是公网出口', en: 'Reserved address, not a public egress' }] };
  }

  const fails: Text[] = [];
  const warns: Text[] = [];
  const unknowns: Text[] = [];

  for (const need of platform.requires) {
    if (need === 'residential') {
      if (info.usageType === 'unknown') unknowns.push({ zh: '网络类型未知', en: 'Network type unknown' });
      else if (info.usageType === 'hosting') fails.push({ zh: '数据中心 IP', en: 'Data center IP' });
      else if (info.usageType === 'cdn') fails.push({ zh: 'CDN / 任播 IP', en: 'CDN / anycast IP' });
      else if (info.usageType === 'reserved') fails.push({ zh: '保留地址', en: 'Reserved address' });
      else if (info.usageType !== 'residential' && info.usageType !== 'mobile') {
        warns.push({ zh: '企业或教育网络，不是住宅', en: 'Business or education network, not residential' });
      }
    } else if (need === 'native') {
      if (info.isNative === null) unknowns.push({ zh: '注册地或定位缺失', en: 'Registry or geolocation country missing' });
      else if (!info.isNative) warns.push({ zh: '广播 IP，注册地与定位不一致', en: 'Geo-announced: registry and location differ' });
    } else if (need === 'noProxy') {
      if (info.isProxy === null) unknowns.push({ zh: '代理标记没查到', en: 'Proxy flag unavailable' });
      else if (info.isProxy) fails.push({ zh: '被标记为代理 / VPN / Tor', en: 'Flagged as proxy / VPN / Tor' });
    } else if (need === 'clean') {
      if (info.hasThreat === null) unknowns.push({ zh: '黑名单没查全', en: 'Blocklist check incomplete' });
      else if (info.hasThreat) fails.push({ zh: '命中黑名单或威胁记录', en: 'Blocklisted or has threat records' });
    }
  }

  if (info.score === null) unknowns.push({ zh: '没有评分', en: 'No score' });
  else if (info.score < platform.minScore) {
    fails.push({ zh: `评分 ${info.score}，低于门槛 ${platform.minScore}`, en: `Score ${info.score}, below the ${platform.minScore} bar` });
  }

  if (fails.length > 0) return { level: 'fail', reasons: [...fails, ...warns] };
  if (unknowns.length > 0) return { level: 'unknown', reasons: [...unknowns, ...warns] };
  if (warns.length > 0) return { level: 'warn', reasons: warns };
  return { level: 'pass', reasons: [] };
}

/** 全部平台的判定，按 PLATFORMS 的顺序。给页面和 /api/platforms 共用。 */
export function judgePlatforms(info: Facts, lang: Lang) {
  return PLATFORMS.map((platform) => {
    const verdict = judgePlatform(platform, info);
    return {
      id: platform.id,
      level: verdict.level,
      label: LEVEL_LABELS[verdict.level][lang],
      reasons: verdict.reasons.map((reason) => reason[lang]),
    };
  });
}
