import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { getLang, localePath, splitLocale } from '../src/lib/i18n.ts';
import { labelEn, localizeLookup } from '../src/lib/lookup-en.ts';
import { localizeRdap } from '../src/lib/rdap-en.ts';

const han = /\p{Script=Han}/u;

test('locale routing defaults to Chinese and preserves queries', () => {
  assert.equal(getLang(undefined), 'zh');
  assert.equal(getLang({ lang: 'en' }), 'en');
  assert.deepEqual(splitLocale('/en'), { lang: 'en', path: '/' });
  assert.deepEqual(splitLocale('/en/'), { lang: 'en', path: '/' });
  assert.deepEqual(splitLocale('/en/whois'), { lang: 'en', path: '/whois' });
  assert.deepEqual(splitLocale('/english'), { lang: 'zh', path: '/english' });
  assert.equal(localePath('/', 'en'), '/en');
  assert.equal(localePath('/whois?q=AS13335', 'en'), '/en/whois?q=AS13335');
  assert.equal(localePath('/card?ip=::1', 'zh'), '/card?ip=::1');
});

test('browser locale helper agrees with server paths', async () => {
  const script = await readFile(new URL('../public/assets/js/boot.js', import.meta.url), 'utf8');
  for (const lang of ['en', 'zh-CN']) {
    const context = {
      window: { localStorage: { getItem: () => 'light' } },
      document: { documentElement: { classList: { add() {} }, getAttribute: () => lang, setAttribute() {} } },
    };
    vm.runInNewContext(script, context);
    for (const path of ['/', '/whois?q=1.1.1.1', '/ip/::1']) {
      assert.equal(context.window.I18N.path(path), localePath(path, lang === 'en' ? 'en' : 'zh'));
    }
    assert.equal(context.window.T('中文', 'English'), lang === 'en' ? 'English' : '中文');
  }
});

test('lookup localization translates labels without changing cached source', () => {
  const source = {
    ip: '127.0.0.1', isBogon: true, countryZh: '保留地址', countryCode: '',
    ipTypeLabel: '内网 / 保留地址', isp: '本地 / 内网保留网段', org: '本地 / 内网保留网段',
    threatLabel: '无威胁记录', proxyLabel: '非代理', rpkiLabel: '未签发 ROA', continentZh: '亚洲',
    scenes: [{ label: 'AI 应用', status: '地区受限 (CN)', note: 'ChatGPT / Claude / Gemini 地区与网络类型参考' }],
    riskChecks: [{ label: 'DNSBL 邮件/垃圾黑名单', status: '0/3 全部通过' }],
  };
  assert.equal(localizeLookup(source, 'zh'), source);
  const english = localizeLookup(source, 'en');
  assert.equal(han.test(JSON.stringify(english)), false);
  assert.equal(source.countryZh, '保留地址');
  assert.equal(labelEn('命中 2/3 (test)'), 'Listed 2/3 (test)');
});

test('RDAP localization covers dynamic labels, dates, status and errors, preserving upstream text', () => {
  const source = {
    ok: true, kind: 'domain', query: 'example.com', displayName: 'example.com',
    eyebrow: '域名', subline: '示例机构', sourceHost: 'example.com',
    badges: [{ text: '域名年龄 1.5 年', tone: 'gray' }, { text: '已注册 · 状态正常', tone: 'green' }],
    life: { regDate: '2025-01-01', expDate: '2027-01-01', pct: 50, tone: 'good', caption: '距到期还有 200 天 · 生命周期已走过 50%' },
    statuses: [{ code: 'active', label: '正常生效', note: '当前记录处于正常活跃状态。', tone: 'green' }],
    dates: [{ label: '注册时间', date: '2025-01-01', hint: '1.5 年前' }, { label: '到期时间', date: '2027-01-01', hint: '还有 200 天' }],
    nameservers: ['ns.example.com'],
    details: [{ label: '注册商', value: '示例机构' }, { label: 'DNSSEC', value: '已签名', badgeTone: 'green' }],
    rawJson: '{"organization":"示例机构"}', rawSizeKb: '1 KB',
  };
  assert.equal(localizeRdap(source, 'zh'), source);
  const result = localizeRdap(source, 'en');
  assert.equal(result.eyebrow, 'Domain');
  assert.equal(result.badges[0].text, 'Domain age: 1.5 years');
  assert.equal(result.life.caption, '200 days until expiry · 50% of registration period elapsed');
  assert.equal(result.statuses[0].label, 'Active');
  assert.equal(result.dates[1].hint, 'In 200 days');
  assert.equal(result.details[0].value, source.details[0].value);
  assert.equal(result.details[1].value, 'Signed');
  assert.equal(result.rawJson, source.rawJson);
  assert.equal(source.details[1].value, '已签名');
  for (const error of [
    '请输入要查询的域名、IP 地址或 ASN。',
    '输入格式无法识别，请输入有效的域名（如 judgeip.com）、IP 地址或 AS 号。',
    '注册局返回未找到「example.com」的记录（该域名可能尚未注册，或该顶级域暂未开放 RDAP）。',
    '未在注册局 RDAP 中查到「AS1」的记录。',
    '上游注册局返回 HTTP 503，请稍后重试。',
    '连接注册局 RDAP 服务超时或网络异常，请稍后再试。',
  ]) {
    assert.equal(han.test(localizeRdap({ ...source, ok: false, error }, 'en').error), false, error);
  }
});

test('English snippets have no Chinese copy or unprefixed page links', async () => {
  const pages = ['tools', 'connectivity', 'dnsleak', 'terms', 'fingerprint', 'cloudflare', 'ai', 'gpt', 'privacy', 'claude', 'split', 'ping', 'cdn', 'webrtc'];
  for (const page of pages) {
    const html = await readFile(new URL(`../src/snippets/en/${page}.html`, import.meta.url), 'utf8');
    assert.equal(han.test(html), false, page);
    assert.equal(/(?:href|action)="\/(?!en(?:\/|[?"#])|assets\/)/.test(html), false, page);
  }
});
