import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../public/assets/js/check.js', import.meta.url), 'utf8');
const probeSource = await readFile(new URL('../public/assets/js/probe.js', import.meta.url), 'utf8');

class Element {
  constructor() { this.children = []; this.text = ''; this.hidden = true; this.disabled = false; }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return this.text + this.children.map((child) => child.textContent).join(''); }
  appendChild(child) { this.children.push(child); }
  addEventListener(event, callback) { this[event] = callback; }
}

async function checkup(options = {}) {
  const cells = new Map();
  const requests = [];
  const root = {
    querySelector(selector) {
      if (!cells.has(selector)) cells.set(selector, new Element());
      return cells.get(selector);
    },
    getAttribute() { return options.visibleIp || '8.8.8.8'; },
  };
  const cell = (name) => root.querySelector(`[data-check-${name}]`);
  const dimension = (name) => root.querySelector(`[data-dim="${name}"] [data-dim-val]`).textContent;
  const info = { score: 100, isDatacenter: false, isProxy: false, timezone: 'UTC', countryCode: 'US', countryZh: 'United States', asnCode: 'AS15169', ipTypeLabel: 'Residential', ...options.info };
  const response = (data) => ({ ok: true, json: async () => data, text: async () => data });
  const window = {
    I18N: { lang: options.lang || 'en' },
    T: (zh, en) => options.lang === 'zh' ? zh : en,
    outerWidth: 1440, outerHeight: 900,
    setTimeout: (fn, ms) => setTimeout(fn, ms >= 3000 ? 20 : ms),
    fetch: async (url) => {
      requests.push(url);
      if (url.includes('icanhazip')) return response(options.v4 === undefined ? '8.8.8.8' : options.v4);
      if (url.includes('/api/ipinfo')) {
        if (options.ipFailure) throw new Error('offline');
        return response({ ok: true, info });
      }
      if (url.includes('edns.ip-api.com')) {
        if (options.dnsFailure || !url.startsWith('https://edns.')) throw new Error('offline');
        return response({ dns: { ip: '1.1.1.1' } });
      }
      if (url.startsWith('/dnsleak/api')) return response({ ok: true, client: { country_code: 'US' }, resolvers: [{ ip: '1.1.1.1', country_code: 'US', type: options.resolverType === undefined ? 'public' : options.resolverType }] });
      if (url.includes('chatgpt.com')) {
        if (options.aiPending) return { ok: true, text: () => new Promise(() => {}) };
        if (options.aiForbidden) return { ok: false, status: 403 };
        return response(options.aiInvalid ? 'loc=US\n' : 'loc=US\nip=8.8.8.8\n');
      }
      throw new Error('Unexpected URL: ' + url);
    },
    RTCPeerConnection: class {
      createDataChannel() {}
      async createOffer() {
        if (options.rtcFailure) throw new Error('STUN failed');
        return {};
      }
      async setLocalDescription() {
        this.onicecandidate({ candidate: { address: options.candidate || '8.8.8.8', type: 'srflx' } });
        this.onicecandidate({ candidate: null });
      }
      close() {}
    },
  };
  const context = vm.createContext({
    window, I18N: window.I18N, navigator: { languages: ['en-US'], language: 'en-US', webdriver: false },
    document: { readyState: 'complete', getElementById: () => root, createElement: () => new Element(), addEventListener() {} },
    Intl: { DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: 'UTC' }) }), DisplayNames: Intl.DisplayNames },
    AbortController, setTimeout: window.setTimeout, clearTimeout,
  });
  vm.runInContext(probeSource, context);
  vm.runInContext(source, context);
  async function finish() {
    const deadline = Date.now() + 2000;
    while (cell('run').disabled && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(cell('run').disabled, false, 'run must finish and restore the button');
  }
  await finish();
  return { cell, dimension, requests, options, info, finish };
}

test('checkup completes all six dimensions only with usable evidence, including DNS fallback', async () => {
  const { cell, requests } = await checkup();
  assert.equal(cell('score').textContent, '100 / 100');
  assert.equal(cell('passed').textContent, 'Passed 6 / 6 · Warnings 0 · Incomplete 0');
  assert.equal(cell('verdict').className, 'verdict is-good');
  assert.ok(requests.some((url) => url.startsWith('https://edns.ip-api.com/')));
});

test('failed WebRTC, missing DNS and HTTP 403 cannot pass or produce an overall score', async () => {
  for (const lang of ['en', 'zh']) {
    const { cell, dimension } = await checkup({ lang, rtcFailure: true, dnsFailure: true, aiForbidden: true });
    assert.equal(cell('score').textContent, lang === 'en' ? 'Incomplete; no score' : '未完成，暂不评分');
    assert.equal(cell('verdict').className, 'verdict is-warn');
    for (const name of ['webrtc', 'dns', 'ai']) assert.ok(dimension(name).startsWith(lang === 'en' ? 'Incomplete' : '未完成'));
    assert.ok(dimension('ai').includes('403'));
  }
});

test('failed IP lookup does not prevent independent checks from completing', async () => {
  const { cell, dimension } = await checkup({ ipFailure: true });
  assert.equal(cell('score').textContent, 'Incomplete; no score');
  assert.ok(dimension('purity').startsWith('Incomplete'));
  assert.ok(dimension('consistency').startsWith('Incomplete'));
  assert.ok(dimension('ai').startsWith('Passed'));
  assert.ok(dimension('webrtc').startsWith('Passed'));
});

test('missing security booleans, resolver types or valid trace remain incomplete', async () => {
  for (const options of [
    { info: { isProxy: undefined } },
    { info: { isDatacenter: null } },
    { resolverType: null },
    { resolverType: 'unknown' },
    { aiInvalid: true },
  ]) {
    const { cell } = await checkup(options);
    assert.equal(cell('score').textContent, 'Incomplete; no score');
  }
});

test('WebRTC dual-stack and /64 comparisons do not claim a leak or pass without a matching family', async () => {
  const dual = await checkup({ visibleIp: '2606:4700::1' });
  assert.ok(dual.dimension('webrtc').startsWith('Passed'));
  const samePrefix = await checkup({ visibleIp: '2606:4700:1:2::1', candidate: '2606:4700:1:2::abcd' });
  assert.ok(samePrefix.dimension('webrtc').startsWith('Passed'));
  const unpaired = await checkup({ candidate: '2606:4700::1' });
  assert.ok(unpaired.dimension('webrtc').startsWith('Incomplete'));
  assert.equal(unpaired.cell('score').textContent, 'Incomplete; no score');
  const different = await checkup({ candidate: '1.1.1.1' });
  assert.ok(different.dimension('webrtc').includes('Same-family exit differs'));
  assert.ok(different.dimension('webrtc').includes('does not prove a proxy leak'));
});

test('response-body deadlines settle incomplete and reruns clear the previous summary', async () => {
  const current = await checkup({ aiPending: true });
  assert.equal(current.cell('score').textContent, 'Incomplete; no score');
  current.options.aiPending = false;
  current.cell('run').click();
  assert.equal(current.cell('score').textContent, 'Checking…');
  assert.equal(current.cell('passed').textContent, 'Checking…');
  assert.equal(current.cell('verdict').hidden, true);
  await current.finish();
  assert.equal(current.cell('score').textContent, '100 / 100');
});
