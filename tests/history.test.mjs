import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../public/assets/js/history.js', import.meta.url), 'utf8');
class Element {
  constructor() { this.children = []; this.text = ''; this.hidden = true; }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); }
  appendChild(child) { this.children.push(child); }
  addEventListener(event, callback) { this[event] = callback; }
}
function mount(lang, storage) {
  const list = new Element(), clear = new Element();
  const section = { getAttribute: () => 'history', querySelector: (s) => s.includes('list') ? list : clear };
  const I18N = { locale: lang === 'en' ? 'en-US' : 'zh-CN' };
  const context = { I18N, window: { I18N, T: (zh, en) => lang === 'en' ? en : zh, localStorage: { getItem: (k) => storage[k], setItem: (k, v) => { storage[k] = v; }, removeItem: (k) => { delete storage[k]; } } }, document: { createElement: () => new Element(), querySelectorAll: () => [{ getAttribute: (name) => name === 'data-signal' ? 'timezone' : lang === 'en' ? 'Time zone' : '时区' }] } };
  vm.runInNewContext(source, context);
  return { history: context.window.JudgeHistory.mount(section), list, clear };
}

test('history stores structured data and renders both languages after navigation', () => {
  const storage = {};
  mount('zh', storage).history.add({ kind: 'ai', ips: ['8.8.8.8'], countries: ['US'], conclusion: 'consistent', tone: 'ok', key: '8.8.8.8' });
  const en = mount('en', storage);
  assert.match(en.list.textContent, /United States/);
  assert.match(en.list.textContent, /Service exits agree/);
  assert.doesNotMatch(en.list.textContent, /[\p{Script=Han}]/u);
  en.history.add({ kind: 'claude', score: 45, band: 'medium', tone: 'warn', signals: ['timezone'] });
  const zh = mount('zh', storage);
  assert.match(zh.list.textContent, /中等风险/);
  assert.match(zh.list.textContent, /命中：时区/);
  assert.match(zh.list.textContent, /美国/);
  assert.equal(JSON.parse(storage.history)[0].v, 2);
  zh.clear.click();
  assert.equal(storage.history, undefined);
});

test('legacy and malformed local records cannot leak old-language copy or break rendering', () => {
  const storage = { history: JSON.stringify([null, { main: '没有读到出口', label: '正常', note: '美国', t: Date.now() }, { main: '8.8.8.8', t: Date.now() }]) };
  const { list } = mount('en', storage);
  assert.match(list.textContent, /Legacy entry/);
  assert.match(list.textContent, /8.8.8.8/);
  assert.doesNotMatch(list.textContent, /[\p{Script=Han}]/u);
});
