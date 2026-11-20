/* JudgeIP — 检测历史（/ai、/gpt、/claude 共用）。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   页面上放一个 <section data-history="存储键">，里面有 [data-history-list] 与 [data-history-clear]；
   检测脚本跑完后调 JudgeHistory.mount(section).add(entry) 记一条。
   entry：{ main, note, tone: ok|warn|leak, label, key }——key 相同的两条视为同一出口，
   不同就在新的那条上标「出口变了」；不给 key 的页面（Claude 检测）不做这项比较。

   记录只写进本机 localStorage，最多 MAX 条，不会发送给本站；
   隐私模式或存储被禁用时整块保持隐藏，检测本身不受影响。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

  var MAX = 20;

  function read(key) {
    try {
      var list = JSON.parse(window.localStorage.getItem(key) || '[]');
      return Array.isArray(list) ? list : [];
    } catch (e) {
      return [];
    }
  }

  function write(key, list) {
    try {
      if (list.length) window.localStorage.setItem(key, JSON.stringify(list));
      else window.localStorage.removeItem(key);
      return true;
    } catch (e) {
      return false;
    }
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function pad(n) {
    return (n < 10 ? '0' : '') + n;
  }

  /* 「11-20 14:32」：同一年内不写年份，跨年才补上 */
  function when(t) {
    var d = new Date(t);
    var head = d.getFullYear() === new Date().getFullYear() ? '' : d.getFullYear() + '-';
    return head + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function mount(section) {
    var key = section && section.getAttribute('data-history');
    var list = section && section.querySelector('[data-history-list]');
    var clear = section && section.querySelector('[data-history-clear]');
    if (!key || !list) return { add: function () {} };

    function render() {
      var items = read(key);
      list.textContent = '';
      if (!items.length) {
        var empty = el('div', 'row');
        empty.appendChild(el('div', 'row__label', T('暂无记录', 'No entries yet')));
        empty.appendChild(el('div', 'row__value dim', T('检测完成后会在这里记一条，方便对比出口有没有变。', 'Each completed check is recorded here so you can see whether the exit changed.')));
        list.appendChild(empty);
      }
      items.forEach(function (item, i) {
        var older = items[i + 1];
        var row = el('div', 'row history__row');
        var label = el('div', 'row__label mono', when(item.t));
        label.title = new Date(item.t).toLocaleString(window.I18N ? I18N.locale : undefined);
        var value = el('div', 'row__value history__value');
        value.appendChild(el('span', 'mono history__main', item.main || '—'));
        if (item.label) value.appendChild(el('span', 'tag tag--' + (item.tone || 'muted'), item.label));
        if (item.key && older && older.key && older.key !== item.key) {
          var changed = el('span', 'tag tag--warn', T('出口变了', 'Exit changed'));
          changed.title = T('上一次是 ', 'Previous: ') + (older.main || '—');
          value.appendChild(changed);
        }
        if (item.note) value.appendChild(el('span', 'dim history__note', item.note));
        row.appendChild(label);
        row.appendChild(value);
        list.appendChild(row);
      });
      if (clear) clear.hidden = !items.length;
    }

    /* 先试写一次：localStorage 不可用就不展示这块，免得出现一个永远空着的「检测历史」 */
    if (!write(key + ':probe', [1])) return { add: function () {} };
    write(key + ':probe', []);

    if (clear) {
      clear.addEventListener('click', function () {
        write(key, []);
        render();
      });
    }

    section.hidden = false;
    render();

    return {
      add: function (entry) {
        var items = read(key);
        entry.t = Date.now();
        items.unshift(entry);
        write(key, items.slice(0, MAX));
        render();
      }
    };
  }

  window.JudgeHistory = { mount: mount };
})();
