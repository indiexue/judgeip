/* JudgeIP — DNS 泄露检测（浏览器直连多路随机 EDNS 探针 + 出口比对）
   无需单独架设 UDP 53 裸机即可真实捕获当前网络生效的递归 DNS 解析器池，
   并通过 /dnsleak/api 补全每台递归解析器的国家、ISP、ASN 与泄露结论。 */
(function () {
  'use strict';

  var root = document.getElementById('dnsleak');
  if (!root) return;

  var PROBE_TIMEOUT = 7000;

  var probeCount = parseInt(root.getAttribute('data-probes'), 10) || 8;
  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();

  var runButton = root.querySelector('[data-dns-run]');
  var progress = root.querySelector('[data-dns-progress]');
  var verdict = root.querySelector('[data-dns-verdict]');
  var verdictTitle = root.querySelector('[data-dns-verdict-title]');
  var verdictNote = root.querySelector('[data-dns-verdict-note]');
  var fixNote = root.querySelector('[data-dns-fix]');
  var exitCell = root.querySelector('[data-dns-exit]');
  var countCell = root.querySelector('[data-dns-count]');
  var list = root.querySelector('[data-dns-list]');

  var running = false;

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) cell.appendChild(nodes[i]);
  }

  function flag(cc) {
    if (!/^[A-Za-z]{2}$/.test(cc)) return '';
    var up = cc.toUpperCase();
    return String.fromCodePoint(
      0x1F1E6 + up.charCodeAt(0) - 65,
      0x1F1E6 + up.charCodeAt(1) - 65
    );
  }

  function randomSubdomain() {
    var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var out = '';
    if (window.crypto && window.crypto.getRandomValues) {
      var bytes = new Uint8Array(32);
      window.crypto.getRandomValues(bytes);
      for (var i = 0; i < 32; i++) out += chars.charAt(bytes[i] % chars.length);
      return out;
    }
    for (var j = 0; j < 32; j++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
  }

  function singleEdnsProbe() {
    return new Promise(function (resolve) {
      var controller = window.AbortController ? new AbortController() : null;
      var timer = window.setTimeout(function () {
        if (controller) controller.abort();
        resolve(null);
      }, PROBE_TIMEOUT);

      var sub = randomSubdomain();
      var url = 'https://' + sub + '.edns.ip-api.com/json';
      var opts = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };
      if (controller) opts.signal = controller.signal;

      window.fetch(url, opts)
        .then(function (r) {
          if (!r.ok) return window.fetch('https://edns.ip-api.com/json?t=' + sub, opts);
          return r;
        })
        .then(function (r) { return r && r.ok ? r.json() : null; })
        .then(function (data) {
          window.clearTimeout(timer);
          if (data && data.dns && data.dns.ip) {
            resolve({
              ip: String(data.dns.ip).trim(),
              geo: data.dns.geo ? String(data.dns.geo).trim() : '',
              ecs: data.edns && data.edns.ip ? String(data.edns.ip).trim() : ''
            });
          } else {
            resolve(null);
          }
        })
        .catch(function () {
          window.clearTimeout(timer);
          resolve(null);
        });
    });
  }

  var ISP_TYPES = ['isp', 'mobile', 'business', 'dia', 'residential'];

  function classify(resolver, client) {
    if (client.asn && resolver.asn && resolver.asn === client.asn) {
      return { key: 'same', tone: 'ok', label: '与出口同网' };
    }
    if (ISP_TYPES.indexOf(resolver.type) !== -1 && resolver.country_code !== client.country_code) {
      return { key: 'isp', tone: 'leak', label: '运营商解析' };
    }
    if (client.country_code && resolver.country_code && resolver.country_code !== client.country_code) {
      return { key: 'cross', tone: 'warn', label: '跨境解析' };
    }
    return { key: 'third', tone: 'ok', label: '公共 / 同区解析' };
  }

  function resolverRow(resolver, state) {
    var row = el('div', 'dnsrow');

    var meta = el('div', 'dnsrow__meta');
    if (resolver.country_code) {
      var mark = flag(resolver.country_code);
      meta.appendChild(el(
        'span',
        'tag ' + (resolver.country_code === 'CN' ? 'tag--cn' : 'tag--global'),
        (mark ? mark + ' ' : '') + (resolver.country || resolver.country_code)
      ));
    }
    if (resolver.provider) meta.appendChild(el('span', 'tag tag--name', resolver.provider));
    row.appendChild(meta);

    var id = el('div', 'dnsrow__id');
    id.appendChild(el('div', 'dnsrow__ip mono', resolver.ip));

    var net = [];
    if (resolver.asn) net.push(resolver.asn);
    if (resolver.isp) net.push(resolver.isp);
    if (net.length) id.appendChild(el('div', 'dnsrow__net', net.join(' · ')));

    if (resolver.ecs) {
      var ecs = el('div', 'dnsrow__ecs');
      ecs.appendChild(el('span', 'tag tag--warn', 'ECS'));
      ecs.appendChild(el('span', 'mono', resolver.ecs));
      id.appendChild(ecs);
    }

    row.appendChild(id);

    var result = el('div', 'dnsrow__result');
    result.appendChild(el('span', 'tag tag--' + state.tone, state.label));
    result.appendChild(el('span', 'dnsrow__count mono', resolver.queries + ' 次查询'));
    row.appendChild(result);

    return row;
  }

  function renderExit(client) {
    var parts = [];
    if (client.country_code) {
      var mark = flag(client.country_code);
      parts.push(el(
        'span',
        'tag ' + (client.country_code === 'CN' ? 'tag--cn' : 'tag--global'),
        (mark ? mark + ' ' : '') + (client.country || client.country_code)
      ));
    }
    if (client.asn) parts.push(el('span', 'mono', client.asn));
    if (client.isp) parts.push(el('span', 'dim', client.isp));

    if (!parts.length) {
      fill(exitCell, [el('span', 'dim', '未知')]);
      return;
    }

    var wrap = el('span', 'dnsexit');
    parts.forEach(function (node) { wrap.appendChild(node); });
    fill(exitCell, [wrap]);
  }

  function render(data) {
    var client = data.client || {};
    var resolvers = data.resolvers || [];

    renderExit(client);
    fill(countCell, [el('span', 'mono', String(resolvers.length))]);

    if (!resolvers.length) {
      fill(list, [el('div', 'dnsrow dnsrow--empty', '未捕获到递归 DNS 解析记录。')]);
      return { leak: 0, cross: 0, third: 0, same: 0 };
    }

    var tally = { leak: 0, cross: 0, third: 0, same: 0 };
    var rows = [];

    resolvers.forEach(function (resolver) {
      var state = classify(resolver, client);
      tally[state.key === 'isp' ? 'leak' : state.key] += 1;
      rows.push(resolverRow(resolver, state));
    });

    fill(list, rows);
    return tally;
  }

  function say(tone, title, note) {
    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    verdictNote.textContent = note;
  }

  function conclude(data, tally, failure) {
    var total = (data.resolvers || []).length;
    var client = data.client || {};
    var where = client.country || client.country_code || (visibleIp || '你的出口');

    if (fixNote) fixNote.hidden = true;

    if (failure) {
      say('is-warn', '检测请求受阻', '未能读取递归 DNS 回显结果，可能是广告拦截扩展或当前网络策略阻断了探测域名。');
      return;
    }

    if (!total) {
      say('is-warn', '未捕获到任何 DNS 请求', '未能收到递归解析器记录。请检查是否有浏览器去广告插件拦截了测试请求。');
      return;
    }

    if (tally.leak) {
      say('is-bad', '检测到 DNS 泄露',
        total + ' 台解析器里有 ' + tally.leak + ' 台属于跨区运营商网络，且不在你出口所在的网络中。网站看到的是 ' + where + ' 的出口，而你的域名解析仍在本地运营商网络中进行。');
      if (fixNote) fixNote.hidden = false;
      return;
    }

    if (tally.cross) {
      say('is-warn', 'DNS 与出口不在同一国家或地区',
        total + ' 台解析器里有 ' + tally.cross + ' 台的归属地与你的出口（' + where + '）不一致。若非手动指定的公共 DNS，建议检查代理客户端的 DNS 分流设置。');
      if (fixNote) fixNote.hidden = false;
      return;
    }

    say('is-good', '未发现 DNS 泄露',
      '捕获到的 ' + total + ' 台递归解析器均位于 ' + where + ' 同区或与当前出口网络一致，未发现本地运营商抢答泄露。');
  }

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    verdict.hidden = true;
    if (fixNote) fixNote.hidden = true;
    fill(list, [el('div', 'dnsrow dnsrow--empty', '正在并发解析 ' + probeCount + ' 个一次性随机子域…')]);
    fill(exitCell, [el('span', 'dim', '查询中…')]);
    fill(countCell, [el('span', 'dim', '查询中…')]);
    progress.textContent = '正在向递归服务器发起 ' + probeCount + ' 路随机解析探测…';

    var jobs = [];
    for (var i = 0; i < probeCount; i++) {
      jobs.push(singleEdnsProbe());
    }

    Promise.all(jobs)
      .then(function (rawHits) {
        var counts = {};
        var ecsMap = {};
        rawHits.forEach(function (item) {
          if (!item || !item.ip) return;
          counts[item.ip] = (counts[item.ip] || 0) + 1;
          if (item.ecs && !ecsMap[item.ip]) ecsMap[item.ip] = item.ecs;
        });

        var ips = Object.keys(counts);
        progress.textContent = '已捕获 ' + ips.length + ' 台解析器，正在核对 ASN 与归属地…';

        return window.fetch('/dnsleak/api', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            clientIp: visibleIp,
            resolvers: ips.map(function (ip) {
              return { ip: ip, queries: counts[ip], ecs: ecsMap[ip] || '' };
            })
          })
        }).then(function (r) { return r.json(); });
      })
      .then(function (data) {
        running = false;
        runButton.disabled = false;
        runButton.textContent = '重新检测';
        if (!data || !data.ok) {
          progress.textContent = '检测中断。';
          conclude({ resolvers: [] }, { leak: 0, cross: 0, third: 0, same: 0 }, true);
          return;
        }
        var tally = render(data);
        progress.textContent = '检测完成，共捕获 ' + (data.resolvers || []).length + ' 台解析器。';
        conclude(data, tally, false);
      })
      .catch(function () {
        running = false;
        runButton.disabled = false;
        runButton.textContent = '重新检测';
        progress.textContent = '检测中断。';
        conclude({ resolvers: [] }, { leak: 0, cross: 0, third: 0, same: 0 }, true);
      });
  }

  runButton.addEventListener('click', run);
})();
