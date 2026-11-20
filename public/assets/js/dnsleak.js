/* JudgeIP — DNS 泄露检测（浏览器直连多路随机 EDNS 探针 + 出口比对）
   无需单独架设 UDP 53 裸机即可真实捕获当前网络生效的递归 DNS 解析器池，
   并通过 /dnsleak/api 补全每台递归解析器的国家、ISP、ASN 与泄露结论。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

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
      return { key: 'same', tone: 'ok', label: T('与出口同网', 'Same network as exit') };
    }
    if (ISP_TYPES.indexOf(resolver.type) !== -1 && resolver.country_code !== client.country_code) {
      return { key: 'isp', tone: 'leak', label: T('运营商解析', 'ISP resolver') };
    }
    if (client.country_code && resolver.country_code && resolver.country_code !== client.country_code) {
      return { key: 'cross', tone: 'warn', label: T('跨境解析', 'Cross-border') };
    }
    return { key: 'third', tone: 'ok', label: T('公共 / 同区解析', 'Public / same region') };
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
    result.appendChild(el('span', 'dnsrow__count mono', resolver.queries + T(' 次查询', ' queries')));
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
      fill(exitCell, [el('span', 'dim', T('未知', 'Unknown'))]);
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
      fill(list, [el('div', 'dnsrow dnsrow--empty', T('未捕获到递归 DNS 解析记录。', 'No recursive DNS lookups captured.'))]);
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
    var where = client.country || client.country_code || (visibleIp || T('你的出口', 'your exit'));

    if (fixNote) fixNote.hidden = true;

    if (failure) {
      say('is-warn', T('检测请求受阻', 'Test requests blocked'), T('没能读取解析结果，可能是广告拦截扩展或当前网络策略拦下了检测域名。', 'Could not read the lookup results. An ad blocker or your network policy may be blocking the test domain.'));
      return;
    }

    if (!total) {
      say('is-warn', T('未捕获到任何 DNS 请求', 'No DNS requests captured'), T('没有收到解析器记录。检查一下是否有广告拦截扩展拦下了检测请求。', 'No resolver records received. Check whether an ad-blocking extension is blocking the test requests.'));
      return;
    }

    if (tally.leak) {
      say('is-bad', T('检测到 DNS 泄露', 'DNS leak detected'),
        T(total + ' 台解析器里有 ' + tally.leak + ' 台是其他国家/地区的运营商网络，也不在你的出口网络里。网站看到的出口在 ' + where + '，域名查询却仍经过本地运营商。',
          tally.leak + ' of ' + total + ' resolvers are ISP networks in another country/region and not in your exit\'s network. Websites see an exit in ' + where + ', but DNS lookups still go through your local ISP.'));
      if (fixNote) fixNote.hidden = false;
      return;
    }

    if (tally.cross) {
      say('is-warn', T('DNS 与出口不在同一国家或地区', 'DNS and exit are in different countries/regions'),
        T(total + ' 台解析器里有 ' + tally.cross + ' 台与你的出口（' + where + '）不在同一国家/地区。如果不是你手动指定的公共 DNS，检查一下代理客户端的 DNS 设置。',
          tally.cross + ' of ' + total + ' resolvers are not in the same country/region as your exit (' + where + '). If this isn\'t a public DNS you set yourself, check your proxy client\'s DNS settings.'));
      if (fixNote) fixNote.hidden = false;
      return;
    }

    say('is-good', T('未发现 DNS 泄露', 'No DNS leak found'),
      T('捕获到的 ' + total + ' 台递归解析器都和出口在同一国家/地区（' + where + '）或同一网络，没有发现经本地运营商解析的情况。',
        'All ' + total + ' recursive resolvers captured are in the same country/region as your exit (' + where + ') or in the same network. No lookups through a local ISP found.'));
  }

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    verdict.hidden = true;
    if (fixNote) fixNote.hidden = true;
    fill(list, [el('div', 'dnsrow dnsrow--empty', T('正在并发解析 ', 'Resolving ') + probeCount + T(' 个一次性随机子域…', ' one-time random subdomains in parallel…'))]);
    fill(exitCell, [el('span', 'dim', T('查询中…', 'Looking up…'))]);
    fill(countCell, [el('span', 'dim', T('查询中…', 'Looking up…'))]);
    progress.textContent = T('正在发起 ', 'Sending ') + probeCount + T(' 路随机子域解析…', ' random subdomain lookups…');

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
        progress.textContent = T('已捕获 ', 'Captured ') + ips.length + T(' 台解析器，正在核对 ASN 与归属地…', ' resolvers, checking ASN and location…');

        return window.fetch('/dnsleak/api' + (window.I18N && window.I18N.lang === 'en' ? '?lang=en' : ''), {
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
        runButton.textContent = T('重新检测', 'Run again');
        if (!data || !data.ok) {
          progress.textContent = T('检测中断。', 'Test interrupted.');
          conclude({ resolvers: [] }, { leak: 0, cross: 0, third: 0, same: 0 }, true);
          return;
        }
        var tally = render(data);
        progress.textContent = T('检测完成，共捕获 ', 'Done, captured ') + (data.resolvers || []).length + T(' 台解析器。', ' resolvers.');
        conclude(data, tally, false);
      })
      .catch(function () {
        running = false;
        runButton.disabled = false;
        runButton.textContent = T('重新检测', 'Run again');
        progress.textContent = T('检测中断。', 'Test interrupted.');
        conclude({ resolvers: [] }, { leak: 0, cross: 0, third: 0, same: 0 }, true);
      });
  }

  runButton.addEventListener('click', run);
})();
