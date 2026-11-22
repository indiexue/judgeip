/* JudgeIP — 平台检测（/platforms）。

   表里每一行的结论先由服务端按页面上的 IP 算好。这个脚本只做一件事：
   对接在 Cloudflare 后面的平台读一次 /cdn-cgi/trace，拿到平台实际看到的出口。
   出口和页面上的 IP 是同一个时结论不动；不是同一个（分流规则把这家平台送去了别的出口）时，
   用 /api/platforms 按那个出口重新判定，换掉这一行的结论。
   读不到出口的平台（data-trace 为空）不发任何请求，保留按页面 IP 推断的结论。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

  var root = document.getElementById('platforms');
  if (!root) return;

  var runButton = root.querySelector('[data-pf-run]');
  var progress = root.querySelector('[data-pf-progress]');
  var verdict = root.querySelector('[data-pf-verdict]');
  var verdictTitle = root.querySelector('[data-pf-verdict-title]');

  if (!window.IpcxProbe) {
    if (progress) progress.textContent = T('检测脚本加载失败，请刷新页面重试。下面的结论按页面上的 IP 推断。', 'Failed to load the check script. Reload the page and try again. The verdicts below are inferred from the IP on this page.');
    if (runButton) runButton.disabled = true;
    return;
  }

  var P = window.IpcxProbe;
  var LANES = 4;
  var TRACE_TIMEOUT = 8000;
  var TAGS = { pass: 'ok', warn: 'warn', fail: 'leak', unknown: 'muted' };
  var LEVELS = ['pass', 'warn', 'fail', 'unknown'];

  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var lang = window.I18N.lang;
  var labels = {};
  try {
    labels = JSON.parse(root.getAttribute('data-level-labels') || '{}') || {};
  } catch (e) {
    labels = {};
  }

  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-platform]')).map(function (node) {
    var result = node.querySelector('[data-pf-result]');
    return {
      node: node,
      id: node.getAttribute('data-platform') || '',
      trace: node.getAttribute('data-trace') || '',
      exitCell: node.querySelector('[data-pf-exit]'),
      resultCell: result,
      /* 服务端按页面 IP 算出的结论，重新检测时先还原成它 */
      serverLevel: node.getAttribute('data-level') || 'unknown',
      serverResult: result ? result.innerHTML : ''
    };
  });
  var probed = rows.filter(function (row) { return row.trace && row.exitCell; });

  if (!probed.length || !runButton) return;

  var running = false;
  /* 同一个出口只问一次 /api/platforms，按 exitKey 记住结果 */
  var judged = {};

  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function tag(tone, text, title) {
    var node = P.el('span', 'tag tag--' + tone, text);
    if (title) node.title = title;
    return node;
  }

  function judge(ip) {
    var key = P.exitKey(ip);
    if (!judged[key]) {
      var url = '/api/platforms?ip=' + encodeURIComponent(ip) + (lang === 'en' ? '&lang=en' : '');
      judged[key] = fetch(url, { headers: { Accept: 'application/json' } }).then(function (response) {
        return response.json();
      }).then(function (data) {
        if (!data || !data.ok || !data.verdicts) return Promise.reject(new Error('judge'));
        return data;
      });
      /* 失败的不留在缓存里，「重新检测」时能再问一次 */
      judged[key].catch(function () { delete judged[key]; });
    }
    return judged[key];
  }

  function showVerdict(row, item) {
    row.node.setAttribute('data-level', item.level);
    var nodes = [tag(TAGS[item.level] || 'muted', item.label)];
    if (item.reasons && item.reasons.length) {
      nodes.push(P.el('span', 'dtable__sub', item.reasons.join(T('；', '; '))));
    }
    fill(row.resultCell, nodes);
  }

  function showExit(row, ip, loc, tone, text, sub) {
    var address = P.el('span', 'mono', P.compactIp(ip));
    address.title = ip;
    var country = P.country(loc);
    var tags = P.el('span', 'tags');
    tags.appendChild(address);
    if (country) tags.appendChild(P.el('span', 'geo__note', country));
    tags.appendChild(tag(tone, text));
    fill(row.exitCell, [tags, sub ? P.el('span', 'dtable__sub', sub) : null]);
  }

  function summarize() {
    if (!verdict || !verdictTitle) return;
    var counts = {};
    rows.forEach(function (row) {
      var level = row.node.getAttribute('data-level') || 'unknown';
      counts[level] = (counts[level] || 0) + 1;
    });
    verdictTitle.textContent = LEVELS.filter(function (level) { return counts[level]; }).map(function (level) {
      return (labels[level] || level) + ' ' + counts[level];
    }).join(' · ');
    verdict.className = 'verdict ' + (counts.pass === rows.length ? 'is-good' : !counts.pass && counts.fail ? 'is-bad' : 'is-warn');
  }

  function probe(row) {
    return P.trace(row.trace, TRACE_TIMEOUT).then(function (result) {
      var ip = result.data.ip;
      var loc = String(result.data.loc || '').toUpperCase();
      var compared = P.compareExit(ip, [visibleIp]);

      if (compared === 'match') {
        showExit(row, ip, loc, 'ok', T('与本页一致', 'Same as this page'));
        return { ip: ip, state: 'match' };
      }

      /* 平台走的是 IPv6、页面上是 IPv4：IPv6 没有评分，按它重新判定只会得到一排「无法判断」，
         结论留给页面上的 IPv4，在出口一栏说明 */
      if (compared === 'uncompared' && P.isIPv6(ip)) {
        showExit(row, ip, loc, 'muted', T('IPv6 出口', 'IPv6 egress'), T('IPv6 没有评分，结论按本页的 IPv4', 'IPv6 has no score; verdict uses the IPv4 on this page'));
        return { ip: ip, state: 'v6' };
      }

      showExit(row, ip, loc, 'warn', T('出口不同', 'Different egress'), T('正在按这个出口重新判定…', 'Re-judging for this egress…'));
      return judge(ip).then(function (data) {
        var item = null;
        for (var i = 0; i < data.verdicts.length; i++) {
          if (data.verdicts[i].id === row.id) item = data.verdicts[i];
        }
        if (!item) return Promise.reject(new Error('judge'));
        var score = data.score === null || data.score === undefined ? T('未出分', 'no score') : T('评分 ', 'score ') + data.score;
        showExit(row, ip, loc, 'warn', T('出口不同', 'Different egress'), (data.type ? data.type + ' · ' : '') + score + T('，结论按这个出口', '; verdict uses this egress'));
        showVerdict(row, item);
        return { ip: ip, state: 'different' };
      }, function () {
        showExit(row, ip, loc, 'warn', T('出口不同', 'Different egress'), T('这个出口没查到，结论仍按本页 IP', 'Lookup for this egress failed; verdict still uses the IP on this page'));
        return { ip: ip, state: 'unjudged' };
      });
    }, function (failure) {
      var note = P.el('span', 'dim', P.failureText(failure && failure.kind) + T('，按当前 IP 推断', '; inferred from current IP'));
      fill(row.exitCell, [note]);
      return { ip: '', state: 'failed' };
    });
  }

  function report(results) {
    if (!progress) return;
    var read = results.filter(function (r) { return r.state !== 'failed'; });
    var differ = results.filter(function (r) { return r.state === 'different' || r.state === 'unjudged'; });
    var text = T('读到 ' + read.length + ' / ' + results.length + ' 个平台看到的出口', 'Read the egress for ' + read.length + ' of ' + results.length + ' platforms');
    if (!read.length) {
      text += T('。请求可能被代理规则或浏览器扩展拦下，结论按页面上的 IP 推断。', '. The requests may be blocked by proxy rules or a browser extension; verdicts are inferred from the IP on this page.');
    } else if (differ.length) {
      text += T('，其中 ' + differ.length + ' 个和本页的 IP 不同。', '; ' + differ.length + ' differ from the IP on this page.');
    } else {
      text += T('，都和本页的 IP 一致。', '; all match the IP on this page.');
    }
    fill(progress, [document.createTextNode(text)]);

    /* 页面是经 IPv6 打开的（没有评分），而平台看到的是 IPv4：给一个按 IPv4 出口重查的入口 */
    if (P.isIPv6(visibleIp)) {
      var v4 = '';
      results.forEach(function (r) { if (!v4 && r.ip && !P.isIPv6(r.ip)) v4 = r.ip; });
      if (v4) {
        var link = P.el('a', '', T('按 IPv4 出口 ' + v4 + ' 检测', 'Check the IPv4 egress ' + v4));
        link.href = window.I18N.path('/platforms') + '?ip=' + encodeURIComponent(v4);
        progress.appendChild(document.createTextNode(' '));
        progress.appendChild(link);
      }
    }
  }

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;

    rows.forEach(function (row) {
      row.node.setAttribute('data-level', row.serverLevel);
      if (row.resultCell) row.resultCell.innerHTML = row.serverResult;
    });
    probed.forEach(function (row) {
      fill(row.exitCell, [P.el('span', 'dim', T('检测中…', 'Checking…'))]);
    });
    summarize();

    var done = 0;
    var queue = P.queue(LANES);
    var step = function () {
      if (progress) progress.textContent = T('正在读取平台看到的出口 ' + done + ' / ' + probed.length + '…', 'Reading platform egress ' + done + ' / ' + probed.length + '…');
    };
    step();

    Promise.all(probed.map(function (row) {
      return queue.add(function () { return probe(row); }).then(function (result) {
        done++;
        step();
        summarize();
        return result;
      });
    })).then(function (results) {
      report(results);
    }).then(function () {
      running = false;
      runButton.disabled = false;
    });
  }

  runButton.addEventListener('click', run);
  run();
})();
