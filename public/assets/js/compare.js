/* JudgeIP — 多 IP 对比（/compare）。

   表头和行由服务端按 ?ips= 排好，格子里先是「待查询」。这个脚本逐个 IP 请求 /api/compare，
   一次拿回一列（每一格的文字和颜色服务端已经拼好），填进两张表；全部回来后在顶部写结论。
   某个 IP 没查到只影响它那一列，点「重新查询」再试。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

  var root = document.getElementById('compare');
  if (!root) return;

  var runButton = root.querySelector('[data-cmp-run]');
  var progress = root.querySelector('[data-cmp-progress]');
  var verdict = root.querySelector('[data-cmp-verdict]');
  var verdictTitle = root.querySelector('[data-cmp-verdict-title]');
  var verdictNote = root.querySelector('[data-cmp-verdict-note]');

  if (!window.IpcxProbe) {
    if (progress) progress.textContent = T('检测脚本加载失败，请刷新页面重试。', 'Failed to load the check script. Reload the page and try again.');
    if (runButton) runButton.disabled = true;
    return;
  }

  var P = window.IpcxProbe;
  var LANES = 3;
  var TONES = { ok: 'is-good', warn: 'is-warn', leak: 'is-bad' };

  var lang = window.I18N.lang;
  var ips = [];
  try {
    ips = JSON.parse(root.getAttribute('data-ips') || '[]') || [];
  } catch (e) {
    ips = [];
  }
  if (!ips.length || !runButton) return;

  /* 行名 → 这一行按 IP 顺序排的格子 */
  function cellsOf(row) {
    return row ? Array.prototype.slice.call(row.querySelectorAll('td')) : [];
  }

  var fieldRows = {};
  Array.prototype.forEach.call(root.querySelectorAll('tr[data-field]'), function (row) {
    fieldRows[row.getAttribute('data-field')] = cellsOf(row);
  });
  var factorRows = {};
  Array.prototype.forEach.call(root.querySelectorAll('tr[data-factor]'), function (row) {
    factorRows[row.getAttribute('data-factor')] = cellsOf(row);
  });
  var clampRow = root.querySelector('tr[data-factor="clamp"]');
  var baseCells = cellsOf(root.querySelector('tr[data-base]'));
  var totalCells = cellsOf(root.querySelector('tr[data-total]'));

  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function tag(tone, text) {
    return P.el('span', 'tag tag--' + tone, text);
  }

  function sub(text) {
    return text ? P.el('span', 'dtable__sub', text) : null;
  }

  function dash() {
    return P.el('span', 'dim', '—');
  }

  function eachCell(index, visit) {
    var key;
    for (key in fieldRows) visit(fieldRows[key][index], key);
    for (key in factorRows) visit(factorRows[key][index], key);
    visit(baseCells[index], 'base');
    visit(totalCells[index], 'total');
  }

  function showPending(index) {
    eachCell(index, function (cell) {
      fill(cell, [P.el('span', 'dim', T('查询中…', 'Looking up…'))]);
    });
  }

  function showFailure(index, reason) {
    eachCell(index, function (cell, key) {
      fill(cell, key === 'score' ? [tag('muted', T('没查到', 'Lookup failed')), sub(reason)] : [dash()]);
    });
  }

  function showColumn(index, column) {
    var key;
    for (key in fieldRows) {
      var item = column.cells[key];
      if (!item) {
        fill(fieldRows[key][index], [dash()]);
        continue;
      }
      fill(fieldRows[key][index], [
        item.tone ? tag(item.tone, item.text) : document.createTextNode(item.text),
        sub(item.sub)
      ]);
    }

    var factors = {};
    column.factors.forEach(function (factor) { factors[factor.key] = factor; });
    for (key in factorRows) {
      var factor = factors[key];
      if (!factor) {
        fill(factorRows[key][index], [dash()]);
        continue;
      }
      var delta = P.el('span', factor.delta < 0 ? 'is-minus' : factor.delta > 0 ? 'is-plus' : '', factor.deltaText);
      fill(factorRows[key][index], [delta, sub(factor.status)]);
    }

    fill(baseCells[index], [column.factors.length ? document.createTextNode(String(column.base)) : dash()]);
    fill(totalCells[index], column.score === null
      ? [dash(), sub(T('未出分', 'No score'))]
      : [document.createTextNode(String(column.score)), sub(T('等级 ', 'Grade ') + column.grade)]);
  }

  function fetchColumn(ip) {
    var url = '/api/compare?ip=' + encodeURIComponent(ip) + (lang === 'en' ? '&lang=en' : '');
    return fetch(url, { headers: { Accept: 'application/json' } }).then(function (response) {
      return response.json().then(function (data) {
        if (data && data.ok && data.column) return data.column;
        return Promise.reject({ status: response.status, retryAfter: data && data.retryAfter });
      }, function () {
        return Promise.reject({ status: response.status });
      });
    });
  }

  function failureReason(failure) {
    if (failure && failure.status === 429) {
      return failure.retryAfter
        ? T('请求过于频繁，' + failure.retryAfter + ' 秒后再试', 'Too many requests; try again in ' + failure.retryAfter + 's')
        : T('请求过于频繁，稍后再试', 'Too many requests; try again later');
    }
    if (failure && failure.status === 400) return T('地址无效', 'Invalid address');
    if (failure && failure.status) return T('查询出错，稍后再试', 'The lookup failed; try again later');
    return T('请求没有发出去，检查网络或浏览器扩展', 'The request did not go through; check the network or browser extensions');
  }

  function label(column) {
    return P.compactIp(column.ip) + ' · ' + column.cells.score.text;
  }

  /* 全部回来后：分数最高的是谁，差多少，有几个没分 */
  function summarize(columns) {
    var loaded = columns.filter(Boolean);
    var scored = loaded.filter(function (column) { return column.score !== null; });
    var failed = columns.length - loaded.length;
    var unscored = loaded.length - scored.length;
    var notes = [];

    if (clampRow) {
      clampRow.hidden = !loaded.some(function (column) {
        return column.factors.some(function (factor) { return factor.key === 'clamp'; });
      });
    }

    if (unscored) {
      notes.push(T(unscored + ' 个地址没有评分（IPv6、保留地址或数据源未返回），不参与排序。', unscored + (unscored > 1 ? ' addresses have' : ' address has') + ' no score (IPv6, reserved, or a data source did not respond) and ' + (unscored > 1 ? 'are' : 'is') + ' left out of the ranking.'));
    }
    if (failed) {
      notes.push(T(failed + ' 个没查到，点「重新查询」再试。', failed + (failed > 1 ? ' lookups' : ' lookup') + ' failed; use "Query again" to retry.'));
    }

    var tone = 'is-warn';
    var title;
    if (!scored.length) {
      title = loaded.length ? T('这次没有可比较的评分', 'No scores to compare') : T('一个都没查到', 'No lookup succeeded');
    } else {
      var best = Math.max.apply(null, scored.map(function (column) { return column.score; }));
      var worst = Math.min.apply(null, scored.map(function (column) { return column.score; }));
      var tops = scored.filter(function (column) { return column.score === best; });
      tone = TONES[tops[0].scoreTone] || 'is-warn';

      if (scored.length === 1) {
        title = label(scored[0]) + T(' · 等级 ', ' · grade ') + scored[0].grade;
        notes.unshift(ips.length === 1
          ? T('只有一个 IP，再加一个才能对比。', 'Only one IP; add another to compare.')
          : T('只有这一个地址有评分。', 'This is the only address with a score.'));
      } else if (tops.length === scored.length) {
        title = T('评分相同：', 'Same score: ') + tops[0].cells.score.text + T(' · 等级 ', ' · grade ') + tops[0].grade;
      } else {
        var names = tops.map(function (column) { return P.compactIp(column.ip); }).join(T('、', ', '));
        title = (tops.length > 1 ? T('评分并列最高：', 'Tied for the highest score: ') : T('评分最高：', 'Highest score: ')) +
          names + ' · ' + tops[0].cells.score.text + T(' · 等级 ', ' · grade ') + tops[0].grade;
        var lows = scored.filter(function (column) { return column.score === worst; });
        notes.unshift(T('最低：', 'Lowest: ') + label(lows[0]) + T('，相差 ' + (best - worst) + ' 分。', ', ' + (best - worst) + ' points apart.'));

        columns.forEach(function (column, index) {
          if (!column || column.score !== best) return;
          var cell = fieldRows.score && fieldRows.score[index];
          if (!cell || !cell.firstChild) return;
          var tags = P.el('span', 'tags');
          tags.appendChild(cell.firstChild);
          tags.appendChild(tag('name', T('最高', 'Highest')));
          cell.insertBefore(tags, cell.firstChild);
        });
      }
    }

    if (verdict && verdictTitle && verdictNote) {
      verdict.className = 'verdict ' + tone;
      verdictTitle.textContent = title;
      verdictNote.textContent = notes.join(T('', ' '));
      verdictNote.hidden = !notes.length;
      verdict.hidden = false;
    }
    return failed;
  }

  var running = false;

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    if (verdict) verdict.hidden = true;

    var done = 0;
    var queue = P.queue(LANES);
    function tick() {
      if (progress) progress.textContent = T('已查询 ' + done + ' / ' + ips.length, 'Looked up ' + done + ' of ' + ips.length);
    }
    tick();

    Promise.all(ips.map(function (ip, index) {
      showPending(index);
      return queue.add(function () { return fetchColumn(ip); }).then(function (column) {
        showColumn(index, column);
        done++;
        tick();
        return column;
      }, function (failure) {
        showFailure(index, failureReason(failure));
        done++;
        tick();
        return null;
      });
    })).then(function (columns) {
      var failed = summarize(columns);
      if (progress) {
        progress.textContent = failed
          ? T('查询完成，' + failed + ' 个没查到。', 'Done; ' + failed + (failed > 1 ? ' lookups' : ' lookup') + ' failed.')
          : T('查询完成，共 ' + ips.length + ' 个 IP。', 'Done; ' + ips.length + (ips.length > 1 ? ' IPs.' : ' IP.'));
      }
      running = false;
      runButton.disabled = false;
    });
  }

  runButton.addEventListener('click', run);
  run();
})();
