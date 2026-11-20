/* JudgeIP — 网站分流测试。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   核心思路：分流的效果只有被访问的网站看得见，那就让几十个网站各报一次「我看到你从哪个 IP 来」，
   再按 IP 把它们归成几个出口——同一个出口下出现了哪几类网站，规则实际怎么生效的就一目了然。

   目标清单不写在这里：它们由 src/SplitTargets.php 渲染成每一行的 data-*，脚本从 DOM 上读回来，
   页面上印着的清单、CSP 放行的源、脚本实际请求的地址永远是同一份。
   请求、trace 解析、限并发队列、机房代码换城市都用 probe.js（window.IpcxProbe）。

   探到的地址只留在当前页面里，不回传本站。 */
(function () {
  'use strict';

  var root = document.getElementById('split');
  if (!root) return;

  /* probe.js 没加载成功（网络中断、被扩展拦截）时不能悄无声息：页面会一直停在「待检测」，像是卡住了。
     在进度提示和结论块里说清楚检测没能开始，并把两枚按钮停掉——留着按了没反应的按钮只会更困惑。 */
  function probeMissing() {
    var message = '检测脚本加载失败，请刷新页面重试';
    var hint = root.querySelector('[data-split-progress]');
    var box = root.querySelector('[data-split-verdict]');
    var title = root.querySelector('[data-split-verdict-title]');
    var notes = root.querySelector('[data-split-verdict-notes]');
    var summary = root.querySelector('[data-split-exits]');

    if (hint) hint.textContent = message + '。';
    if (summary) {
      summary.textContent = '';
      var empty = document.createElement('p');
      empty.className = 'splitsum__empty';
      empty.textContent = '检测没有开始，暂无出口可汇总。';
      summary.appendChild(empty);
    }
    if (box && title) {
      title.textContent = message;
      if (notes) {
        var p = document.createElement('p');
        p.className = 'verdict__note';
        p.textContent = '本页依赖的公共检测脚本没有加载成功（网络中断，或被浏览器扩展拦截），所以一个网站都没有去问。'
          + '下面的清单仍然是本页会检测的全部网站。';
        notes.textContent = '';
        notes.appendChild(p);
      }
      box.classList.add('is-bad');
      box.hidden = false;
    }
    Array.prototype.forEach.call(root.querySelectorAll('[data-split-run], [data-split-mask]'), function (button) {
      button.disabled = true;
    });
  }

  if (!window.IpcxProbe) {
    probeMissing();
    return;
  }

  var P = window.IpcxProbe;

  function intAttr(name, fallback) {
    var value = parseInt(root.getAttribute(name) || '', 10);
    return value > 0 ? value : fallback;
  }

  var LANES = intAttr('data-lanes', 8);
  var TIMEOUT = intAttr('data-timeout', 6000);
  var RETRY_DELAYS = (root.getAttribute('data-retry') || '2000 4000').split(' ').map(Number).filter(function (n) { return n > 0; });
  var DENIED = (root.getAttribute('data-ai-denied') || '').split(' ').filter(Boolean);
  var IATA_URL = root.getAttribute('data-iata') || '';
  var EXIT_HUES = 6;

  var runButton = root.querySelector('[data-split-run]');
  var progress = root.querySelector('[data-split-progress]');
  var maskButton = root.querySelector('[data-split-mask]');
  var maskLabel = root.querySelector('[data-split-mask-label]');
  var verdict = root.querySelector('[data-split-verdict]');
  var verdictTitle = root.querySelector('[data-split-verdict-title]');
  var verdictNotes = root.querySelector('[data-split-verdict-notes]');
  var exitsBox = root.querySelector('[data-split-exits]');

  var masked = false;
  var running = false;
  var finished = false;
  var iataReady = null;

  /* ---------------------------------------------------------------- 行 */

  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-split-row]')).map(function (node) {
    return {
      node: node,
      key: node.getAttribute('data-split-row'),
      name: node.getAttribute('data-name') || '',
      method: node.getAttribute('data-method') || 'trace',
      host: node.getAttribute('data-host') || '',
      fallback: node.getAttribute('data-fallback') || '',
      url: node.getAttribute('data-url') || '',
      headers: (node.getAttribute('data-headers') || '').split(' ').filter(Boolean),
      region: node.getAttribute('data-region') || 'intl',
      group: node.getAttribute('data-group') || '',
      tag: node.getAttribute('data-tag') || '',
      ipCell: node.querySelector('[data-split-ip]'),
      geoCell: node.querySelector('[data-split-geo]'),
      coloCell: node.querySelector('[data-split-colo]'),
      stateCell: node.querySelector('[data-split-state]'),
      status: 'idle',
      ip: '',
      loc: '',
      colo: null,
      ms: null,
      via: '',
      kind: '',
      attempts: 0
    };
  });

  var targets = rows.filter(function (row) { return row.method !== 'self'; });

  /* 「IP.cx 服务器看到的地址」一行由服务器直接写好，从一开始就算完成，参与出口汇总与结论 */
  var selfRow = null;
  rows.forEach(function (row) {
    if (row.method !== 'self') return;
    selfRow = row;
    var ip = extractIp(root.getAttribute('data-visible-ip'));
    if (ip) {
      row.status = 'ok';
      row.ip = ip;
    }
  });

  /* ---------------------------------------------------------------- IP 工具 */

  function isIPv4(text) {
    var parts = String(text).split('.');
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i]) || Number(parts[i]) > 255) return false;
      /* 前导零在不同实现里会被当成八进制，宁可不认 */
      if (parts[i].length > 1 && parts[i].charAt(0) === '0') return false;
    }
    return true;
  }

  function isIPv6(text) {
    var s = String(text);
    if (s.indexOf(':') === -1 || !/^[0-9a-f:.]+$/i.test(s)) return false;

    /* 末尾嵌着 IPv4（::ffff:1.2.3.4 这类），先验掉那一段再按两组十六进制算 */
    var tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (tail) {
      if (!isIPv4(tail[1])) return false;
      s = s.slice(0, s.length - tail[1].length) + '0:0';
    }

    var halves = s.split('::');
    if (halves.length > 2) return false;
    var head = halves[0] ? halves[0].split(':') : [];
    var rest = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    var groups = head.concat(rest);
    for (var i = 0; i < groups.length; i++) {
      if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return false;
    }
    return halves.length === 1 ? groups.length === 8 : groups.length <= 7;
  }

  /* 从一段任意文本里取出第一个合法 IP。响应头的格式没有文档：x-response-cinfo 里可能夹着别的字段，
     cdn-user-ip 偶尔是「客户端, 代理」两个地址——取第一个，读不出就返回空串，绝不把半截字符串当地址显示。 */
  function extractIp(raw) {
    var tokens = String(raw || '').split(/[^0-9A-Fa-f:.]+/);
    for (var i = 0; i < tokens.length; i++) {
      var token = tokens[i];
      if (!token) continue;
      if (isIPv4(token)) return token;
      if (isIPv6(token)) {
        var mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(token);
        return mapped ? mapped[1] : token.toLowerCase();
      }
      /* 「ip:1.2.3.4」切出来是 :1.2.3.4，去掉首尾的标点再认一次 */
      var trimmed = token.replace(/^[:.]+|[:.]+$/g, '');
      if (isIPv4(trimmed)) return trimmed;
    }
    return '';
  }

  function family(ip) {
    return P.isIPv6(ip) ? 6 : 4;
  }

  /* 「出口」的唯一口径（IPv4 按地址，IPv6 按 /64，见 IpcxProbe.exitKey）。
     出口汇总、每一行的「出口 N」、结论里数出口与比出口，全部经过这一个函数，页面上下才不会互相矛盾。 */
  var exitKey = P.exitKey;

  /* 2001:db8:1:2::/64 —— 展开后的前四组去掉前导零，给汇总里的说明文字用 */
  function prefix64(ip) {
    return P.ipKey(ip).split(':').slice(0, 4).map(function (group) {
      return group.replace(/^0+(?=.)/, '');
    }).join(':') + '::/64';
  }

  /* IPv4 留前两段（8.8.8.8 → 8.8.*.*）；IPv6 留前两组。和首页 IP 卡片的遮罩是同一个口径 */
  function maskIp(ip) {
    if (P.isIPv6(ip)) return ip.split(':').slice(0, 2).join(':') + ':*';
    var octets = ip.split('.');
    return octets.length === 4 ? octets[0] + '.' + octets[1] + '.*.*' : '*.*.*.*';
  }

  function displayIp(ip) {
    return masked ? maskIp(ip) : P.compactIp(ip);
  }

  /* 出口在汇总与结论里的写法。汇总一个出口占一整行，放得下完整地址，不用 compactIp：
     「2001:db8:aa:1:…」与「2001:db8:bb:1:…」收成「2001:db8…1」后，两个不同 /64 的出口会长得几乎一样。
     结论标题里，由几个地址合成的 IPv6 出口直接写网段（2001:db8:aa:1::/64），那才是这个出口的身份。 */
  function exitIp(exit) {
    return masked ? maskIp(exit.ip) : exit.ip;
  }

  function exitLabel(exit) {
    if (masked) return maskIp(exit.ip);
    return exit.ips.length > 1 ? prefix64(exit.ip) : exit.ip;
  }

  /* loc 是两位国家代码；Cloudflare 认不出时给 XX，经 Tor 出口时给 T1 */
  function normLoc(value) {
    var loc = String(value || '').trim().toUpperCase();
    return /^[A-Z][A-Z0-9]$/.test(loc) ? loc : '';
  }

  /* 地区名用 probe.js 的全站统一写法（中国香港、中国台湾……），这里只补 trace 特有的两个代码 */
  function countryName(cc) {
    if (cc === 'T1') return 'Tor 网络';
    if (cc === 'XX') return '未知地区';
    return P.countryName(cc) || cc;
  }

  function countryList(codes) {
    return codes.map(countryName).join('、');
  }

  /* ---------------------------------------------------------------- DOM 工具 */

  var el = P.el;

  /* 结果格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function dim(text, title) {
    var node = el('span', 'dim', text);
    if (title) node.title = title;
    return node;
  }

  function tag(text, tone, title) {
    var node = el('span', 'tag tag--' + tone, text);
    if (title) node.title = title;
    return node;
  }

  /* ---------------------------------------------------------------- 探测 */

  /* trace 的读法与 IpcxProbe.trace 相同，单独写是为了分出「回了东西但不是 trace」：
     那通常意味着该站已经不走 Cloudflare，和网络不通是两回事，也不值得重试。 */
  function readTrace(host) {
    return P.text('https://' + host + '/cdn-cgi/trace', {}, TIMEOUT).then(function (result) {
      var data = P.parseTrace(result.text);
      var ip = extractIp(data.ip);
      if (!ip) return Promise.reject({ kind: 'invalid', ms: result.ms });
      return {
        ip: ip,
        loc: normLoc(data.loc),
        colo: String(data.colo || '').toUpperCase().replace(/[^A-Z0-9]/g, ''),
        ms: result.ms,
        via: host
      };
    }, function (failure) {
      return Promise.reject({ kind: (failure && failure.kind) || 'error', ms: failure && failure.ms });
    });
  }

  function probeTrace(row) {
    return readTrace(row.host).then(null, function (first) {
      if (!row.fallback) return Promise.reject(first);
      /* 备用域名也不通时，报主域名的失败原因：页面上写的是主域名 */
      return readTrace(row.fallback).then(null, function () { return Promise.reject(first); });
    });
  }

  /* 响应头那几行。跨域时浏览器只让网页读少数几个「安全」头，cdn-user-ip、x-request-ip 都不在其中，
     必须由对方在 Access-Control-Expose-Headers 里点名开放——没开放时 headers.get() 拿到的是 null。
     fetch 失败时也分不清「对方不让跨域读」和「根本连不上」，于是用不透明请求再敲一次门：
     敲得开就是前者，归为「该站未开放 IP 头」，不必重试；敲不开才是网络问题。 */
  function probeHeader(row) {
    return P.request(row.url, { method: 'HEAD' }, TIMEOUT).then(function (result) {
      var raw = null;
      for (var i = 0; i < row.headers.length && !raw; i++) {
        raw = result.response.headers.get(row.headers[i]);
      }
      var ip = extractIp(raw);
      if (!ip) return Promise.reject({ kind: 'noheader', ms: result.ms });
      return { ip: ip, loc: '', colo: '', ms: result.ms, via: row.host };
    }, function (failure) {
      if (!failure || failure.kind !== 'error') return Promise.reject(failure || { kind: 'error' });
      return P.timing(row.url, {}, TIMEOUT).then(function (knock) {
        return Promise.reject(knock.ok ? { kind: 'noheader', ms: failure.ms } : failure);
      });
    });
  }

  function probe(row) {
    return row.method === 'header' ? probeHeader(row) : probeTrace(row);
  }

  /* 只有偶发的那两种值得重试：CSP 拦截、对方不开放 IP 头、回的不是 trace，再试几次结果都一样 */
  function retryable(row) {
    return row.status === 'fail' && (row.kind === 'timeout' || row.kind === 'error');
  }

  function failureText(kind) {
    if (kind === 'noheader') return '该站未开放 IP 头';
    if (kind === 'invalid') return '未返回 trace';
    return P.failureText(kind);
  }

  function failureTitle(row) {
    var parts = [];
    if (row.kind === 'noheader') parts.push('浏览器只能读到对方明确开放的响应头，这一家没有把访客 IP 开放给其他网站读取');
    if (row.kind === 'invalid') parts.push('请求成功，但回的不是 Cloudflare 的 trace，该站可能已经不走 Cloudflare');
    if (row.kind === 'csp') parts.push('本页的 CSP 没有放行这个域名，属于本站的部署问题');
    if (row.attempts > 1) parts.push('已重试 ' + (row.attempts - 1) + ' 次');
    return parts.join('；');
  }

  /* ---------------------------------------------------------------- 渲染：单行 */

  function renderIp(row) {
    /* 窄屏上没结果的行把「IP · 国家 · 节点」那一行整个收起，见 split.css */
    row.node.classList.toggle('is-empty', row.status !== 'ok');
    if (!row.ipCell) return;
    if (row.status !== 'ok') {
      fill(row.ipCell, [dim(row.method === 'self' ? '未知' : '—')]);
      return;
    }
    var nodes = [];
    var ip = el('span', 'mono', displayIp(row.ip));
    ip.setAttribute('data-ip', row.ip);
    if (!masked) ip.title = row.ip;
    nodes.push(ip);
    if (family(row.ip) === 6) nodes.push(el('span', 'splitrow__fam', 'IPv6'));
    fill(row.ipCell, nodes);
  }

  function renderGeo(row, loc, derived) {
    if (!row.geoCell) return;
    if (row.status !== 'ok' || !loc) {
      fill(row.geoCell, [dim('—', row.status === 'ok' ? '这一家只给了 IP，没有其他网站看到同一个出口，国家未知' : '')]);
      return;
    }
    var wrap = el('span', 'splitgeo' + (derived ? ' is-derived' : ''));
    var flag = P.flag(loc);
    if (flag && loc !== 'XX') wrap.appendChild(el('span', 'flag', flag));
    wrap.appendChild(el('span', 'splitgeo__name', countryName(loc)));
    wrap.title = derived ? '这一家只给了 IP，国家取自看到同一个出口的其他网站' : loc;
    fill(row.geoCell, [wrap]);
  }

  function renderColo(row, colos) {
    if (!row.coloCell) return;
    if (row.status !== 'ok' || !row.colo) {
      var why = row.method === 'self' ? '本站不经过 Cloudflare' : row.method === 'header' ? '这一家不是 Cloudflare 的节点' : '';
      fill(row.coloCell, [dim('—', why)]);
      return;
    }
    var info = P.colo(colos || {}, row.colo);
    var wrap = el('span', 'splitcolo');
    if (info.known && info.city !== info.code) {
      wrap.appendChild(el('span', 'splitcolo__city', info.city));
      wrap.appendChild(el('span', 'splitcolo__code mono', info.code));
      wrap.title = (info.cityEn ? info.cityEn + ' · ' : '') + (info.cc ? countryName(info.cc) : '') + '（Cloudflare 机房 ' + info.code + '）';
    } else {
      wrap.appendChild(el('span', 'mono', info.code));
      wrap.title = 'Cloudflare 机房 ' + info.code;
    }
    fill(row.coloCell, [wrap]);
  }

  function renderState(row, exitNo) {
    if (!row.stateCell) return;
    if (row.status === 'ok') {
      var nodes = [];
      if (exitNo) nodes.push(el('span', 'tag splitexit splitexit--' + ((exitNo - 1) % EXIT_HUES), '出口 ' + exitNo));
      if (row.method === 'self') nodes.push(el('span', 'splitrow__ms', '对照基准'));
      else if (row.ms !== null) nodes.push(el('span', 'splitrow__ms mono', row.ms + ' ms'));
      if (row.via && row.via !== row.host && row.method === 'trace') {
        nodes.push(el('span', 'splitrow__ms', '经备用域名'));
        row.stateCell.title = '主域名不通，结果来自 ' + row.via;
      } else {
        row.stateCell.removeAttribute('title');
      }
      fill(row.stateCell, nodes);
      return;
    }
    row.stateCell.removeAttribute('title');
    if (row.status === 'fail') {
      var tone = row.kind === 'csp' ? 'leak' : row.kind === 'noheader' || row.kind === 'invalid' ? 'muted' : 'warn';
      fill(row.stateCell, [tag(failureText(row.kind), tone, failureTitle(row))]);
      return;
    }
    if (row.status === 'running') {
      fill(row.stateCell, [dim(row.attempts > 1 ? '重试中…' : '检测中…')]);
      return;
    }
    if (row.status === 'waiting') {
      fill(row.stateCell, [dim(failureText(row.kind) + ' · 等待重试', failureTitle(row))]);
      return;
    }
    if (row.status === 'queued') {
      fill(row.stateCell, [dim('排队中')]);
      return;
    }
    fill(row.stateCell, [dim(row.method === 'self' ? '未知' : '待检测')]);
  }

  /* ---------------------------------------------------------------- 汇总：出口 */

  function okRows() {
    return rows.filter(function (row) { return row.status === 'ok' && row.ip; });
  }

  /* 只给 IP 的那几行（网易、字节、本站）借用 trace 行的国家：先找看到同一个地址的，
     没有再找同一个出口（IPv6 同一 /64）的——同一个 /64 是同一条线路，不会一半在德国一半在美国。 */
  function derivedLocs() {
    var byIp = {};
    var byExit = {};
    okRows().forEach(function (row) {
      if (!row.loc) return;
      if (!byIp[P.ipKey(row.ip)]) byIp[P.ipKey(row.ip)] = row.loc;
      if (!byExit[exitKey(row.ip)]) byExit[exitKey(row.ip)] = row.loc;
    });
    return { ip: byIp, exit: byExit };
  }

  function locOf(row, derived) {
    return row.loc || derived.ip[P.ipKey(row.ip)] || derived.exit[exitKey(row.ip)] || '';
  }

  /* 按 exitKey 归并成出口。编号按页面顺序（本站、国内、AI……第一次出现的那一行）来定，
     而不是按谁先返回：同一个网络重测一遍，编号不会因为快慢不同而换来换去。
     一个 IPv6 出口下可能有好几个地址：ips 按出现顺序记下每一个，ip 是其中被最多网站看到的那个，
     作为这个出口的代表显示、复制（并列时取先出现的）。 */
  function collectExits() {
    var derived = derivedLocs();
    var map = {};
    var list = [];
    okRows().forEach(function (row) {
      var key = exitKey(row.ip);
      var exit = map[key];
      if (!exit) {
        exit = map[key] = { key: key, ip: '', ips: [], seen: {}, loc: '', rows: [], tags: [], no: 0 };
        list.push(exit);
      }
      var addr = P.ipKey(row.ip);
      if (!exit.seen[addr]) {
        exit.seen[addr] = 0;
        exit.ips.push(row.ip);
      }
      exit.seen[addr]++;
      exit.rows.push(row);
      if (!exit.loc) exit.loc = locOf(row, derived);
      if (row.tag && exit.tags.indexOf(row.tag) === -1) exit.tags.push(row.tag);
    });
    list.forEach(function (exit, index) {
      exit.no = index + 1;
      exit.ip = exit.ips[0];
      exit.ips.forEach(function (ip) {
        if (exit.seen[P.ipKey(ip)] > exit.seen[P.ipKey(exit.ip)]) exit.ip = ip;
      });
    });
    return { list: list, map: map, derived: derived };
  }

  /* 出口下不止一个地址时，chip 上的说明与悬停提示。遮罩打开时提示里不列地址，只说个数 */
  var RANGE_LIST_MAX = 6;

  function rangeTitle(exit) {
    var n = exit.ips.length;
    if (masked) return '同一个 /64 网段里有 ' + n + ' 个不同地址，按一个出口算';
    var shown = exit.ips.slice(0, RANGE_LIST_MAX).join('、') + (n > RANGE_LIST_MAX ? ' 等' : '');
    return '同一个 /64 网段（' + prefix64(exit.ip) + '）里有 ' + n + ' 个不同地址：' + shown
      + '。IPv6 的临时地址会在网段内轮换，有的代理也按连接换源地址，所以按一个出口算；显示与复制的是其中出现次数最多的那个';
  }

  function renderExits(exits) {
    if (!exitsBox) return;
    if (!exits.list.length) {
      fill(exitsBox, [el('p', 'splitsum__empty', running ? '正在等待第一个网站返回…' : '还没有网站返回出口 IP。')]);
      return;
    }

    var nodes = exits.list.map(function (exit) {
      var hue = (exit.no - 1) % EXIT_HUES;
      var id = 'split-exit-' + exit.no;
      /* 复制沿用全站 app.js 的 [data-copy-target]：它读目标元素的 data-copy-value，
         遮罩打开时页面上是 8.8.*.*，复制出去的仍是真值 */
      var button = el('button', 'splitchip');
      button.type = 'button';
      button.setAttribute('data-copy-target', id);
      button.setAttribute('data-copy-done', '已复制');
      button.title = (masked ? '点击复制完整 IP' : '点击复制 ' + exit.ip)
        + (exit.ips.length > 1 ? '\n' + rangeTitle(exit) : '');

      button.appendChild(el('span', 'tag splitexit splitexit--' + hue, '出口 ' + exit.no));

      var where = el('span', 'splitchip__where');
      var flag = exit.loc && exit.loc !== 'XX' ? P.flag(exit.loc) : '';
      if (flag) where.appendChild(el('span', 'flag', flag));
      var ip = el('span', 'splitchip__ip mono', exitIp(exit));
      ip.id = id;
      ip.setAttribute('data-copy-value', exit.ip);
      where.appendChild(ip);
      /* 同一 /64 下的几个地址合成了这一个出口：紧跟在代表地址后面说出来（「2001:db8::1 等 3 个地址」），
         免得有人对着表格里各不相同的地址以为汇总算错了 */
      if (exit.ips.length > 1) where.appendChild(el('span', 'splitchip__range', '等 ' + exit.ips.length + ' 个地址（同一 /64）'));
      if (exit.loc) where.appendChild(el('span', 'splitchip__country', countryName(exit.loc)));
      button.appendChild(where);

      button.appendChild(el('span', 'splitchip__count', exit.rows.length + ' 个站点'));

      var tags = el('span', 'splitchip__tags');
      exit.tags.forEach(function (text) {
        var tone = text === '国内' ? 'cn' : text === '本站' ? 'name' : 'global';
        tags.appendChild(el('span', 'tag tag--' + tone, text));
      });
      button.appendChild(tags);

      button.appendChild(el('span', 'splitchip__copy copy__label', '复制'));
      return button;
    });

    fill(exitsBox, nodes);
  }

  /* 每返回一行就重画一次派生的部分：借来的国家、出口编号、出口汇总。四十来行，整张重画也只是几毫秒 */
  function refresh() {
    var exits = collectExits();
    rows.forEach(function (row) {
      if (row.status === 'ok') {
        var own = !!row.loc;
        renderGeo(row, locOf(row, exits.derived), !own);
        renderState(row, exits.map[exitKey(row.ip)].no);
      }
    });
    renderExits(exits);
    return exits;
  }

  /* ---------------------------------------------------------------- 结论 */

  function unique(list) {
    var out = [];
    list.forEach(function (item) { if (item && out.indexOf(item) === -1) out.push(item); });
    return out;
  }

  function count(map) {
    var n = 0;
    for (var key in map) if (Object.prototype.hasOwnProperty.call(map, key)) n++;
    return n;
  }

  /* 「X、Y、Z 等 7 个网站」。后面直接接中文谓语，只有以西文结尾时才空一格（「Claude 看到」「等 7 个网站看到」） */
  function nameList(list) {
    var names = list.map(function (row) { return row.name; });
    var text = names.length <= 4 ? names.join('、') : names.slice(0, 4).join('、') + ' 等 ' + names.length + ' 个网站';
    return /[\x21-\x7e]$/.test(text) ? text + ' ' : text;
  }

  /* 出现最多的那个值（并列时取先出现的） */
  function mostCommon(list) {
    var tally = {};
    var best = '';
    list.forEach(function (item) {
      if (!item) return;
      tally[item] = (tally[item] || 0) + 1;
      if (!best || tally[item] > tally[best]) best = item;
    });
    return best;
  }

  /* 每条结论：tone 决定颜色（bad > warn > good > info），只有最重的那一条当标题，其余作为补充列在下面 */
  var RANK = { bad: 3, warn: 2, good: 1, info: 0 };

  function evaluate() {
    /* 出口一律取自 collectExits()：结论里说的「几个出口」「出口 X」和汇总里列的是同一份 */
    var exits = collectExits();
    var derived = exits.derived;
    var ok = okRows();
    var probed = ok.filter(function (row) { return row.method !== 'self'; });
    var failed = targets.filter(function (row) { return row.status === 'fail' || row.status === 'waiting'; });
    var findings = [];

    if (!probed.length) {
      var allCsp = failed.length && failed.every(function (row) { return row.kind === 'csp'; });
      showVerdict([{
        tone: 'bad',
        title: allCsp ? '探测请求全部被本页的 CSP 拦下' : '没有一个网站返回出口 IP',
        note: allCsp
          ? '这是本站的部署问题：nginx 里这一页的 connect-src 没有放行这些域名。请稍后再试，或把这个情况告诉我们。'
          : '可能是网络不通、浏览器扩展拦截了跨站请求，或者这些网站在你的网络里都被屏蔽了。稍后点「重新检测」再试一次。'
      }], failed.length, probed.length);
      return;
    }

    var loc = function (row) { return locOf(row, derived); };
    var intl = probed.filter(function (row) { return row.region === 'intl' && loc(row); });
    var cn = probed.filter(function (row) { return row.region === 'cn' && loc(row); });
    var ai = probed.filter(function (row) { return row.group === 'ai'; });

    /* AI 出口落在受限地区：最重的一条，无论分流对不对都要先说 */
    var deniedRows = ai.filter(function (row) { return DENIED.indexOf(loc(row)) !== -1; });
    if (deniedRows.length) {
      var deniedCountries = unique(deniedRows.map(loc));
      findings.push({
        tone: 'bad',
        title: 'AI 出口位于' + countryList(deniedCountries) + '：ChatGPT / Claude 不支持该地区',
        note: nameList(deniedRows) + '看到的出口在' + countryList(deniedCountries) + '。OpenAI 与 Anthropic 都不向该地区提供服务，'
          + '打开、注册或调用接口时可能被拒，已有账号也可能被标记。换到支持地区的节点，并让 AI 相关的域名都走它；各家服务完整的支持地区见',
        link: { href: '/ai', text: 'AI 解锁检测' }
      });
    }

    /* IPv4 与 IPv6 各算各的：双栈网络里同一个人对不同网站本来就可能用不同的地址族，
       跨族比 IP 必然「不同」，那不是分流。跨族只比国家——国外网站经 IPv4 在美国、经 IPv6 在中国，才是真的漏了。 */
    var keysByFamily = { 4: {}, 6: {} };
    ok.forEach(function (row) { keysByFamily[family(row.ip)][exitKey(row.ip)] = true; });

    var intlLocs = { 4: [], 6: [] };
    intl.forEach(function (row) { intlLocs[family(row.ip)].push(loc(row)); });
    intlLocs[4] = unique(intlLocs[4]);
    intlLocs[6] = unique(intlLocs[6]);
    var familySplit = intlLocs[4].length && intlLocs[6].length && intlLocs[6].every(function (c) { return intlLocs[4].indexOf(c) === -1; });

    if (familySplit) {
      findings.push({
        tone: 'warn',
        title: 'IPv4 与 IPv6 走了不同出口',
        note: '经 IPv4 访问的国外网站看到的出口在' + countryList(intlLocs[4]) + '，经 IPv6 访问的在' + countryList(intlLocs[6]) + '。'
          + '常见原因是代理只接管了 IPv4：支持 IPv6 的网站会绕开代理直连。可以在代理软件里打开 IPv6 接管，或暂时在系统里关闭 IPv6。'
      });
    }

    /* 每个地址族至多一个出口才算「没分流」。两族各一个时还要看国家：
       IPv4 在美国、IPv6 在中国，往往是国内网站经 IPv6 直连、国外网站经 IPv4 走代理——那是分流，交给下面细看 */
    var dual = count(keysByFamily[4]) === 1 && count(keysByFamily[6]) === 1;
    var locs4 = unique(ok.filter(function (row) { return family(row.ip) === 4; }).map(loc));
    var locs6 = unique(ok.filter(function (row) { return family(row.ip) === 6; }).map(loc));
    var dualApart = dual && locs4.length && locs6.length && locs6.every(function (c) { return locs4.indexOf(c) === -1; });
    var single = count(keysByFamily[4]) <= 1 && count(keysByFamily[6]) <= 1 && !familySplit && !dualApart;

    if (single) {
      var exitLoc = mostCommon(ok.map(loc));
      var text = exitLoc === 'CN'
        ? '出口在中国大陆，这些网站都没有走代理。被屏蔽的国外网站大多打不开，可以到网络连通性里确认。'
        : (exitLoc ? '出口在' + countryName(exitLoc) + '。' : '')
          + '如果你在中国大陆、开着代理，说明代理处于全局模式：国内网站也绕道海外，打开会变慢，部分国内服务会把你当成海外用户。'
          + '如果你本来就在海外、没有用代理，这是正常的。';
      if (dual) {
        text += locs4.length && locs6.length
          ? '你同时有一个 IPv4 和一个 IPv6 出口，位于同一国家，属于正常的双栈网络。'
          : '你同时有一个 IPv4 和一个 IPv6 出口，其中一个只有少数网站看到、国家未知，可以对照下面的表格确认。';
      }
      findings.push({ tone: 'info', title: '所有网站走同一出口（未分流：直连或全局代理）', note: text, link: exitLoc === 'CN' ? { href: '/connectivity', text: '查看网络连通性' } : null });
    } else {
      var anyCN = ok.some(function (row) { return loc(row) === 'CN'; });
      var cnAway = cn.filter(function (row) { return loc(row) !== 'CN'; });
      var intlHome = intl.filter(function (row) { return loc(row) === 'CN'; });

      if (cnAway.length && anyCN) {
        findings.push({
          tone: 'warn',
          title: '国内网站也走了代理',
          note: nameList(cnAway) + '看到的出口不在中国（' + countryList(unique(cnAway.map(loc))) + '）。'
            + '访问国内网站会绕道海外、变慢，部分国内服务会把你判定为海外用户。把这些域名加进直连规则（或检查 GEOSITE,CN / GEOIP,CN 那几条的位置）即可。'
        });
      } else if (cnAway.length) {
        findings.push({
          tone: 'info',
          title: '国内网站看到的出口不在中国',
          note: nameList(cnAway) + '看到的出口在' + countryList(unique(cnAway.map(loc))) + '。'
            + '如果你在中国大陆，说明国内流量也走了代理（全局模式或规则缺漏）；如果你本来就在海外，这是正常的。'
        });
      }

      if (cn.length && !cnAway.length) {
        if (intl.length && !intlHome.length) {
          findings.push({
            tone: 'good',
            title: '分流正常：国内网站直连，国外网站走代理',
            note: cn.length + ' 个国内网站看到的出口在中国，' + intl.length + ' 个国外网站看到的出口在' + countryList(unique(intl.map(loc))) + '。'
          });
        } else if (intlHome.length && intlHome.length < intl.length) {
          findings.push({
            tone: 'warn',
            title: '部分国外网站没有走代理',
            note: nameList(intlHome) + '看到的出口在中国大陆。如果这是你有意设置的直连规则可以忽略；否则请检查代理软件里这些域名命中了哪条规则。'
          });
        } else if (intl.length) {
          findings.push({
            tone: 'info',
            title: '所有网站都从中国大陆直连',
            note: '出口地址不止一个，但都在中国大陆，多半是运营商的多出口或双栈网络，并没有走代理。'
          });
        }
      }

      /* AI 单独分流：同一地址族里，AI 网站的出口与其他国外网站一个都不重合 */
      var aiKeys = { 4: {}, 6: {} };
      var otherKeys = { 4: {}, 6: {} };
      probed.forEach(function (row) {
        if (row.group === 'ai') aiKeys[family(row.ip)][exitKey(row.ip)] = true;
        else if (row.region === 'intl') otherKeys[family(row.ip)][exitKey(row.ip)] = true;
      });

      var scattered = count(aiKeys[4]) > 1 || count(aiKeys[6]) > 1;
      var comparable = 0;
      var overlap = false;
      [4, 6].forEach(function (fam) {
        if (!count(aiKeys[fam]) || !count(otherKeys[fam])) return;
        comparable++;
        for (var key in aiKeys[fam]) if (otherKeys[fam][key]) overlap = true;
      });

      if (scattered) {
        findings.push({
          tone: 'warn',
          title: 'AI 网站分散在 ' + Math.max(count(aiKeys[4]), count(aiKeys[6])) + ' 个出口',
          note: '同一家服务的几个域名（例如 chatgpt.com、openai.com 与 sora.com）出口不一致，容易被当成异常登录。建议让所有 AI 相关的域名走同一个节点。'
        });
      } else if (ai.length && comparable && !overlap) {
        /* 按出口而不是按地址取：同一 /64 里轮换的几个地址是同一个出口。标题里写它在汇总里的编号，
           以及它的身份（单个地址；几个地址合成的 IPv6 出口写网段） */
        var aiExit = exits.map[mostCommon(ai.map(function (row) { return exitKey(row.ip); }))];
        findings.push({
          tone: 'info',
          title: 'AI 流量单独分流到出口 ' + aiExit.no + '（' + exitLabel(aiExit) + (aiExit.loc ? '，' + countryName(aiExit.loc) : '') + '）',
          note: ai.length + ' 个 AI 网站走的出口与其他国外网站不同，说明代理软件里为 AI 单独设置的规则生效了。'
        });
      }

      if (!findings.length) {
        findings.push({
          tone: 'info',
          title: '检测到 ' + exits.list.length + ' 个出口',
          note: '不同网站看到了不同的地址，但能用来判断国内 / 国外的国家信息不全，无法断定规则是否正确。可以对照下面每一行的国家自行判断。'
        });
      }
    }

    showVerdict(findings, failed.length, probed.length);
  }

  function showVerdict(findings, failedCount, okCount) {
    var head = findings[0];
    findings.forEach(function (item) { if (RANK[item.tone] > RANK[head.tone]) head = item; });

    verdict.classList.remove('is-good', 'is-warn', 'is-bad');
    if (head.tone !== 'info') verdict.classList.add('is-' + head.tone);
    verdictTitle.textContent = head.title;

    var nodes = [note(head, false)];
    findings.forEach(function (item) { if (item !== head) nodes.push(note(item, true)); });
    if (failedCount) {
      nodes.push(el('p', 'verdict__note', '另有 ' + failedCount + ' 个网站未能检测，结论只基于返回了地址的 ' + okCount + ' 个网站。'));
    }
    fill(verdictNotes, nodes);
    verdict.hidden = false;
  }

  function note(item, withTitle) {
    var p = el('p', 'verdict__note');
    if (withTitle) {
      /* 标题里本身常带冒号（「分流正常：国内直连……」），再接一个冒号会读成两层，用句号断开 */
      p.appendChild(el('strong', 'splitnotes__title', item.title));
      p.appendChild(document.createTextNode('。'));
    }
    p.appendChild(document.createTextNode(item.note));
    if (item.link) {
      var a = el('a', 'splitnotes__link', item.link.text);
      a.href = item.link.href;
      p.appendChild(document.createTextNode(' '));
      p.appendChild(a);
      p.appendChild(document.createTextNode('。'));
    }
    return p;
  }

  /* ---------------------------------------------------------------- 流程 */

  function setProgress(text) {
    if (progress) progress.textContent = text;
  }

  function settledCount() {
    return targets.filter(function (row) { return row.status === 'ok' || row.status === 'fail'; }).length;
  }

  function markOk(row, result, colos) {
    row.status = 'ok';
    row.ip = result.ip;
    row.loc = result.loc;
    row.colo = result.colo;
    row.ms = result.ms;
    row.via = result.via;
    row.kind = '';
    renderIp(row);
    renderColo(row, colos);
    refresh();
  }

  function markFailed(row, failure) {
    row.status = 'fail';
    row.kind = (failure && failure.kind) || 'error';
    row.ip = '';
    renderIp(row);
    renderGeo(row, '', false);
    renderColo(row, null);
    renderState(row, 0);
    refresh();
  }

  function pass(list, queue) {
    return Promise.all(list.map(function (row) {
      row.status = 'queued';
      renderState(row, 0);
      return queue.add(function () {
        row.status = 'running';
        row.attempts++;
        renderState(row, 0);
        return probe(row).then(function (result) {
          return iataReady.then(function (colos) { markOk(row, result, colos); });
        }, function (failure) {
          markFailed(row, failure);
        }).then(function () {
          if (!finished && running) setProgress('已完成 ' + settledCount() + ' / ' + targets.length + '……');
        });
      });
    }));
  }

  function retryLoop(index, queue) {
    var failed = targets.filter(retryable);
    if (index >= RETRY_DELAYS.length || !failed.length) return Promise.resolve();

    failed.forEach(function (row) {
      row.status = 'waiting';
      renderState(row, 0);
    });
    setProgress(failed.length + ' 个网站暂时失败，' + Math.round(RETRY_DELAYS[index] / 1000) + ' 秒后第 ' + (index + 1) + ' 次重试……');

    return P.sleep(RETRY_DELAYS[index]).then(function () {
      return pass(failed, queue);
    }).then(function () {
      evaluate();
      return retryLoop(index + 1, queue);
    });
  }

  function run() {
    if (running) return;
    running = true;
    finished = false;
    if (runButton) runButton.disabled = true;
    verdict.hidden = true;

    targets.forEach(function (row) {
      row.status = 'idle';
      row.ip = '';
      row.loc = '';
      row.colo = '';
      row.ms = null;
      row.via = '';
      row.kind = '';
      row.attempts = 0;
      renderIp(row);
      renderGeo(row, '', false);
      renderColo(row, null);
      renderState(row, 0);
    });
    refresh();

    var started = P.now();
    var queue = P.queue(LANES);
    if (!iataReady) iataReady = P.iata(IATA_URL);
    setProgress('正在检测 ' + targets.length + ' 个网站……');

    pass(targets, queue).then(function () {
      evaluate();
      return retryLoop(0, queue);
    }).then(null, function (error) {
      /* 正常路径上不会走到这里：每一行的成败都在 pass 里兜住了。真走到了也要把按钮还回去 */
      if (window.console && console.error) console.error('[JudgeIP] 分流检测中断：', error);
    }).then(function () {
      running = false;
      finished = true;
      if (runButton) runButton.disabled = false;
      refresh();
      evaluate();

      var ok = targets.filter(function (row) { return row.status === 'ok'; }).length;
      var bad = targets.length - ok;
      var seconds = ((P.now() - started) / 1000).toFixed(1);
      setProgress('完成：' + ok + ' 个网站返回了出口 IP'
        + (bad ? '，' + bad + ' 个未能检测' + (RETRY_DELAYS.length ? '（网络失败的已重试）' : '') : '')
        + '，用时 ' + seconds + ' 秒。');
    });
  }

  /* ---------------------------------------------------------------- 遮罩

     录屏、截图时把页面上所有 IP 收成 8.8.*.*。纯显示层的开关：不落存储、不发请求，刷新即恢复。
     真值一直在行的状态里，遮罩只改显示；复制出去的仍是完整地址。 */
  function setMasked(value) {
    masked = value;
    root.classList.toggle('is-masked', masked);
    if (maskButton) maskButton.setAttribute('aria-pressed', masked ? 'true' : 'false');
    if (maskLabel) maskLabel.textContent = masked ? '显示 IP' : '隐藏 IP';
    rows.forEach(renderIp);
    refresh();
    if (!verdict.hidden) evaluate();
  }

  if (maskButton) {
    maskButton.addEventListener('click', function () { setMasked(!masked); });
  }

  if (runButton) {
    runButton.addEventListener('click', run);
  }

  /* 本站那一行先把出口编号挂上：在第一个网站返回之前，汇总里就已经有「本站看到的地址」可以对照 */
  if (selfRow) renderIp(selfRow);
  refresh();

  /* 打开即测：整页就这一件事，让访客再点一下按钮没有意义（与 CDN、连通性两页一致） */
  run();
})();
