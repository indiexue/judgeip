/* JudgeIP — 全球 Ping。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   测量由访客的浏览器直接请求 Globalping（api.globalping.io）完成：
   POST /v1/measurements 创建一次测量、拿到 id，再每秒 GET /v1/measurements/{id} 取一次进度，
   哪台探针先测完就先填哪一行。额度按访客自己的 IP 计，本站不代理、也看不到他 Ping 了谁。

   节点清单与位置条件由 src/GlobalPing.php 渲染进每一行的 data-filter，脚本从 DOM 读回去拼请求——
   页面上印着的节点与真正发出去的位置条件永远是同一份。

   结果不是按顺序对号入座的：Globalping 不保证 results 的顺序与 locations 一致，
   某个位置分不到探针时结果还会少一条，按下标对齐就会整体错位。所以按探针报回的城市 / 国家
   逐级归位（见 assign()），国家对不上的探针绝不借用别国的行，单独成行，放进它所在大洲的分组。

   预填与分享用网址片段 /ping#host=…，不用查询串：片段不随请求发出，目标不会进本站的访问日志。 */
(function () {
  'use strict';

  var root = document.getElementById('ping');
  if (!root) return;

  /* probe.js 没加载成功（被扩展拦下、网络中断）：不能让按钮点了没反应、页面却一声不吭。
     说清楚原因、锁住按钮，并拦下表单的原生提交——否则回车会把页面带着输入框的内容整页重新打开一遍 */
  if (!window.IpcxProbe) {
    var missingForm = root.querySelector('[data-ping-form]');
    var missingRun = root.querySelector('[data-ping-run]');
    var missingBox = root.querySelector('[data-ping-error]');
    var missingText = root.querySelector('[data-ping-error-text]');
    var missingHint = root.querySelector('[data-ping-progress]');
    var missingMessage = '检测脚本加载失败，请刷新页面重试。';
    if (missingBox && missingText) {
      missingText.textContent = missingMessage;
      missingBox.hidden = false;
    } else if (missingHint) {
      missingHint.textContent = missingMessage;
    }
    if (missingRun) missingRun.disabled = true;
    if (missingForm) missingForm.addEventListener('submit', function (event) { event.preventDefault(); });
    return;
  }

  var P = window.IpcxProbe;

  function toInt(value, fallback) {
    var n = parseInt(value, 10);
    return isNaN(n) || n <= 0 ? fallback : n;
  }

  var API = root.getAttribute('data-api') || 'https://api.globalping.io/v1/measurements';
  var PACKETS = toInt(root.getAttribute('data-packets'), 3);
  var PORT = toInt(root.getAttribute('data-port'), 443);
  var POLL_MS = toInt(root.getAttribute('data-poll-ms'), 1000);
  var POLL_MAX = toInt(root.getAttribute('data-poll-max'), 30);

  /* 创建测量要等 Globalping 挑完探针才返回，给宽一点；轮询是一次普通的 GET */
  var CREATE_TIMEOUT = 15000;
  var POLL_TIMEOUT = 8000;
  /* 连续失败几次才放弃轮询：一次网络抖动不该让整轮测量作废 */
  var POLL_FAIL_MAX = 3;
  /* 延迟条的满格：400 ms 以上一律画满。线性刻度——近处几毫秒与跨洲三百毫秒的差距本来就该一眼看出来 */
  var BAR_FULL_MS = 400;

  var form = root.querySelector('[data-ping-form]');
  var input = root.querySelector('[data-ping-input]');
  var proto = root.querySelector('[data-ping-proto]');
  var runButton = root.querySelector('[data-ping-run]');
  var errorBox = root.querySelector('[data-ping-error]');
  var errorText = root.querySelector('[data-ping-error-text]');
  var progress = root.querySelector('[data-ping-progress]');
  var verdict = root.querySelector('[data-ping-verdict]');
  var verdictTitle = root.querySelector('[data-ping-verdict-title]');
  var verdictNote = root.querySelector('[data-ping-verdict-note]');
  var targetCell = root.querySelector('[data-ping-target]');
  var modeCell = root.querySelector('[data-ping-mode]');
  var resolvedCell = root.querySelector('[data-ping-resolved]');
  var statusCell = root.querySelector('[data-ping-status]');

  if (!form || !input || !runButton) return;

  var sections = {};
  Array.prototype.forEach.call(root.querySelectorAll('[data-ping-region]'), function (section) {
    sections[section.getAttribute('data-ping-region')] = {
      node: section,
      list: section.querySelector('[data-ping-rows]'),
      hiddenAtStart: section.hidden
    };
  });

  var baseRows = Array.prototype.map.call(root.querySelectorAll('[data-ping-row]'), readRow);
  var rows = baseRows.slice();

  /* 每轮测量一个令牌：上一轮迟到的轮询结果一律丢弃，不会把新一轮的格子写乱 */
  var token = 0;
  var running = false;

  /* ---------------------------------------------------------------- 数据表 */

  /* Globalping 的 probe.continent 是两位洲代码 */
  var CONTINENTS = { AS: 'asia', EU: 'europe', NA: 'americas', SA: 'americas', OC: 'oceania' };

  /* 公网探针解析不到、或根本不该被 Ping 的后缀 */
  var RESERVED_TLDS = ['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp',
    'private', 'test', 'invalid', 'example', 'onion', 'arpa', 'alt'];

  /* IPv4 特殊用途地址段（RFC 6890 等）：私有、回环、链路本地、运营商级 NAT、文档示例、组播、保留 */
  var V4_RESERVED = [
    [[0, 0, 0, 0], 8], [[10, 0, 0, 0], 8], [[100, 64, 0, 0], 10], [[127, 0, 0, 0], 8],
    [[169, 254, 0, 0], 16], [[172, 16, 0, 0], 12], [[192, 0, 0, 0], 24], [[192, 0, 2, 0], 24],
    [[192, 88, 99, 0], 24], [[192, 168, 0, 0], 16], [[198, 18, 0, 0], 15], [[198, 51, 100, 0], 24],
    [[203, 0, 113, 0], 24], [[224, 0, 0, 0], 4], [[240, 0, 0, 0], 4]
  ];

  /* ---------------------------------------------------------------- 工具 */

  var el = P.el;

  /* 格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function dim(text) {
    return el('span', 'dim', text);
  }

  function tag(tone, text) {
    return el('span', 'tag tag--' + tone, text);
  }

  function upper(value) {
    return String(value || '').toUpperCase().trim();
  }

  /* 城市名比较前去掉变音符号与标点：São Paulo、Sao Paulo、sao-paulo 视为同一个 */
  function normCity(value) {
    var s = String(value || '').toLowerCase();
    if (s.normalize) s = s.normalize('NFD').replace(/[̀-ͯ]/g, '');
    return s.replace(/[^a-z0-9]+/g, ' ').trim();
  }

  function isNum(v) {
    return typeof v === 'number' && !isNaN(v) && isFinite(v);
  }

  /* 10 ms 以内保留一位小数：同城几毫秒的差别有意义；再往上取整，小数只是噪音 */
  function ms(value) {
    if (!isNum(value)) return '—';
    return value < 10 ? value.toFixed(1) : String(Math.round(value));
  }

  function seconds(msValue) {
    return (msValue / 1000).toFixed(1) + ' 秒';
  }

  function humanWait(sec) {
    if (sec < 60) return Math.max(1, Math.round(sec)) + ' 秒';
    return Math.ceil(sec / 60) + ' 分钟';
  }

  /* 四档与图例、prose 里的说明一致 */
  function grade(avg) {
    if (avg < 100) return 'good';
    if (avg < 200) return 'ok';
    if (avg < 350) return 'slow';
    return 'bad';
  }

  function parseJson(text) {
    try { return JSON.parse(text); } catch (e) { return null; }
  }

  /* 地区叫法全站统一由 probe.js 给出（中国香港、中国台湾……），这里不再各自覆盖 */
  function countryLabel(cc) {
    cc = upper(cc);
    return P.countryName(cc) || cc;
  }

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function svg(tagName, attrs) {
    var node = document.createElementNS(SVG_NS, tagName);
    for (var key in attrs) node.setAttribute(key, String(attrs[key]));
    return node;
  }

  /* 进度用 <rect width> 而不是 style="width:…"：CSP 的 style-src 只有 'self'，行内样式会被整条丢掉 */
  function bar(avg) {
    var box = svg('svg', { 'class': 'pingbar', viewBox: '0 0 100 6', 'aria-hidden': 'true' });
    box.appendChild(svg('rect', { 'class': 'pingbar__track', x: 0, y: 0, width: 100, height: 6, rx: 3 }));
    if (isNum(avg)) {
      var width = Math.max(3, Math.min(100, Math.round(avg / BAR_FULL_MS * 100)));
      box.appendChild(svg('rect', { 'class': 'pingbar__fill', x: 0, y: 0, width: width, height: 6, rx: 3 }));
    }
    return box;
  }

  /* ---------------------------------------------------------------- 行 */

  function readRow(node) {
    var filter = parseJson(node.getAttribute('data-filter') || '') || {};
    return {
      node: node,
      extra: false,
      name: node.getAttribute('data-name') || '',
      cc: upper(node.getAttribute('data-cc')),
      region: node.getAttribute('data-region') || 'other',
      city: normCity(node.getAttribute('data-city')),
      filter: filter,
      probe: node.querySelector('[data-ping-probe]'),
      rtt: node.querySelector('[data-ping-rtt]'),
      loss: node.querySelector('[data-ping-loss]'),
      barCell: node.querySelector('[data-ping-bar]'),
      index: null,
      outcome: null
    };
  }

  /* 无法归位的探针单独成行：结构与服务端渲染的行一致，只是名字取自探针自己报的国家 */
  function extraRow(probe, region) {
    var section = sections[region] || sections.other;
    var cc = upper(probe.country);
    var node = el('div', 'pingrow');
    node.setAttribute('data-ping-row', '');

    var nodeCell = el('div', 'pingrow__node');
    var name = el('span', 'pingrow__name');
    var flag = P.flag(cc);
    if (flag) {
      var flagNode = el('span', 'flag', flag);
      flagNode.setAttribute('aria-hidden', 'true');
      name.appendChild(flagNode);
      name.appendChild(document.createTextNode(' '));
    }
    var label = countryLabel(cc) || '未知地区';
    name.appendChild(document.createTextNode(label));
    var probeLine = el('span', 'pingrow__probe');
    nodeCell.appendChild(name);
    nodeCell.appendChild(probeLine);

    var rttCell = el('div', 'pingrow__rtt');
    rttCell.appendChild(el('span', 'pingrow__k', '最小 / 平均 / 最大'));
    var rtt = el('span', 'pingrow__v mono');
    rttCell.appendChild(rtt);

    var lossCell = el('div', 'pingrow__loss');
    lossCell.appendChild(el('span', 'pingrow__k', '丢包'));
    var loss = el('span', 'pingrow__v mono');
    lossCell.appendChild(loss);

    var barCell = el('div', 'pingrow__bar');
    barCell.appendChild(bar(null));

    node.appendChild(nodeCell);
    node.appendChild(rttCell);
    node.appendChild(lossCell);
    node.appendChild(barCell);

    if (section && section.list) {
      section.list.appendChild(node);
      section.node.hidden = false;
    }

    var row = {
      node: node, extra: true, name: label, cc: cc, region: region, city: '', filter: {},
      probe: probeLine, rtt: rtt, loss: loss, barCell: barCell, index: null, outcome: null
    };
    rows.push(row);
    return row;
  }

  function setRowState(row, state) {
    row.node.className = 'pingrow' + (state ? ' is-' + state : '');
  }

  /* 一轮开始前把所有格子恢复成空白：上一轮多出来的行删掉，原本隐藏的分组重新藏起来 */
  function resetRows(probeText, rttNode) {
    rows.forEach(function (row) {
      if (row.extra && row.node.parentNode) row.node.parentNode.removeChild(row.node);
    });
    rows = baseRows.slice();
    Object.keys(sections).forEach(function (key) {
      sections[key].node.hidden = sections[key].hiddenAtStart;
    });
    rows.forEach(function (row) {
      row.index = null;
      row.outcome = null;
      setRowState(row, '');
      fill(row.probe, [document.createTextNode(probeText)]);
      fill(row.rtt, [rttNode ? rttNode() : dim('—')]);
      fill(row.loss, [dim('—')]);
      fill(row.barCell, [bar(null)]);
    });
  }

  /* ---------------------------------------------------------------- 输入校验

     只是替访客省一次额度：Globalping 服务端自己也会拒绝内网目标。
     IP 必须是公网地址；域名必须是带点的 LDH 主机名（中文域名先转成 punycode）。
     粘贴整条网址也行——取出主机部分，去掉端口。 */

  function invalid(message) {
    return { ok: false, message: message };
  }

  function normalizeTarget(raw) {
    var value = String(raw || '').trim();
    if (!value) return invalid('请输入要 Ping 的 IP 地址或域名。');
    if (/\s/.test(value)) return invalid('目标里不能有空格。');

    var url = /^[a-z][a-z0-9+.\-]*:\/\/([^\/?#]*)/i.exec(value);
    value = url ? url[1] : value.split(/[\/?#]/)[0];
    value = value.replace(/^[^@\[]*@/, '');

    if (value.charAt(0) === '[') {
      var end = value.indexOf(']');
      if (end < 0) return invalid('IPv6 地址格式不对。');
      value = value.slice(1, end);
    } else if (/^[^:]+:\d+$/.test(value)) {
      value = value.replace(/:\d+$/, '');
    }

    /* 全角字符、中文句号、中文域名：交给浏览器的 URL 解析器按 IDNA 规则转成 ASCII */
    if (/[^\x00-\x7f]/.test(value)) {
      try {
        value = new URL('http://' + value + '/').hostname;
      } catch (e) {
        return invalid('域名格式不对。');
      }
    }

    value = value.replace(/\.$/, '').toLowerCase();
    if (!value) return invalid('请输入要 Ping 的 IP 地址或域名。');

    if (value.indexOf(':') !== -1) return checkIPv6(value);
    if (/^[0-9.]+$/.test(value)) return checkIPv4(value);
    return checkHost(value);
  }

  function checkIPv4(value) {
    var parts = value.split('.');
    if (parts.length !== 4) return invalid('IPv4 地址应为四段数字，例如 8.8.8.8。');

    var octets = [];
    for (var i = 0; i < 4; i++) {
      /* 带前导零的写法（010）在不同实现里可能被当成八进制，直接拒绝，免得 Ping 到另一个地址 */
      if (!/^(0|[1-9]\d{0,2})$/.test(parts[i]) || Number(parts[i]) > 255) {
        return invalid('IPv4 地址每段应为 0–255 的数字，例如 8.8.8.8。');
      }
      octets.push(Number(parts[i]));
    }

    var n = ((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3];
    for (var j = 0; j < V4_RESERVED.length; j++) {
      var b = V4_RESERVED[j][0];
      var base = ((b[0] * 256 + b[1]) * 256 + b[2]) * 256 + b[3];
      var size = Math.pow(2, 32 - V4_RESERVED[j][1]);
      if (Math.floor(n / size) === Math.floor(base / size)) {
        return invalid(value + ' 是内网或保留地址，公网上的探针无法 Ping 到它。');
      }
    }

    return { ok: true, value: value, kind: 'ipv4' };
  }

  function checkIPv6(value) {
    if (!/^[0-9a-f:]+$/.test(value)) return invalid('IPv6 地址格式不对（不支持带 % 的区域标识或内嵌 IPv4 的写法）。');

    var halves = value.split('::');
    if (halves.length > 2) return invalid('IPv6 地址格式不对。');
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    var groups = head.concat(tail);
    for (var i = 0; i < groups.length; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return invalid('IPv6 地址格式不对。');
    }
    if (halves.length === 1 ? groups.length !== 8 : groups.length > 7) return invalid('IPv6 地址格式不对。');

    /* 只放行全球单播 2000::/3，再扣掉两段文档示例地址：2001:db8::/32 与 3fff::/20 */
    var key = P.ipKey(value);
    var first = parseInt(key.slice(0, 4), 16);
    var second = parseInt(key.slice(5, 9), 16);
    if (first < 0x2000 || first > 0x3fff || (first === 0x2001 && second === 0x0db8) || (first === 0x3fff && second < 0x1000)) {
      return invalid('这是内网、链路本地或保留的 IPv6 地址，公网上的探针无法 Ping 到它。');
    }

    return { ok: true, value: value, kind: 'ipv6' };
  }

  function checkHost(value) {
    if (value === 'localhost' || /\.localhost$/.test(value)) {
      return invalid('localhost 指的是你自己的电脑，远方的探针 Ping 不到它。');
    }
    if (value.length > 253) return invalid('域名太长了（最多 253 个字符）。');

    var labels = value.split('.');
    if (labels.length < 2) return invalid('请输入完整的域名（例如 example.com），或公网 IP 地址。');
    for (var i = 0; i < labels.length; i++) {
      if (!/^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$/.test(labels[i])) {
        return invalid('域名只能由字母、数字和连字符组成，每一段不能以连字符开头或结尾。');
      }
    }

    var tld = labels[labels.length - 1];
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$/.test(tld)) return invalid('域名后缀不对。');
    if (RESERVED_TLDS.indexOf(tld) !== -1) {
      return invalid('.' + tld + ' 是内网或保留用的后缀，公网上的探针解析不到它。');
    }

    return { ok: true, value: value, kind: 'host' };
  }

  /* ---------------------------------------------------------------- 结果归位

     第一遍：城市级的行要求城市名与国家都对上，国家级的行按国家代码精确匹配；
     第二遍：同一个国家的空行（Tokyo 那一行分到了千代田区的探针、阿什本那一行分到了邻近的 Sterling）；
     国家对不上任何一行的，单独成行、用探针自己的国家命名——绝不拿同一大洲的空行顶替：
     「英国伦敦」那一行装着一台加拿大 London 的探针，延迟条和评级就全是别国的，只靠行内一个小小的国名很难看出来。
     位置条件里已经带了 country（见 src/GlobalPing.php），正常情况下不会出现这种探针；这里是第二道保险。
     每条结果只在第一次出现时归位一次，之后的轮询按下标直接找到它的行。 */

  function continentRegion(code) {
    return CONTINENTS[upper(code)] || 'other';
  }

  function cityMatches(rowCity, probeCity) {
    var city = normCity(probeCity);
    return !!city && !!rowCity && (city.indexOf(rowCity) !== -1 || rowCity.indexOf(city) !== -1);
  }

  function assign(state, results) {
    var pending = [];
    for (var i = 0; i < results.length; i++) {
      if (!state.map[i]) pending.push(i);
    }
    if (!pending.length) return;

    var passes = [
      function (row, probe) {
        if (row.cc !== upper(probe.country)) return false;
        return row.city ? cityMatches(row.city, probe.city) : true;
      },
      function (row, probe) { return row.cc === upper(probe.country); }
    ];

    passes.forEach(function (match) {
      pending = pending.filter(function (index) {
        var probe = (results[index] && results[index].probe) || {};
        for (var r = 0; r < baseRows.length; r++) {
          var row = baseRows[r];
          if (row.index === null && match(row, probe)) {
            row.index = index;
            state.map[index] = row;
            return false;
          }
        }
        return true;
      });
    });

    pending.forEach(function (index) {
      var probe = (results[index] && results[index].probe) || {};
      var row = extraRow(probe, continentRegion(probe.continent));
      row.index = index;
      state.map[index] = row;
    });
  }

  /* ---------------------------------------------------------------- 单行渲染 */

  /* 探针自己报出的错误多是英文的一行，常见几种翻成中文，其余原样显示（textContent，不会被当成 HTML）。
     「Temporary failure in name resolution」是 Linux ping 解析不了域名时的原话，同样归为解析失败 */
  function failureReason(raw) {
    var line = String(raw || '').split('\n').map(function (s) { return s.trim(); }).filter(Boolean)[0] || '';
    if (/unknown host|not known|could not resolve|name resolution|enotfound|nxdomain|no address|failed to resolve|servfail/i.test(line)) {
      return '域名解析失败';
    }
    if (/private|reserved|not allowed/i.test(line)) return '目标解析到了内网或保留地址，探针拒绝测量';
    if (!line) return '探针未返回原因';
    return line.length > 100 ? line.slice(0, 100) + '…' : line;
  }

  function outcomeOf(item) {
    var result = (item && item.result) || {};
    var stats = result.stats || {};
    if (!result.status || result.status === 'in-progress') return { kind: 'running' };
    if (result.status === 'offline') return { kind: 'offline' };
    if (isNum(stats.avg) && !(stats.loss >= 100)) return { kind: 'ok', stats: stats };
    /* 没拿到地址、也一个包都没发出去：卡在解析或探针内部，算「探测失败」；
       地址有了却一个回应都没有，才是真正的「不可达」 */
    if (result.status === 'failed' && !result.resolvedAddress && !stats.total) {
      return { kind: 'error', reason: failureReason(result.rawOutput) };
    }
    return { kind: 'down' };
  }

  function probeLine(item, primary) {
    var probe = item.probe || {};
    var result = item.result || {};
    var parts = [];

    /* 不必再写国家：归位只把探针放进同一国家的行（见 assign()），单独成行的则以探针自己的国家命名 */
    var where = probe.city || '';
    if (probe.state && upper(probe.country) === 'US') where += (where ? ', ' : '') + probe.state;
    if (where) parts.push(el('span', 'pingrow__where', where));

    var net = (probe.asn ? 'AS' + probe.asn : '') + (probe.network ? (probe.asn ? ' ' : '') + probe.network : '');
    if (net) parts.push(el('span', 'pingrow__net', net));

    /* 与多数节点解析到的地址不同时才写出来：GeoDNS / CDN 把这一地区送去了别处 */
    if (result.resolvedAddress && primary && result.resolvedAddress !== primary) {
      var addr = el('span', 'pingrow__addr mono', '→ ' + P.compactIp(result.resolvedAddress));
      addr.title = result.resolvedAddress;
      parts.push(addr);
    }

    return parts;
  }

  function renderRow(row, item, primary, isTcp) {
    var outcome = outcomeOf(item);
    row.outcome = outcome;

    var line = probeLine(item, primary);
    if (outcome.kind === 'error') line.push(el('span', 'pingrow__why', outcome.reason));
    fill(row.probe, line.length ? line : [dim('探针信息缺失')]);

    if (outcome.kind === 'running') {
      setRowState(row, 'running');
      fill(row.rtt, [el('span', 'pingrow__wait', '测量中…')]);
      fill(row.loss, [dim('—')]);
      fill(row.barCell, [bar(null)]);
      return;
    }

    if (outcome.kind === 'ok') {
      var s = outcome.stats;
      setRowState(row, grade(s.avg));
      fill(row.rtt, [
        el('span', 'pingrow__num', ms(s.min)),
        el('span', 'pingrow__sep', ' / '),
        el('span', 'pingrow__avg', ms(s.avg)),
        el('span', 'pingrow__sep', ' / '),
        el('span', 'pingrow__num', ms(s.max)),
        el('span', 'pingrow__unit', ' ms')
      ]);
      var loss = isNum(s.loss) ? Math.round(s.loss) : 0;
      fill(row.loss, [loss > 0 ? tag('warn', loss + '%') : dim('0%')]);
      fill(row.barCell, [bar(s.avg)]);
      return;
    }

    setRowState(row, outcome.kind === 'down' || outcome.kind === 'error' ? 'down' : 'none');
    var label = outcome.kind === 'offline' ? tag('muted', '探针离线')
      : outcome.kind === 'error' ? tag('leak', '探测失败')
      : tag('leak', '不可达');
    if (outcome.kind === 'down') {
      label.title = isTcp ? '3 次握手都没有收到回应' : '3 个包都没有收到回应：目标可能屏蔽了 ICMP，可以换 TCP 443 再测';
    }
    fill(row.rtt, [label]);
    fill(row.loss, [outcome.kind === 'down' ? tag('leak', '100%') : dim('—')]);
    fill(row.barCell, [bar(null)]);
  }

  /* 一轮结束时仍然空着或停在「测量中」的行。why 只用于汇总：noprobe 没分到探针 / timeout 没测完 */
  function closeRow(row, why, text, probeText) {
    setRowState(row, 'none');
    row.outcome = { kind: 'none', why: why };
    fill(row.rtt, [tag('muted', text)]);
    fill(row.loss, [dim('—')]);
    if (probeText) fill(row.probe, [dim(probeText)]);
  }

  /* ---------------------------------------------------------------- 汇总 */

  /* 各地解析到的地址，按出现次数排序；只有一个地址时不标次数 */
  function resolvedSummary(results) {
    var counts = {};
    var order = [];
    results.forEach(function (item) {
      var addr = item && item.result && item.result.resolvedAddress;
      if (!addr) return;
      if (!counts[addr]) { counts[addr] = 0; order.push(addr); }
      counts[addr]++;
    });
    order.sort(function (a, b) { return counts[b] - counts[a]; });
    return { list: order, counts: counts, primary: order.length ? order[0] : '' };
  }

  function renderResolved(summary) {
    if (!summary.list.length) {
      fill(resolvedCell, [dim('等待探针返回')]);
      return;
    }
    var box = el('span', 'tags');
    var shown = summary.list.slice(0, 6);
    shown.forEach(function (addr) {
      var text = P.compactIp(addr) + (summary.list.length > 1 ? ' ×' + summary.counts[addr] : '');
      var node = el('span', 'tag tag--name mono', text);
      node.title = addr;
      box.appendChild(node);
    });
    if (summary.list.length > shown.length) box.appendChild(dim('等 ' + summary.list.length + ' 个'));
    fill(resolvedCell, [box]);
  }

  function setProgress(text) {
    if (progress) progress.textContent = text;
  }

  function showVerdict(tone, title, note) {
    if (!verdict) return;
    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    verdictNote.textContent = note;
  }

  function rawLink(id) {
    var link = el('a', 'pinglink', '原始数据');
    link.href = API + '/' + encodeURIComponent(id);
    link.target = '_blank';
    link.rel = 'noopener noreferrer external';
    return link;
  }

  function summarize(state, timedOut) {
    var ok = [];
    var down = [];
    var errors = [];
    var missing = { noprobe: 0, timeout: 0, offline: 0 };

    rows.forEach(function (row) {
      var outcome = row.outcome || { kind: 'none', why: 'noprobe' };
      if (outcome.kind === 'ok') ok.push(row);
      else if (outcome.kind === 'down') down.push(row);
      else if (outcome.kind === 'error') errors.push(row);
      else if (outcome.kind === 'offline') missing.offline++;
      else missing[outcome.why === 'timeout' ? 'timeout' : 'noprobe']++;
    });

    /* 没出结果的几类分开说：「没分到探针」与目标无关，「超时」「离线」是探针那一侧的问题 */
    var gaps = [];
    if (missing.noprobe) gaps.push(missing.noprobe + ' 个地区暂无可用探针');
    if (missing.timeout) gaps.push(missing.timeout + ' 台探针未在时限内测完');
    if (missing.offline) gaps.push(missing.offline + ' 台探针中途离线');
    var tail = gaps.length ? '另有 ' + gaps.join('，') + '。' : '';
    var names = function (list) {
      var picked = list.slice(0, 4).map(function (row) { return row.name; }).join('、');
      return list.length > 4 ? picked + ' 等 ' + list.length + ' 个' : picked;
    };

    if (!ok.length && !down.length && !errors.length) {
      showVerdict('is-warn', '没有拿到任何节点的结果',
        timedOut
          ? '探针没能在约 ' + Math.round(POLL_MAX * POLL_MS / 1000) + ' 秒内测完。Globalping 繁忙时偶尔会这样，稍等片刻再测一次。'
          : '这一刻 Globalping 在所选地区都没有可用的探针，稍后再试。');
      return;
    }

    if (!ok.length && errors.length && !down.length) {
      showVerdict('is-bad', '目标无法解析或探测失败',
        '探针报告：' + errors[0].outcome.reason + '。请检查域名拼写，或确认它有公网的 A / AAAA 记录。');
      return;
    }

    if (!ok.length) {
      showVerdict('is-bad', '所有节点都不可达',
        state.tcp
          ? '各地探针与目标 ' + PORT + ' 端口的握手都没有成功：这个端口可能没有开放，或者目标确实离线。'
            + '如果目标是网站域名，确认它解析到的地址是否正确。'
          : '很可能是目标屏蔽了 ICMP——云服务器的安全组、企业防火墙默认如此，并不代表服务不可用。'
            + '把方式切到 TCP ' + PORT + ' 再测一次：TCP 也全部不通，才说明目标确实连不上。');
      return;
    }

    var sorted = ok.slice().sort(function (a, b) { return a.outcome.stats.avg - b.outcome.stats.avg; });
    var fastest = sorted[0];
    var slowest = sorted[sorted.length - 1];
    var median = P.median(ok.map(function (row) { return row.outcome.stats.avg; }));
    var speed = '最快的是' + fastest.name + '（' + ms(fastest.outcome.stats.avg) + ' ms）'
      + (sorted.length > 1 ? '，最慢的是' + slowest.name + '（' + ms(slowest.outcome.stats.avg) + ' ms）' : '')
      + (sorted.length > 2 ? '，各地平均延迟的中位数约 ' + ms(median) + ' ms' : '') + '。';

    if (down.length || errors.length) {
      var what = [];
      if (down.length) what.push(names(down) + '没有收到回应');
      if (errors.length) what.push(names(errors) + '探测失败（' + errors[0].outcome.reason + '）');
      showVerdict('is-warn', ok.length + ' 个节点可达，' + (down.length + errors.length) + ' 个不可达',
        what.join('，') + (!down.length ? '。'
          : state.tcp
            ? '，可能是那一带到目标的线路有问题，或目标对部分地区做了封锁。'
            : '。如果只是个别地区，可能是当地线路或防火墙过滤了 ICMP，可以换 TCP ' + PORT + ' 对照。')
          + speed + tail);
      return;
    }

    showVerdict('is-good', (tail ? '测到的 ' : '全部 ') + ok.length + ' 个节点均可达', speed + tail);
  }

  /* ---------------------------------------------------------------- 主流程 */

  /* 把目标写进地址栏的片段：/ping#host=…。整个地址重写一遍，顺手去掉旧链接带来的 ?host= 查询串。
     用 replaceState 而不是给 location.hash 赋值：不多出一条历史记录，也不触发 hashchange */
  function rememberTarget(value) {
    try {
      if (window.history && history.replaceState) {
        history.replaceState(null, '', location.pathname + (value ? '#host=' + encodeURIComponent(value) : ''));
      }
    } catch (e) { /* file:// 或沙箱里可能不允许改地址栏，不影响测量 */ }
  }

  function setRunning(on) {
    running = on;
    runButton.disabled = on;
    runButton.textContent = on ? '测量中' : '开始';
    if (proto) proto.disabled = on;
  }

  function showError(message) {
    if (!errorBox) return;
    errorText.textContent = message;
    errorBox.hidden = !message;
  }

  /* 创建失败、或轮询彻底失败且一条结果都没拿到：所有行回到「未测量」，结论写明原因 */
  function fail(state, title, note) {
    if (state.token !== token) return;
    resetRows('未测量', null);
    showVerdict('is-bad', title, note);
    setProgress('这一轮没有完成，原因见下方说明。');
    fill(statusCell, state.id ? [dim('测量未完成 · '), rawLink(state.id)] : [dim('未能创建测量')]);
    fill(resolvedCell, [dim('—')]);
    setRunning(false);
  }

  function networkFailure(state, failure, during) {
    var kind = failure && failure.kind;
    if (kind === 'csp') {
      fail(state, '浏览器拦下了对 Globalping 的请求',
        '本页的内容安全策略（CSP）没有放行 api.globalping.io，这是本站的部署配置问题，不是你的网络问题。');
    } else if (kind === 'timeout') {
      fail(state, '连接 Globalping 超时',
        during + '时等待太久没有响应。api.globalping.io 在部分网络下访问不稳定，稍后重试，或换一个网络环境。');
    } else {
      fail(state, '无法连接 Globalping',
        during + '失败：请求没能到达 api.globalping.io（可能被当前网络、代理规则或浏览器扩展拦截）。');
    }
  }

  function createFailure(state, status, data, headers) {
    var error = (data && data.error) || {};
    var detail = '';
    if (error.params && typeof error.params === 'object') {
      var keys = Object.keys(error.params);
      if (keys.length) detail = String(error.params[keys[0]]);
    }
    if (!detail && error.message) detail = String(error.message);
    if (detail.length > 160) detail = detail.slice(0, 160) + '…';

    if (status === 429) {
      var wait = NaN;
      try {
        wait = parseInt(headers.get('Retry-After') || headers.get('X-RateLimit-Reset') || '', 10);
      } catch (e) { wait = NaN; }
      fail(state, '这一小时的测量额度用完了',
        'Globalping 按你的出口 IP 限制匿名测量：每小时约 250 个「探针·次」，本页每轮消耗 ' + baseRows.length + ' 次。'
        + (isNum(wait) && wait > 0 ? '额度约 ' + humanWait(wait) + '后恢复。' : '额度按小时滚动恢复，稍后再试。')
        + '如果你和很多人共用同一个出口（公司网络、公共代理），额度可能已被别人用掉。');
    } else if (status === 400) {
      fail(state, 'Globalping 拒绝了这个目标',
        '它认为这次测量的参数不合法' + (detail ? '：' + detail : '。') + ' 请确认目标是公网 IP 或可以公开解析的域名。');
    } else if (status === 422) {
      fail(state, '没有找到可用的探针',
        'Globalping 这一刻在所选地区都找不到能执行这次测量的探针（IPv6 目标可用的探针更少），稍后再试。');
    } else if (status >= 500) {
      fail(state, 'Globalping 暂时不可用', '服务端返回了 HTTP ' + status + '，通常是临时故障，过几分钟再试。');
    } else {
      fail(state, 'Globalping 返回了意外的响应',
        'HTTP ' + status + (detail ? '：' + detail : '') + '。稍后再试。');
    }
  }

  function start(target, tcp) {
    token++;
    var state = {
      token: token,
      target: target,
      tcp: tcp,
      id: '',
      polls: 0,
      fails: 0,
      map: {},
      last: null,
      remaining: NaN,
      started: P.now()
    };

    setRunning(true);
    showError('');
    if (verdict) verdict.hidden = true;
    resetRows('排队中', function () { return el('span', 'pingrow__wait', '等待分配探针…'); });

    fill(targetCell, [el('span', 'mono', target.value)]);
    fill(modeCell, [document.createTextNode(tcp
      ? 'TCP ' + PORT + ' · 每个节点握手 ' + PACKETS + ' 次'
      : 'ICMP · 每个节点 ' + PACKETS + ' 个包')]);
    fill(resolvedCell, [dim(target.kind === 'host' ? '等待探针解析' : '—')]);
    fill(statusCell, [dim('正在提交')]);
    setProgress('正在向 Globalping 提交测量…');

    /* 地址栏换成可以分享的 /ping#host=…：只预填、不自动测，转发给别人也不会替他消耗额度 */
    rememberTarget(target.value);

    var locations = baseRows.map(function (row) {
      var location = {};
      for (var key in row.filter) location[key] = row.filter[key];
      location.limit = 1;
      return location;
    });

    var options = { packets: PACKETS };
    if (tcp) {
      options.protocol = 'TCP';
      options.port = PORT;
    }

    var body = JSON.stringify({ type: 'ping', target: target.value, locations: locations, measurementOptions: options });

    /* 只带 Content-Type 一个请求头：它已经让这次 POST 成为需要预检的请求（Globalping 本来就为浏览器端调用开放了 CORS），
       再加别的头只会多一个被拒的机会。
       走 P.text 而不是 P.request 再自己读正文：时限要一直管到正文读完——响应头到了、正文卡住时，
       自己调 response.text() 会永远等下去，按钮就一直停在「测量中」 */
    P.text(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body
    }, CREATE_TIMEOUT).then(function (result) {
      var response = result.response;
      return { status: response.status, data: parseJson(result.text), headers: response.headers };
    }).then(function (reply) {
      if (state.token !== token) return;
      var id = reply.data && reply.data.id;
      if (reply.status >= 200 && reply.status < 300 && typeof id === 'string' && /^[A-Za-z0-9_\-]{1,64}$/.test(id)) {
        state.id = id;
        /* 剩余额度只有在 Globalping 通过 Access-Control-Expose-Headers 暴露了这个头时才读得到；读不到就不提 */
        try { state.remaining = parseInt(reply.headers.get('X-RateLimit-Remaining') || '', 10); } catch (e) { state.remaining = NaN; }
        var count = isNum(reply.data.probesCount) ? reply.data.probesCount : baseRows.length;
        setProgress('已分配 ' + count + ' 台探针，正在测量…');
        fill(statusCell, [dim('测量中：0 / ' + count)]);
        window.setTimeout(function () { poll(state); }, Math.min(POLL_MS, 800));
        return;
      }
      if (reply.status >= 200 && reply.status < 300) {
        fail(state, 'Globalping 返回了意外的响应', '创建测量成功，但响应里没有测量 ID。稍后再试。');
        return;
      }
      createFailure(state, reply.status, reply.data, reply.headers);
    }, function (failure) {
      networkFailure(state, failure, '提交测量');
    });
  }

  function poll(state) {
    if (state.token !== token) return;
    state.polls++;

    /* 与创建时同理，用 P.text 让时限覆盖到正文读完：卡住的那一次按超时计入连续失败，下一秒照常重试 */
    P.text(API + '/' + encodeURIComponent(state.id), {}, POLL_TIMEOUT).then(function (result) {
      if (!result.response.ok) return Promise.reject({ kind: 'http', status: result.response.status });
      var data = parseJson(result.text);
      return data && Object.prototype.toString.call(data.results) === '[object Array]'
        ? data
        : Promise.reject({ kind: 'parse' });
    }).then(function (data) {
      if (state.token !== token) return;
      state.fails = 0;
      state.last = data;
      try {
        update(state, data);
      } catch (e) {
        if (window.console && console.error) console.error(e);
        finish(state, true);
        return;
      }
      if (data.status === 'finished') {
        finish(state, false);
      } else if (state.polls >= POLL_MAX) {
        finish(state, true);
      } else {
        window.setTimeout(function () { poll(state); }, POLL_MS);
      }
    }, function (failure) {
      if (state.token !== token) return;
      state.fails++;

      /* 测量过期或 ID 不存在，重试也没用 */
      var gone = failure && failure.kind === 'http' && failure.status === 404;
      if (gone || state.fails >= POLL_FAIL_MAX || state.polls >= POLL_MAX) {
        if (state.last) {
          finish(state, true, '读取进度失败，下面是中断前拿到的部分结果。');
        } else if (gone) {
          fail(state, '测量结果已不存在', 'Globalping 找不到这次测量（可能已过期），请重新开始。');
        } else if (failure && failure.kind === 'http') {
          fail(state, '读取测量结果失败', 'Globalping 返回了 HTTP ' + failure.status + '，稍后重试。');
        } else {
          networkFailure(state, failure, '读取测量结果');
        }
        return;
      }
      window.setTimeout(function () { poll(state); }, POLL_MS);
    });
  }

  function update(state, data) {
    var results = data.results;
    assign(state, results);

    var summary = resolvedSummary(results);
    var done = 0;
    results.forEach(function (item, index) {
      var row = state.map[index];
      if (!row) return;
      renderRow(row, item, summary.list.length > 1 ? summary.primary : '', state.tcp);
      if (row.outcome.kind !== 'running') done++;
    });

    renderResolved(summary);
    fill(statusCell, [dim('测量中：' + done + ' / ' + results.length + ' · '), rawLink(state.id)]);
    if (results.length) setProgress('正在测量：' + done + ' / ' + results.length + ' 个节点已完成…');
  }

  function finish(state, timedOut, note) {
    if (state.token !== token) return;

    var measured = 0;
    rows.forEach(function (row) {
      if (row.index === null) {
        closeRow(row, 'noprobe', '无探针', '这一地区暂无可用探针');
      } else if (!row.outcome || row.outcome.kind === 'running') {
        closeRow(row, 'timeout', timedOut ? '超时' : '未完成');
      } else {
        measured++;
      }
    });

    var elapsed = seconds(P.now() - state.started);
    fill(statusCell, [document.createTextNode(measured + ' / ' + rows.length + ' 个节点完成 · 用时 ' + elapsed + ' · '), rawLink(state.id)]);
    if (state.last && !resolvedSummary(state.last.results).list.length) fill(resolvedCell, [dim('未解析到地址')]);

    summarize(state, timedOut);
    if (note && verdictNote) verdictNote.textContent = note + ' ' + verdictNote.textContent;

    setProgress('测量完成，用时 ' + elapsed + '。可以换个目标或方式再测一次——每轮消耗 ' + baseRows.length + ' 次 Globalping 额度'
      + (isNum(state.remaining) && state.remaining >= 0 ? '，这一小时还剩约 ' + state.remaining + ' 次。' : '。'));
    setRunning(false);
  }

  /* ---------------------------------------------------------------- 绑定 */

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (running) return;

    var target = normalizeTarget(input.value);
    if (!target.ok) {
      showError(target.message);
      input.focus();
      return;
    }

    /* 把归一化之后真正要测的值写回输入框：粘贴的是整条网址时，访客能看到实际测的是哪个主机 */
    input.value = target.value;
    start(target, !!proto && proto.value === 'tcp');
  });

  input.addEventListener('input', function () {
    if (errorBox && !errorBox.hidden) showError('');
  });

  /* 分享链接带来的目标：只填进输入框，绝不自动开始——
     每一轮都会消耗访客自己的 Globalping 额度，必须由他本人点下去。
     页面整页走 public 缓存，所以这一步只能在这里做，不能交给 PHP 渲染进 value。

     目标放在网址片段里（/ping#host=…）：片段不随请求发出，不会进本站的访问日志。
     早期的 /ping?host=… 链接仍然认，但查询串在打开那一刻已经随请求行发给了服务器、记进了日志——
     这一次挽回不了，至少马上把地址栏改写成片段形式，之后的刷新、收藏、转发都不会再把目标带给服务器。 */
  function readPreset() {
    var match = /(?:^#|&)host=([^&]*)/.exec(location.hash || '');
    var legacy = false;
    if (!match) {
      match = /[?&]host=([^&#]*)/.exec(location.search || '');
      legacy = !!match;
    }
    if (!match) return null;
    var value = '';
    try { value = decodeURIComponent(match[1].replace(/\+/g, ' ')).trim().slice(0, 255); } catch (e) { value = ''; }
    return { value: value, legacy: legacy };
  }

  function applyPreset() {
    var preset = readPreset();
    if (!preset) return;
    if (preset.legacy) rememberTarget(preset.value);
    if (!preset.value) return;
    input.value = preset.value;
    showError('');
    setProgress('已填入 ' + preset.value + '，选择探测方式后点「开始」。每轮消耗 ' + baseRows.length + ' 次 Globalping 额度。');
  }

  applyPreset();

  /* 停在本页时在地址栏改了 #host= 再回车，浏览器只换片段、不重新加载页面，只会触发 hashchange。
     测量进行中不动输入框：那一轮测的是什么，以「目标」一栏为准 */
  window.addEventListener('hashchange', function () {
    if (!running) applyPreset();
  });
})();
