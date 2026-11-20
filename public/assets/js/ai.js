/* JudgeIP — AI 解锁检测（/ai）。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   每一行做两件事：
   1. 走 Cloudflare 的服务读一次 /cdn-cgi/trace，拿到「这家服务看到的你」——出口 ip、国家 loc、机房 colo；
   2. 对同一个地址再发三次 no-cors 请求，取中位数当延迟。trace 刚读过一次，连接是热的，
      后面三次测到的接近纯往返；不读 trace 的行第一次带着握手，中位数会把它筛掉。
   不走 Cloudflare 的（Google、DeepSeek）只有第 2 步：看不到出口就显示「看不到」，绝不拿别家的出口去猜。

   判据全部来自页面：各家的地区名单、出口国家的时区区间都由 src/AiServices.php 印进 data-*，
   页面上印着的名单和脚本里比对的永远是同一份。地区中文名用 probe.js 的 P.countryName，与全站各页同一套叫法。
   结果不回传本站；页面上有「检测历史」块时，每轮的出口摘要经 history.js 记进本机 localStorage，方便对比出口有没有变。 */
(function () {
  'use strict';

  var root = document.getElementById('ai');
  if (!root) return;

  /* probe.js 没加载成功（被扩展拦下、网络中断）：这一页是打开即自动检测的，
     什么都不做的话，访客只会看到一排永远「待检测」的格子。说清楚原因，并锁住「重新检测」 */
  if (!window.IpcxProbe) {
    var missingHint = root.querySelector('[data-ai-progress]');
    var missingVerdict = root.querySelector('[data-ai-verdict]');
    var missingTitle = root.querySelector('[data-ai-verdict-title]');
    var missingNotes = root.querySelector('[data-ai-verdict-notes]');
    var missingRun = root.querySelector('[data-ai-run]');
    var missingMessage = '检测脚本加载失败，请刷新页面重试。';
    if (missingVerdict && missingTitle) {
      missingVerdict.className = 'verdict is-bad';
      missingTitle.textContent = missingMessage;
      if (missingNotes) {
        var missingNote = document.createElement('p');
        missingNote.className = 'verdict__note';
        missingNote.textContent = '页面的公共检测脚本没能加载，可能是网络中断，或被浏览器扩展、代理规则拦截了。下面的服务一个都还没有检测。';
        missingNotes.appendChild(missingNote);
      }
      missingVerdict.hidden = false;
      /* 「打开页面即自动开始」已经不成立，进度一栏只说一句「没有开始」，原因留给上面的结论块 */
      if (missingHint) missingHint.textContent = '检测没有开始。';
    } else if (missingHint) {
      missingHint.textContent = missingMessage;
    }
    if (missingRun) missingRun.disabled = true;
    return;
  }

  var P = window.IpcxProbe;

  function num(name, fallback) {
    var value = parseInt(root.getAttribute(name), 10);
    return isNaN(value) || value <= 0 ? fallback : value;
  }

  /* data-* 里的 JSON 由 PHP 生成，理论上不会坏；真坏了也只是少几条判据，页面照样能跑完 */
  function json(name) {
    try {
      return JSON.parse(root.getAttribute(name) || '{}') || {};
    } catch (e) {
      return {};
    }
  }

  var LANES = num('data-lanes', 4);
  var TRACE_TIMEOUT = num('data-trace-timeout', 8000);
  var OPTIONAL_TIMEOUT = num('data-optional-timeout', 5000);
  var TIMING_TIMEOUT = num('data-timing-timeout', 6000);
  var ROUNDS = num('data-rounds', 3);
  var FAST = num('data-fast', 250);
  var SLOW = num('data-slow', 500);

  /* 时区比对的宽限：区间两头再各放 60 分钟，半小时时区、邻国、夏令时切换那几天都不会误报 */
  var TZ_SLACK = 60;

  var iataUrl = root.getAttribute('data-iata') || '';
  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var vendors = json('data-vendors');
  var tzRanges = json('data-tz');

  /* 与 claude.js 同一张表：这几个时区名本身就写着「中国大陆」，偏移再对得上也藏不住 */
  var CN_TIMEZONES = ['Asia/Shanghai', 'Asia/Urumqi', 'Asia/Chongqing', 'Asia/Chungking', 'Asia/Harbin', 'Asia/Kashgar'];

  var runButton = root.querySelector('[data-ai-run]');
  var progress = root.querySelector('[data-ai-progress]');
  var verdict = root.querySelector('[data-ai-verdict]');
  var verdictTitle = root.querySelector('[data-ai-verdict-title]');
  var verdictNotes = root.querySelector('[data-ai-verdict-notes]');
  var sumExit = root.querySelector('[data-ai-sum-exit]');
  var sumSelf = root.querySelector('[data-ai-sum-self]');
  var sumTz = root.querySelector('[data-ai-sum-tz]');
  var sumLang = root.querySelector('[data-ai-sum-lang]');
  var v6Box = root.querySelector('[data-ai-v6]');
  var v6Note = root.querySelector('[data-ai-v6-note]');
  var history = window.JudgeHistory ? window.JudgeHistory.mount(document.querySelector('[data-history]')) : null;

  /* 同一家的网页入口与 API 入口：网页能开、API 不通（或反过来）时单独说一句，Codex / Claude Code 用户最常踩的就是这个 */
  var PAIRS = [
    { web: 'chatgpt', api: 'openai-api', apiUse: 'Codex、OpenAI API' },
    { web: 'claude', api: 'claude-api', apiUse: 'Claude Code、Claude API' }
  ];

  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-ai-row]')).map(function (node) {
    return {
      node: node,
      key: node.getAttribute('data-ai-row') || '',
      name: node.getAttribute('data-name') || node.getAttribute('data-ai-row') || '',
      vendor: node.getAttribute('data-vendor') || '',
      trace: node.getAttribute('data-trace') || '',
      optional: node.getAttribute('data-optional') === '1',
      timing: node.getAttribute('data-timing') || '',
      ipCell: node.querySelector('[data-ai-ip]'),
      coloCell: node.querySelector('[data-ai-colo]'),
      latCell: node.querySelector('[data-ai-lat]'),
      regionCell: node.querySelector('[data-ai-region]'),
      stateCell: node.querySelector('[data-ai-state]')
    };
  });

  if (!rows.length || !runButton) return;

  var running = false;

  /* ---------------------------------------------------------------- 工具 */

  /* 结果格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function dim(text, title) {
    var node = P.el('span', 'dim', text);
    if (title) node.title = title;
    return node;
  }

  function tag(tone, text, title) {
    var node = P.el('span', 'tag tag--' + tone, text);
    if (title) node.title = title;
    return node;
  }

  function vendorOf(row) {
    return vendors[row.vendor] || { name: row.vendor, basis: '', denied: [] };
  }

  function isReference(row) {
    return vendorOf(row).basis === 'reference';
  }

  function locOf(result) {
    return result.exit ? String(result.exit.loc || '').toUpperCase() : '';
  }

  /* 地区叫法交给 probe.js：中国大陆 / 中国香港 / 中国澳门 / 中国台湾是全站统一的短名，其余取 Intl（「日本」）。
     T1 不是国家，是 Cloudflare 给 Tor 出口的代号，Intl 不认识，单独翻译 */
  function nameOf(cc) {
    cc = String(cc || '').toUpperCase();
    if (cc === 'T1') return 'Tor 网络';
    return P.countryName(cc) || cc || '未知地区';
  }

  function countryLabel(cc) {
    var flag = P.flag(cc);
    return flag ? flag + ' ' + nameOf(cc) : nameOf(cc);
  }

  /* 「ChatGPT、Claude、Sora 等 5 项」 */
  function listNames(results, limit) {
    var list = results.map(function (r) { return r.row.name; });
    limit = limit || 3;
    if (list.length <= limit) return list.join('、');
    return list.slice(0, limit).join('、') + ' 等 ' + list.length + ' 项';
  }

  /* 结论标题里的主语：「ChatGPT 的」「ChatGPT 等 4 项服务的」——拉丁名后面留一个空格，与全站中英混排一致 */
  function whose(results) {
    var first = results.length ? results[0].row.name : '';
    return results.length > 1 ? first + ' 等 ' + results.length + ' 项服务的' : first + ' 的';
  }

  function unique(list) {
    var out = [];
    list.forEach(function (v) { if (v && out.indexOf(v) === -1) out.push(v); });
    return out;
  }

  /* 分组并按组大小降序；一样大时保持页面上的先后——「主出口」因此优先落在 ChatGPT / Claude 那一组 */
  function groupBy(results, keyOf) {
    var map = {};
    var order = [];
    results.forEach(function (r) {
      var key = keyOf(r);
      if (!key) return;
      if (!map[key]) {
        map[key] = { key: key, items: [] };
        order.push(map[key]);
      }
      map[key].items.push(r);
    });
    return order.map(function (g, i) { return { g: g, i: i }; }).sort(function (a, b) {
      return b.g.items.length - a.g.items.length || a.i - b.i;
    }).map(function (x) { return x.g; });
  }

  function timezoneName() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (e) {
      return '';
    }
  }

  function localOffset() {
    return -new Date().getTimezoneOffset();
  }

  function offsetText(minutes) {
    var sign = minutes < 0 ? '-' : '+';
    var abs = Math.abs(minutes);
    var h = Math.floor(abs / 60);
    var m = abs % 60;
    return 'UTC' + sign + h + (m ? ':' + (m < 10 ? '0' : '') + m : '');
  }

  function languages() {
    var list = navigator.languages && navigator.languages.length
      ? Array.prototype.slice.call(navigator.languages)
      : [navigator.language || ''];
    return list.filter(Boolean);
  }

  /* 简体中文：zh-CN / zh-SG / zh-Hans，以及没有后缀的 zh */
  function isHans(lang) {
    var l = String(lang || '').toLowerCase();
    return l === 'zh' || l.indexOf('zh-cn') === 0 || l.indexOf('zh-sg') === 0 || l.indexOf('zh-hans') === 0;
  }

  /* ---------------------------------------------------------------- 探测 */

  /* 三次测速，串行：并发发出去会互相抢连接，测出来的是排队时间。
     某一次超时或被 CSP 拦下就不再试——再试也是同样的结果，只会让这一行多挂十几秒。 */
  function timings(url) {
    var list = [];
    var lastKind = '';
    var round = 0;

    function next() {
      if (round >= ROUNDS) return Promise.resolve({ list: list, kind: lastKind });
      round += 1;
      return P.timing(url, {}, TIMING_TIMEOUT).then(function (t) {
        if (t.ok) {
          list.push(t.ms);
        } else {
          lastKind = t.kind || 'error';
          if (t.kind === 'timeout' || t.kind === 'csp') round = ROUNDS;
        }
        return next();
      });
    }

    return next();
  }

  /* 一行的完整探测。永不 reject：结果里 reachable / exit / ms / kind 说明一切 */
  function probe(row) {
    var result = { row: row, exit: null, traceMs: null, traceKind: '', reachable: false, ms: null, kind: '' };

    var step = row.trace
      ? P.trace(row.trace, row.optional ? OPTIONAL_TIMEOUT : TRACE_TIMEOUT).then(function (r) {
          result.exit = r.data;
          result.traceMs = r.ms;
          result.reachable = true;
        }, function (failure) {
          result.traceKind = (failure && failure.kind) || 'error';
        })
      : Promise.resolve();

    return step.then(function () {
      /* trace 超时或被 CSP 拦下，同一个域名的测速只会是同样的下场，直接判不可达。
         读到了却不是 trace（被劫持成一张 HTML、对方没开放这个路径），才值得再测一次「到底通不通」。 */
      if (!result.reachable && (result.traceKind === 'timeout' || result.traceKind === 'csp')) {
        result.kind = result.traceKind;
        return result;
      }

      return timings(row.timing).then(function (t) {
        if (t.list.length) {
          result.reachable = true;
          result.ms = P.median(t.list);
        } else if (result.traceMs !== null) {
          /* trace 读到了、测速却全部失败（极少见）：退而用 trace 那一次的耗时，它至少是真实的一次往返 */
          result.ms = result.traceMs;
        }
        if (!result.reachable) result.kind = t.kind || result.traceKind || 'error';
        return result;
      });
    }).catch(function () {
      result.kind = result.kind || 'error';
      return result;
    });
  }

  /* ---------------------------------------------------------------- 判定 */

  /* 地区判定。level：bad 官方名单外 / warn 可能受限 / ok 支持 / unknown 看不到出口 / ref 国内参照 / none 不可达 */
  function regionOf(result) {
    var row = result.row;
    var vendor = vendorOf(row);

    if (vendor.basis === 'reference') {
      return { level: 'ref', node: tag('muted', '国内参照', '国内服务，作为网络本身是否通畅的对照，不做地区判断') };
    }

    if (!result.exit) {
      if (!result.reachable) return { level: 'none', node: dim('—') };
      return {
        level: 'unknown',
        node: tag('muted', '未知', row.trace
          ? '读不到这一行的出口，无法判断地区'
          : '这一家不经过 Cloudflare，网页读不到它看到的出口，无法判断地区')
      };
    }

    var loc = locOf(result);

    if (loc === 'T1') {
      return { level: 'warn', node: tag('warn', 'Tor 出口', 'Cloudflare 把这个出口识别为 Tor 网络，多数 AI 服务会直接拦截或要求验证') };
    }

    if (!/^[A-Z]{2}$/.test(loc) || loc === 'XX') {
      return { level: 'unknown', node: tag('muted', '未知', 'Cloudflare 没有给出这个出口的国家') };
    }

    var denied = (vendor.denied || []).indexOf(loc) !== -1;

    if (denied && vendor.basis === 'official') {
      return { level: 'bad', node: tag('leak', '不支持', nameOf(loc) + '不在 ' + vendor.name + ' 的官方支持地区名单上') };
    }

    if (denied) {
      return { level: 'warn', node: tag('warn', '可能受限', vendor.name + ' 未公布逐国名单；' + nameOf(loc) + '属于常见的受限地区') };
    }

    if (vendor.basis === 'official') {
      return { level: 'ok', node: tag('ok', '支持', nameOf(loc) + '在 ' + vendor.name + ' 的官方支持地区名单上') };
    }

    return { level: 'ok', node: tag('ok', '未见受限', vendor.name + ' 未公布逐国名单；' + nameOf(loc) + '不在常见的受限地区里') };
  }

  /* 浏览器时区 vs 出口国家。level：mismatch 明显对不上 / ok 对得上 / unknown 表里没有这个国家 / none 没有出口可比 */
  function tzCheck(loc) {
    var off = localOffset();
    if (!loc) return { level: 'none', off: off };
    var range = tzRanges[loc];
    if (!range || range.length < 2) return { level: 'unknown', off: off };
    if (off < range[0] - TZ_SLACK || off > range[1] + TZ_SLACK) return { level: 'mismatch', off: off };
    return { level: 'ok', off: off };
  }

  /* ---------------------------------------------------------------- 渲染：单行 */

  function renderIp(result) {
    var row = result.row;

    if (result.exit) {
      var ip = String(result.exit.ip || '');
      var loc = locOf(result);
      var addr = P.el('span', 'mono airow__addr', P.compactIp(ip));
      addr.title = ip;
      var nodes = [addr];
      if (P.isIPv6(ip)) nodes.push(P.el('span', 'airow__fam', 'IPv6'));
      nodes.push(P.el('span', 'airow__where', loc ? countryLabel(loc) : '国家未知'));
      fill(row.ipCell, nodes);
      return;
    }

    if (!result.reachable) {
      fill(row.ipCell, [dim('—')]);
    } else if (!row.trace) {
      fill(row.ipCell, [dim('看不到出口', '这一家不经过 Cloudflare，网页读不到它看到的出口；本页不会拿别家的出口去猜')]);
    } else if (row.optional) {
      fill(row.ipCell, [dim('未开放 trace', '这个域名没有回 Cloudflare trace，只测了可达性与延迟')]);
    } else {
      fill(row.ipCell, [dim('读不到', '能连上，但 trace 没能读出来：可能被浏览器扩展、企业网关或代理的证书替换拦下了')]);
    }
  }

  function renderColo(result, colos) {
    var row = result.row;
    if (!result.exit || !result.exit.colo) {
      fill(row.coloCell, [dim('—')]);
      return;
    }

    var c = P.colo(colos, result.exit.colo);
    var wrap = P.el('span', 'aicolo');
    wrap.appendChild(P.el('span', 'aicolo__city', c.city));
    /* 认不出的代码 city 就是代码本身，不必再重复一遍 */
    if (c.known) wrap.appendChild(P.el('span', 'aicolo__code mono', c.code));
    wrap.title = c.cityEn ? c.cityEn + ' · ' + c.code : c.code;
    fill(row.coloCell, [wrap]);
  }

  function renderLatency(result) {
    var row = result.row;
    if (result.ms === null) {
      fill(row.latCell, [dim('—')]);
      return;
    }
    var band = result.ms < FAST ? 'fast' : result.ms < SLOW ? 'mid' : 'slow';
    var node = P.el('span', 'ailat ailat--' + band + ' mono', result.ms + ' ms');
    node.title = band === 'fast' ? '快' : band === 'mid' ? '一般' : '慢';
    fill(row.latCell, [node]);
  }

  function renderState(result) {
    var row = result.row;
    if (result.reachable) {
      fill(row.stateCell, [tag('ok', '可访问')]);
    } else {
      fill(row.stateCell, [tag('leak', '不可访问'), P.el('span', 'airow__why', P.failureText(result.kind))]);
    }
  }

  function renderRow(result, colos) {
    result.region = regionOf(result);
    renderIp(result);
    renderColo(result, colos);
    renderLatency(result);
    fill(result.row.regionCell, [result.region.node]);
    renderState(result);
    /* 两个状态类只给窄屏用：不可达 / 没有出口的行，把空着的格子收起来，不在手机上摆两行破折号 */
    result.row.node.classList.remove('is-active');
    result.row.node.classList[result.reachable ? 'remove' : 'add']('is-down');
    result.row.node.classList[result.exit ? 'remove' : 'add']('is-noexit');
  }

  /* ---------------------------------------------------------------- 渲染：汇总 */

  /* 一个出口（IPv6 按 /64 归并）里出现过的不同地址 */
  function addressesOf(group) {
    var seen = {};
    return group.items.map(function (r) { return r.exit.ip; }).filter(function (ip) {
      var key = P.ipKey(ip);
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    });
  }

  function renderExits(byExit) {
    if (!byExit.length) {
      fill(sumExit, [dim('没有读到任何出口')]);
      return;
    }

    fill(sumExit, byExit.map(function (g) {
      var ips = addressesOf(g);
      var loc = locOf(g.items[0]);
      var line = P.el('span', 'aiexit');
      var flag = P.flag(loc);
      if (flag) line.appendChild(P.el('span', 'aiexit__flag', flag));
      var addr = P.el('span', 'mono aiexit__ip', P.compactIp(ips[0]) + (ips.length > 1 ? ' 等 ' + ips.length + ' 个地址（同一 /64）' : ''));
      addr.title = ips.join('\n');
      line.appendChild(addr);
      line.appendChild(P.el('span', 'aiexit__who', nameOf(loc) + ' · ' + listNames(g.items, 3)));
      return line;
    }));
  }

  /* 本站看到的地址 vs AI 服务看到的出口：只在同一协议族里比，IPv4 与 IPv6 本来就不可能相同 */
  function renderSelf(byExit) {
    if (!sumSelf) return;
    if (!visibleIp || !byExit.length) {
      fill(sumSelf, []);
      return;
    }

    var v6 = P.isIPv6(visibleIp);
    var peers = byExit.filter(function (g) { return P.isIPv6(g.items[0].exit.ip) === v6; });

    if (!peers.length) {
      fill(sumSelf, [tag('muted', '协议族不同', '本站看到的是 ' + (v6 ? 'IPv6' : 'IPv4') + '，AI 服务看到的都是 ' + (v6 ? 'IPv4' : 'IPv6') + '，无法直接比较')]);
      return;
    }

    /* IPv6 按 /64 比：隐私地址会换后 64 位，同一条线路上本站和 AI 服务看到的完整地址可能不一样 */
    var match = peers.filter(function (g) { return g.key === P.exitKey(visibleIp); });

    if (match.length && peers.length === 1) {
      fill(sumSelf, [tag('name', '与 AI 出口相同', 'AI 服务和本站看到的是同一个出口：AI 流量与普通网页走的是同一条线路')]);
    } else if (match.length) {
      fill(sumSelf, [tag('name', '与部分 AI 出口相同', listNames(match[0].items, 3) + ' 与本站看到的是同一个出口，其余 AI 服务走了别的出口')]);
    } else {
      fill(sumSelf, [tag('global', 'AI 走了另一个出口', 'AI 服务看到的出口与本站看到的不同：代理把 AI 流量分到了单独的出口，这本身不是问题')]);
    }
  }

  function renderTz(tzName, check, dominant) {
    var nodes = [P.el('span', 'mono', tzName || '未知'), P.el('span', 'dim', '（' + offsetText(check.off) + '）')];

    if (check.level === 'mismatch') {
      nodes.push(tag('warn', '时区与出口不一致', '出口在' + nameOf(dominant) + '，浏览器时区与当地相差超过一小时'));
    } else if (check.level === 'ok') {
      nodes.push(tag('ok', '与出口相符', '与出口所在的' + nameOf(dominant) + '时区相符'));
    } else if (check.level === 'unknown') {
      nodes.push(tag('muted', '无法比较', '对照表里没有' + nameOf(dominant) + '，不做判断'));
    } else {
      nodes.push(tag('muted', '无法比较', '没有读到 AI 服务的出口'));
    }

    if (check.level !== 'mismatch' && dominant && dominant !== 'CN' && CN_TIMEZONES.indexOf(tzName) !== -1) {
      nodes.push(tag('warn', '中国大陆时区', '时区名本身就写着中国大陆；据公开分析，Claude Code 会读取这一项'));
    }

    fill(sumTz, nodes);
  }

  function renderLang(langs, dominant) {
    var nodes = [P.el('span', 'mono', langs.slice(0, 3).join(', ') || '未知')];
    if (dominant && langs.length && isHans(langs[0]) && dominant !== 'CN' && dominant !== 'SG') {
      nodes.push(tag('muted', '与出口所在地不同 · 仅供参考',
        '首选语言是简体中文，出口在' + nameOf(dominant) + '。海外华人同样如此，单看这一项说明不了什么，但它会和时区、字体一起构成中文环境画像'));
    } else {
      nodes.push(tag('muted', '仅供参考', '语言只作参考，不参与结论'));
    }
    fill(sumLang, nodes);
  }

  function showVerdict(tone, title, notes) {
    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    fill(verdictNotes, notes.map(function (text) { return P.el('p', 'verdict__note', text); }));
  }

  /* 走 IPv6 访问 AI 服务时的提醒：IPv6 地址的地理库普遍不如 IPv4 准，代理的 IPv6 出口又多是整段机房地址 */
  function renderV6(traced) {
    if (!v6Box) return;
    var v6 = traced.filter(function (r) { return !isReference(r.row) && P.isIPv6(r.exit.ip); });
    v6Box.hidden = !v6.length;
    if (!v6.length || !v6Note) return;
    v6Note.textContent = listNames(v6, 4) + ' 看到的是 IPv6 出口（' + P.compactIp(v6[0].exit.ip) + '）。'
      + 'IPv6 地址的地理库数据普遍不如 IPv4 准，代理的 IPv6 出口又常是整段机房地址，更容易被判为数据中心；'
      + '双栈网络下同一台设备还可能在 IPv4 与 IPv6 之间来回切换，出口随之变化。建议在代理里对这些域名关闭 IPv6，或让系统优先使用 IPv4，'
      + '改完回到本页重测。';
  }

  var TONE_LABEL = {
    'is-good': { tone: 'ok', label: '正常' },
    'is-warn': { tone: 'warn', label: '需注意' },
    'is-bad': { tone: 'leak', label: '有问题' }
  };

  /* 历史里一条只记出口摘要：地址、国家与结论档位，不记延迟这类每次都会抖的数 */
  function remember(tone, traced, byExit) {
    if (!history) return;
    var t = TONE_LABEL[tone] || TONE_LABEL['is-warn'];
    if (!traced.length) {
      history.add({ main: '没有读到出口', tone: t.tone, label: t.label, note: verdictTitle.textContent });
      return;
    }
    var main = byExit.slice(0, 2).map(function (g) { return P.compactIp(g.items[0].exit.ip); }).join(' / ')
      + (byExit.length > 2 ? ' 等 ' + byExit.length + ' 个' : '');
    history.add({
      main: main,
      key: byExit.map(function (g) { return g.key; }).sort().join(','),
      tone: t.tone,
      label: t.label,
      note: byExit.map(function (g) { return countryLabel(locOf(g.items[0])); }).filter(function (v, i, a) { return a.indexOf(v) === i; }).join('、')
        + ' · ' + verdictTitle.textContent
    });
  }

  function finalize(results) {
    var foreign = results.filter(function (r) { return !isReference(r.row); });
    var refs = results.filter(function (r) { return isReference(r.row); });
    var reachable = foreign.filter(function (r) { return r.reachable; });
    var down = foreign.filter(function (r) { return !r.reachable; });
    var traced = foreign.filter(function (r) { return !!r.exit; });
    var bad = traced.filter(function (r) { return r.region.level === 'bad'; });
    var risky = traced.filter(function (r) { return r.region.level === 'warn'; });

    var byCountry = groupBy(traced, locOf);
    var byExit = groupBy(traced, function (r) { return P.exitKey(r.exit.ip); });
    var dominant = byCountry.length ? byCountry[0].key : '';

    var tzName = timezoneName();
    var tz = tzCheck(dominant);
    var langs = languages();

    renderExits(byExit);
    renderSelf(byExit);
    renderTz(tzName, tz, dominant);
    renderLang(langs, dominant);

    var tone;
    var title;
    var primary = '';
    var notes = [];
    var refUp = refs.some(function (r) { return r.reachable; });

    if (!reachable.length) {
      tone = 'is-bad';
      title = '海外 AI 服务全部无法访问';
      notes.push(refUp
        ? '国内参照 DeepSeek 可以访问，说明网络本身是通的：这些域名被拦截了，或者代理没有接管它们。确认代理已开启、规则里覆盖了 AI 相关的域名，再回到本页重测。'
        : '连国内参照 DeepSeek 也没有连上，请先确认网络连接正常，再回到本页重测。');
    } else if (bad.length) {
      var badPlaces = unique(bad.map(locOf)).map(nameOf).join('、');
      var badVendors = unique(bad.map(function (r) { return vendorOf(r.row).name; })).join('、');
      tone = 'is-bad';
      title = whose(bad) + '出口位于' + badPlaces + '，不在官方支持地区';
      notes.push(badVendors + ' 不向' + badPlaces + '提供服务。用这样的出口注册或登录，常见的结果是反复要求验证、付款失败，严重时账号被停用——'
        + '建议先把这些域名分流到支持地区的节点，再回到本页重测。名单以下方链接的官方页面为准。');
    } else if (!traced.length) {
      tone = 'is-warn';
      title = '服务能访问，但没读到它们看到的出口';
      notes.push(reachable.length + ' 个海外入口可以访问，但没有一个读出了 trace——浏览器扩展、企业网关或代理的证书替换都可能拦下这类请求。'
        + '看不到出口，地区也就无从判断。');
    } else if (byCountry.length > 1) {
      tone = 'is-warn';
      title = 'AI 服务走了 ' + byCountry.length + ' 个国家的出口';
    } else if (risky.length) {
      tone = 'is-warn';
      primary = 'risky';
      title = whose(risky) + '出口位于' + unique(risky.map(locOf)).map(nameOf).join('、') + '，可能受限';
      notes.push(listNames(risky, 4) + ' 没有公布逐国支持名单，这里按常见的受限地区（制裁地区与中国大陆）推断，仅作提示。');
    } else if (tz.level === 'mismatch') {
      tone = 'is-warn';
      title = 'AI 出口一致，但浏览器时区与出口所在地对不上';
    } else {
      var allOfficial = traced.every(function (r) { return vendorOf(r.row).basis !== 'official' || r.region.level === 'ok'; });
      tone = 'is-good';
      title = 'AI 服务出口一致，位于' + nameOf(dominant) + (allOfficial ? '，在官方支持地区内' : '');
      notes.push(reachable.length + ' 个海外入口可以访问，' + traced.length + ' 个读到了出口，全部来自 ' + countryLabel(dominant)
        + (byExit.length === 1 ? '的同一个出口。' : '的 ' + byExit.length + ' 个出口。'));
    }

    /* 网页与 API 只坏一半，是最该先改的一条，紧跟主结论 */
    var byKey = {};
    results.forEach(function (r) { byKey[r.row.key] = r; });
    PAIRS.forEach(function (pair) {
      var web = byKey[pair.web];
      var api = byKey[pair.api];
      if (!web || !api) return;
      var webHost = web.row.trace || web.row.name;
      var apiHost = api.row.trace || api.row.name;
      if (web.reachable && !api.reachable) {
        notes.push(webHost + ' 能打开，但 ' + apiHost + ' 连不上：网页版正常，' + pair.apiUse + ' 会请求失败。把 ' + apiHost + ' 加进与 ' + webHost + ' 相同的代理规则。');
      } else if (!web.reachable && api.reachable) {
        notes.push(apiHost + ' 能连上，但 ' + webHost + ' 打不开：' + pair.apiUse + ' 可用，网页版与网页登录不可用。');
      } else if (web.exit && api.exit && locOf(web) !== locOf(api)) {
        notes.push(webHost + ' 的出口在' + nameOf(locOf(web)) + '，' + apiHost + ' 的出口在' + nameOf(locOf(api)) + '：同一个账号的网页与 ' + pair.apiUse + ' 请求来自两个国家。');
      }
    });

    /* ---- 以下几条与主结论叠加：结论只说最要紧的一件事，其余的破绽逐条列出 */

    /* 同一家的几个入口分在不同国家，比不同服务之间不一致更要紧——同一个账号的请求在两国之间来回切换 */
    if (byCountry.length > 1) {
      var split = [];
      ['openai', 'anthropic'].forEach(function (key) {
        var mine = traced.filter(function (r) { return r.row.vendor === key; });
        var places = unique(mine.map(locOf));
        if (places.length > 1) split.push((vendors[key] ? vendors[key].name : key) + ' 自家的几个入口分在了' + places.map(nameOf).join('、'));
      });
      notes.push(byCountry.map(function (g) { return countryLabel(g.key) + '：' + listNames(g.items, 4); }).join('；') + '。');
      notes.push((split.length ? split.join('；') + '。' : '')
        + '不同服务之间出口不同问题不大；同一家的网页版与 API 出口不一致，同一个账号的请求就会在两个国家之间来回切换，这是风控最常见的触发条件之一。'
        + '把同一家的域名放进同一条规则、指向同一个节点。');
    } else if (traced.length && byExit.length > 1) {
      notes.push('出口都在' + nameOf(dominant) + '，但出现了 ' + byExit.length + ' 个不同的出口 IP：多节点负载均衡常常如此；同一个会话中途换 IP 可能触发重新验证。');
    }

    /* 「可能受限」在别的结论盖过它时也要单独说一句，否则只在出口分布里露个国名，容易看漏 */
    if (risky.length && primary !== 'risky') {
      notes.push(whose(risky) + '出口位于' + unique(risky.map(locOf)).map(nameOf).join('、')
        + '，可能受限：' + (risky.length > 1 ? '这几家' : '这一家') + '没有公布逐国支持名单，按常见的受限地区推断，仅作提示。');
    }

    var families = unique(traced.map(function (r) { return P.isIPv6(r.exit.ip) ? 'v6' : 'v4'; }));
    if (families.length > 1) {
      notes.push('同时出现了 IPv4 与 IPv6 出口：双栈网络下不同网站可能走不同的协议族，本页按国家比较，不按 IP。');
    }

    if (down.length && reachable.length) {
      notes.push('无法访问：' + listNames(down, 4) + '（' + unique(down.map(function (r) { return P.failureText(r.kind); })).join('、') + '）。'
        + (down.some(function (r) { return r.kind === 'csp'; })
          ? '标着「CSP 未放行」的是本站配置的问题，与你的网络无关；其余的'
          : '')
        + '多半是这几个域名没有被代理规则覆盖，也可能是对方暂时故障，可以到「服务状态」页确认。');
    }

    if (tz.level === 'mismatch') {
      notes.push('浏览器时区是 ' + (tzName || '未知') + '（' + offsetText(tz.off) + '），出口却在' + nameOf(dominant) + '。'
        + '网页和客户端都读得到系统时区，「IP 在一处、时区在另一处」是识别代理成本最低的线索；把系统时区改成出口所在地，或换一个与时区相符的出口。');
    } else if (dominant && dominant !== 'CN' && CN_TIMEZONES.indexOf(tzName) !== -1) {
      notes.push('系统时区是中国大陆的 ' + tzName + '：偏移和出口所在地对得上，但时区名本身就会暴露地区——据公开分析，Claude Code 会读取这一项。'
        + '完整的浏览器环境检查见「Claude 检测」。');
    }

    renderV6(traced);
    showVerdict(tone, title, notes);
    remember(tone, traced, byExit);

    progress.textContent = '检测完成：' + results.length + ' 个入口，可访问 ' + results.filter(function (r) { return r.reachable; }).length
      + ' 个，读到出口 ' + results.filter(function (r) { return !!r.exit; }).length + ' 个。';
  }

  /* ---------------------------------------------------------------- 主流程 */

  function reset() {
    verdict.hidden = true;
    if (v6Box) v6Box.hidden = true;
    rows.forEach(function (row) {
      row.node.classList.remove('is-active', 'is-down', 'is-noexit');
      fill(row.ipCell, [dim('等待中')]);
      fill(row.coloCell, [dim('—')]);
      fill(row.latCell, [dim('—')]);
      fill(row.regionCell, [dim('—')]);
      fill(row.stateCell, [dim('排队中')]);
    });
    fill(sumExit, [dim('检测中…')]);
    if (sumSelf) fill(sumSelf, []);

    /* 时区与语言是本地的，马上就能填；和出口的比对要等结果出齐 */
    var tzName = timezoneName();
    fill(sumTz, [P.el('span', 'mono', tzName || '未知'), P.el('span', 'dim', '（' + offsetText(localOffset()) + '）')]);
    fill(sumLang, [P.el('span', 'mono', languages().slice(0, 3).join(', ') || '未知')]);
  }

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    runButton.textContent = '检测中…';
    reset();
    progress.textContent = '正在检测：已完成 0 / ' + rows.length + ' 个入口…';

    var colos = P.iata(iataUrl);
    var queue = P.queue(LANES);
    var done = 0;

    var jobs = rows.map(function (row) {
      return queue.add(function () {
        row.node.classList.add('is-active');
        fill(row.stateCell, [dim('检测中…')]);
        return probe(row);
      }).then(function (result) {
        return colos.then(function (map) {
          renderRow(result, map);
          done += 1;
          progress.textContent = '正在检测：已完成 ' + done + ' / ' + rows.length + ' 个入口…';
          return result;
        });
      });
    });

    Promise.all(jobs).then(finalize).catch(function () {
      /* 走到这里是脚本自己的 bug，不是网络问题——至少别让页面停在「检测中」 */
      showVerdict('is-warn', '检测没有正常完成', ['页面脚本出错，请刷新后重试。']);
      progress.textContent = '检测中断。';
    }).then(function () {
      running = false;
      runButton.disabled = false;
      runButton.textContent = '重新检测';
    });
  }

  runButton.addEventListener('click', run);
  run();
})();
