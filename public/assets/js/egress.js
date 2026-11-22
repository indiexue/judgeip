/* JudgeIP — 我的出口（/egress）。

   同一台设备，不同通道看到的出口可以不一样：国内网站、国外网站、仅 IPv4、仅 IPv6、WebRTC、DNS、
   Claude、ChatGPT。这个脚本让每个通道各报一次「我看到你从哪个 IP 来」，再把结果放进一张表里比。

   比较的基准是国外出口（x.com 看到的地址，读不到时用 cloudflare.com 的）。
   其余通道和它是同一个 IP、同一个 /64 或同一个 ASN，算一致；
   和国内出口是同一个网络，算走了国内；两边都不是，算另一个出口。

   回显请求由浏览器直接发给各服务，读到的 IP 只发给本站的 /api/ipinfo 查归属与评分。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };
  var lp = function (p) { return window.I18N ? window.I18N.path(p) : p; };

  var root = document.getElementById('egress');
  if (!root) return;

  var runButton = root.querySelector('[data-eg-run]');
  var progress = root.querySelector('[data-eg-progress]');
  var verdict = root.querySelector('[data-eg-verdict]');
  var verdictTitle = root.querySelector('[data-eg-verdict-title]');
  var verdictNote = root.querySelector('[data-eg-verdict-note]');
  var tbody = root.querySelector('[data-eg-body]');

  if (!window.IpcxProbe || !window.fetch || !window.Promise) {
    if (progress) progress.textContent = T('检测脚本加载失败，请刷新页面重试。', 'Failed to load the check script. Reload the page and try again.');
    if (runButton) runButton.disabled = true;
    return;
  }

  if (!tbody || !runButton) return;

  var P = window.IpcxProbe;
  var ECHO_TIMEOUT = 5000;
  var TRACE_TIMEOUT = 6000;
  var STUN_TIMEOUT = 3500;
  var DNS_TIMEOUT = 5000;
  var DNS_PROBES = 4;
  var MAX_ENTRIES = 4;
  var LOOKUP_LANES = 3;
  var STUN_SERVERS = ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'];

  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var lang = window.I18N ? window.I18N.lang : 'zh';

  /* 通道的名称和说明由页面渲染在每行的 <th> 里，这里原样留着，重画表格时克隆回去 */
  var channels = Array.prototype.slice.call(tbody.querySelectorAll('[data-eg-channel]')).map(function (node) {
    return {
      key: node.getAttribute('data-eg-channel') || '',
      name: node.getAttribute('data-eg-name') || '',
      head: node.querySelector('th')
    };
  }).filter(function (channel) { return channel.key && channel.head; });

  var state = {};
  /* 同一个出口只查一次 /api/ipinfo，按 exitKey 记住；重新检测时沿用 */
  var infos = {};
  var lookups = P.queue(LOOKUP_LANES);
  var running = false;

  function tag(tone, text, title) {
    var node = P.el('span', 'tag tag--' + tone, text);
    if (title) node.title = title;
    return node;
  }

  function cell(nodes, className) {
    var td = document.createElement('td');
    if (className) td.className = className;
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) td.appendChild(nodes[i]);
    }
    return td;
  }

  function dim(text) {
    return P.el('span', 'dim', text);
  }

  /* ---------------------------------------------------------------- 探测 */

  /* 几个来源同时问，先答上来的算数；全部失败才算失败 */
  function first(tasks) {
    return new Promise(function (resolve, reject) {
      var left = tasks.length;
      tasks.forEach(function (task) {
        task().then(resolve, function (failure) {
          left--;
          if (left === 0) reject(failure);
        });
      });
    });
  }

  function plain(text) {
    return String(text || '').trim();
  }

  function echo(url, source, parse) {
    return function () {
      return P.text(url, {}, ECHO_TIMEOUT).then(function (result) {
        var ip = '';
        try { ip = result.response.ok ? parse(result.text) : ''; } catch (e) { ip = ''; }
        if (!P.ipKey(ip)) return Promise.reject({ kind: 'error' });
        return { ip: ip, loc: '', sources: [source] };
      });
    };
  }

  function jsonField(pick) {
    return function (text) {
      return plain(pick(JSON.parse(text)));
    };
  }

  function trace(host) {
    return function () {
      return P.trace(host, TRACE_TIMEOUT).then(function (result) {
        return { ip: result.data.ip, loc: String(result.data.loc || '').toUpperCase(), sources: [host] };
      });
    };
  }

  /* 永不 reject：失败的来源给 {failed, kind} */
  function settle(task) {
    return task().then(function (entry) { return entry; }, function (failure) {
      return { failed: true, kind: failure && failure.kind };
    });
  }

  function merge(entries) {
    var seen = {};
    var out = [];
    entries.forEach(function (entry) {
      var key = P.exitKey(entry.ip);
      if (!key) return;
      if (seen[key]) {
        entry.sources.forEach(function (source) {
          if (seen[key].sources.indexOf(source) === -1) seen[key].sources.push(source);
        });
        return;
      }
      seen[key] = { ip: entry.ip, loc: entry.loc || '', sources: entry.sources.slice() };
      out.push(seen[key]);
    });
    return out.slice(0, MAX_ENTRIES);
  }

  var PROBES = {
    cn: function () {
      return first([
        echo('https://myip.ipip.net/json', 'ipip.net', jsonField(function (data) { return data.data.ip; })),
        echo('https://pubstatic.b0.upaiyun.com/?_upnode', T('又拍云', 'Upyun'), jsonField(function (data) { return data.remote_addr; })),
        echo('https://ipv4.ddnspod.com/', 'DNSPod', plain)
      ]).then(function (entry) { return [entry]; });
    },

    /* x.com 在国内被屏蔽，有代理时一定走代理；cloudflare.com 没被屏蔽，代表「普通国外网站」。
       两个都问，地址不同就各占一行。都读不到再问 ipify。 */
    intl: function () {
      return Promise.all([settle(trace('x.com')), settle(trace('www.cloudflare.com'))]).then(function (results) {
        var ok = results.filter(function (r) { return !r.failed; });
        if (ok.length) return merge(ok);
        return echo('https://api.ipify.org?format=json', 'ipify', jsonField(function (data) { return data.ip; }))().then(function (entry) {
          return [entry];
        }, function () {
          return Promise.reject(results[0]);
        });
      });
    },

    v4: function () {
      return first([
        echo('https://ipv4.icanhazip.com/', 'icanhazip', plain),
        echo('https://v4.ident.me/', 'ident.me', plain),
        echo('https://checkip.amazonaws.com/', 'AWS', plain)
      ]).then(function (entry) { return [entry]; });
    },

    v6: function () {
      return first([
        echo('https://api6.ipify.org?format=json', 'ipify', jsonField(function (data) { return data.ip; })),
        echo('https://ipv6.icanhazip.com/', 'icanhazip', plain)
      ]).then(function (entry) { return [entry]; }, function () {
        /* 没有 IPv6 是常态，不是故障 */
        return [];
      });
    },

    webrtc: function () {
      var PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
      if (!PeerConnection) return Promise.reject({ kind: 'unsupported' });
      return Promise.all(STUN_SERVERS.map(function (url) { return stun(PeerConnection, url); })).then(function (lists) {
        var entries = [];
        lists.forEach(function (list) {
          list.forEach(function (ip) { entries.push({ ip: ip, loc: '', sources: ['STUN'] }); });
        });
        return merge(entries);
      });
    },

    dns: function () {
      var jobs = [];
      for (var i = 0; i < DNS_PROBES; i++) jobs.push(resolver());
      return Promise.all(jobs).then(function (hits) {
        var entries = hits.filter(Boolean).map(function (ip) {
          return { ip: ip, loc: '', sources: ['edns.ip-api.com'] };
        });
        if (!entries.length) return Promise.reject({ kind: 'error' });
        return merge(entries);
      });
    },

    claude: function () {
      return trace('claude.ai')().then(function (entry) { return [entry]; });
    },

    chatgpt: function () {
      return trace('chatgpt.com')().then(function (entry) { return [entry]; });
    }
  };

  function isPublic(ip) {
    if (!P.ipKey(ip)) return false;
    if (P.isIPv6(ip)) return !/^(fe[89ab]|f[cd]|::1$|::$)/i.test(ip);
    var p = ip.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return false;
    if (p[0] === 192 && p[1] === 168) return false;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
    if (p[0] === 169 && p[1] === 254) return false;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false;
    return true;
  }

  /* 每台 STUN 服务器单独建一个连接（见 webrtc.js）。resolve 这台服务器让浏览器交出的公网地址，永不 reject。
     host 候选一般是内网地址或 mDNS 名字，但公网 IPv6 会原样出现在这里，一并算上。 */
  function stun(PeerConnection, url) {
    return new Promise(function (resolve) {
      var found = [];
      var settled = false;
      var pc;
      var timer;

      function finish() {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        try { pc.close(); } catch (e) { /* 已经关了就算了 */ }
        resolve(found);
      }

      try {
        pc = new PeerConnection({ iceServers: [{ urls: url }] });
      } catch (e) {
        resolve(found);
        return;
      }

      timer = window.setTimeout(finish, STUN_TIMEOUT);

      pc.onicecandidate = function (event) {
        if (!event.candidate || !event.candidate.candidate) {
          finish();
          return;
        }
        var address = event.candidate.address || '';
        var type = event.candidate.type || '';
        if (!address || !type) {
          var parts = event.candidate.candidate.split(' ');
          if (parts.length >= 8) {
            if (!address) address = parts[4];
            if (!type) type = parts[7];
          }
        }
        if (type === 'relay' || !isPublic(address)) return;
        if (found.indexOf(address) === -1) found.push(address);
      };

      pc.onicegatheringstatechange = function () {
        if (pc.iceGatheringState === 'complete') finish();
      };

      try {
        pc.createDataChannel('ipcx-probe');
      } catch (e) {
        finish();
        return;
      }

      pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); }).catch(finish);
    });
  }

  function randomSubdomain() {
    var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var out = '';
    var i;
    if (window.crypto && window.crypto.getRandomValues) {
      var bytes = new Uint8Array(32);
      window.crypto.getRandomValues(bytes);
      for (i = 0; i < 32; i++) out += chars.charAt(bytes[i] % chars.length);
      return out;
    }
    for (i = 0; i < 32; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
  }

  /* 随机子域名逼着解析器回源，权威服务器记下来问它的解析器地址（做法同 dnsleak.js）。resolve 地址或 null。 */
  function resolver() {
    var sub = randomSubdomain();
    return P.request('https://' + sub + '.edns.ip-api.com/json', {}, DNS_TIMEOUT).then(function (result) {
      if (result.response.ok) return result.response;
      return P.request('https://edns.ip-api.com/json?t=' + sub, {}, DNS_TIMEOUT).then(function (retry) { return retry.response; });
    }).then(function (response) {
      return response.ok ? response.json() : null;
    }).then(function (data) {
      var ip = data && data.dns && data.dns.ip ? plain(data.dns.ip) : '';
      return P.ipKey(ip) ? ip : null;
    }, function () {
      return null;
    });
  }

  /* ---------------------------------------------------------------- 归属与评分 */

  /* resolve 永不 reject；查不到时 infos[key].data 为 null */
  function lookup(ip) {
    var key = P.exitKey(ip);
    if (!key) return Promise.resolve();
    if (!infos[key]) {
      var url = '/api/ipinfo?ip=' + encodeURIComponent(ip) + (lang === 'en' ? '&lang=en' : '');
      var record = { data: null, done: false, promise: null };
      record.promise = lookups.add(function () {
        return fetch(url, { headers: { Accept: 'application/json' } }).then(function (response) {
          return response.json();
        }).then(function (data) {
          if (data && data.ok && data.info) record.data = data.info;
        }, function () {
          /* 查不到就留空，比较时按「没核对到」处理 */
        }).then(function () {
          record.done = true;
          /* 失败的不留在缓存里，「重新检测」时能再问一次 */
          if (!record.data && infos[key] === record) delete infos[key];
          render();
        });
      });
      infos[key] = record;
    }
    return infos[key].promise;
  }

  function info(ip) {
    var record = infos[P.exitKey(ip)];
    return record && record.data ? record.data : null;
  }

  function known(value) {
    return value && value !== '—' ? String(value) : '';
  }

  function countryOf(entry) {
    var data = info(entry.ip);
    return known(data && data.countryCode) || entry.loc || '';
  }

  /* ---------------------------------------------------------------- 比较 */

  /* same 同一个 IP 或 /64；net 同一个 ASN，或同国同运营商；other 不同网络；unknown 归属没查到 */
  function rel(a, b) {
    if (P.exitKey(a.ip) === P.exitKey(b.ip)) return 'same';
    var ia = info(a.ip);
    var ib = info(b.ip);
    if (!ia || !ib) return 'unknown';
    if (known(ia.asnCode) && ia.asnCode === ib.asnCode) return 'net';
    if (known(ia.isp) && ia.isp === ib.isp && known(ia.countryCode) && ia.countryCode === ib.countryCode) return 'net';
    return 'other';
  }

  function near(relation) {
    return relation === 'same' || relation === 'net';
  }

  function entriesOf(key) {
    return state[key] ? state[key].entries : [];
  }

  function judgeAll() {
    var base = entriesOf('intl')[0] || entriesOf('v4')[0] || entriesOf('site')[0] || null;
    var cn = entriesOf('cn')[0] || null;
    var split = !!(base && cn) && rel(cn, base) === 'other';

    function side(entry) {
      if (!base) return 'unknown';
      var toBase = rel(entry, base);
      if (near(toBase)) return 'foreign';
      if (toBase === 'unknown') return 'unknown';
      if (!split) return 'third';
      if (near(rel(entry, cn))) return 'domestic';
      var country = countryOf(entry);
      if (country && country === countryOf(cn) && country !== countryOf(base)) return 'domestic';
      return 'third';
    }

    var same = { tone: 'ok', text: T('与国外出口一致', 'Same as international') };
    var unknown = { tone: 'muted', text: T('没核对到', 'Not compared') };
    var other = T('另一个出口', 'Another egress');
    var viaCn = T('走了国内出口', 'Uses China-side egress');

    function judge(key, entry) {
      if (entry === base) return { tone: 'global', text: T('基准', 'Baseline') };

      if (key === 'cn') {
        if (!base) return unknown;
        var toBase = rel(entry, base);
        if (toBase === 'unknown') return unknown;
        return split ? { tone: 'cn', text: T('国内直连', 'Direct') } : { tone: 'muted', text: T('与国外出口相同', 'Same as international') };
      }

      var where = side(entry);
      if (where === 'unknown') return unknown;

      if (key === 'dns') {
        if (where === 'foreign') return { tone: 'ok', text: T('与国外出口同网络', 'Same network as international') };
        if (where === 'domestic') return { tone: 'leak', text: T('走了国内解析', 'Resolved on the China side') };
        var country = countryOf(entry);
        if (country && country === countryOf(base)) return { tone: 'ok', text: T('与国外出口同地区', 'Same region as international') };
        return { tone: 'muted', text: T('其他地区的解析器', 'Resolver in another region') };
      }

      if (where === 'foreign') return same;

      if (where === 'domestic') {
        if (key === 'v6') return { tone: 'leak', text: T('IPv6 暴露国内网络', 'IPv6 exposes China-side network') };
        if (key === 'webrtc') return { tone: 'leak', text: T('暴露国内出口', 'Exposes China-side egress') };
        if (key === 'claude' || key === 'chatgpt') return { tone: 'leak', text: viaCn };
        return { tone: 'warn', text: viaCn };
      }

      if (key === 'claude' || key === 'chatgpt') return { tone: 'muted', text: T('独立出口', 'Dedicated egress') };
      if (key === 'site') return { tone: 'muted', text: other };
      return { tone: 'warn', text: other };
    }

    channels.forEach(function (channel) {
      entriesOf(channel.key).forEach(function (entry) {
        entry.verdict = judge(channel.key, entry);
      });
    });

    return { base: base, cn: cn, split: split };
  }

  /* ---------------------------------------------------------------- 画表 */

  function emptyRow(channel, current) {
    var lead;
    var last = null;

    if (current.status === 'pending') lead = dim(T('待检测', 'Pending'));
    else if (current.status === 'running') lead = dim(T('检测中…', 'Checking…'));
    else if (current.status === 'failed') {
      lead = dim(current.kind === 'unsupported' ? T('浏览器不支持 WebRTC', 'WebRTC is not supported') : P.failureText(current.kind));
      last = tag('muted', T('没读到', 'No result'));
    } else if (channel.key === 'v6') {
      lead = dim(T('没有 IPv6 出口', 'No IPv6 egress'));
      last = tag('muted', T('没有 IPv6', 'No IPv6'));
    } else if (channel.key === 'webrtc') {
      lead = dim(T('没有交出公网地址', 'No public address handed out'));
      last = tag('ok', T('未暴露公网 IP', 'No public IP exposed'));
    } else {
      lead = dim('—');
    }

    return [cell([lead]), cell([]), cell([]), cell([last])];
  }

  function entryRow(channel, entry) {
    var record = infos[P.exitKey(entry.ip)];
    var data = record && record.data;

    var address = P.el('a', 'mono', P.compactIp(entry.ip));
    address.href = lp('/ip/' + entry.ip);
    address.title = entry.ip;
    var source = P.el('span', 'dtable__sub', entry.sources.join(' · '));

    var country = P.country(countryOf(entry));
    var place = [];
    if (country) place.push(document.createTextNode(country));
    if (data) {
      var network = [known(data.asnCode), known(data.isp)].filter(Boolean).join(' ');
      if (network) place.push(P.el('span', 'dtable__sub', network));
    } else if (!country) {
      place.push(dim(record && !record.done ? T('查询中…', 'Looking up…') : T('没查到', 'Lookup failed')));
    }

    var kind = [];
    if (data) {
      kind.push(document.createTextNode(known(data.ipTypeLabel) || '—'));
      /* 解析器的评分没有参考意义，只留类型 */
      if (channel.key !== 'dns') {
        var score = data.score === null || data.score === undefined ? T('未出分', 'No score') : data.score + ' · ' + data.grade;
        kind.push(P.el('span', 'dtable__sub', score));
      }
    } else {
      kind.push(dim(record && !record.done ? T('查询中…', 'Looking up…') : '—'));
    }

    var result = entry.verdict ? [tag(entry.verdict.tone, entry.verdict.text)] : [];
    return [cell([address, source]), cell(place), cell(kind), cell(result)];
  }

  function render() {
    var body = document.createDocumentFragment();

    channels.forEach(function (channel) {
      var current = state[channel.key];
      var entries = current.entries.length ? current.entries : [null];

      entries.forEach(function (entry, index) {
        var tr = document.createElement('tr');
        if (index === 0) {
          var head = channel.head.cloneNode(true);
          head.rowSpan = entries.length;
          tr.appendChild(head);
        }
        (entry ? entryRow(channel, entry) : emptyRow(channel, current)).forEach(function (td) {
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
    });

    tbody.textContent = '';
    tbody.appendChild(body);
  }

  /* ---------------------------------------------------------------- 结论 */

  function flagged(tone) {
    return channels.filter(function (channel) {
      return entriesOf(channel.key).some(function (entry) { return entry.verdict && entry.verdict.tone === tone; });
    }).map(function (channel) { return channel.name; });
  }

  function conclude() {
    var result = judgeAll();
    render();
    if (!verdict || !verdictTitle || !verdictNote) return;

    var sep = T('、', ', ');
    var leaks = flagged('leak');
    var warns = flagged('warn');
    var tone = 'is-good';
    var title;
    var notes = [];

    if (!result.base) {
      tone = 'is-warn';
      title = T('没读到国外出口，无法比较', 'No international egress to compare against');
      notes.push(T('请求可能被代理规则或浏览器扩展拦下，稍后重新检测。', 'The requests may be blocked by proxy rules or a browser extension. Try again later.'));
    } else if (leaks.length) {
      tone = 'is-bad';
      title = T('有通道暴露了国内出口', 'Some channels expose the China-side egress');
      notes.push(T('暴露的通道：', 'Exposed: ') + leaks.join(sep) + T('。', '.'));
      if (warns.length) notes.push(T('另有通道没走国外出口：', 'Also off the international egress: ') + warns.join(sep) + T('。', '.'));
    } else if (warns.length) {
      tone = 'is-warn';
      title = T('有通道没走国外出口', 'Some channels do not use the international egress');
      notes.push(T('涉及的通道：', 'Channels: ') + warns.join(sep) + T('。', '.'));
    } else if (result.split) {
      title = T('国内外分流，其余通道都跟国外出口一致', 'Split routing; every other channel matches the international egress');
    } else {
      title = T('各通道是同一个出口', 'Every channel uses the same egress');
    }

    if (result.base) {
      var summary = T('国外出口 ', 'International ') + result.base.ip;
      if (result.cn) {
        summary += T('，国内出口 ', ', China-side ') + result.cn.ip;
      } else {
        summary += T('。国内出口没读到，无法判断是否分流', '. The China-side egress could not be read, so split routing cannot be determined');
      }
      notes.push(summary + T('。', '.'));
    }

    verdict.className = 'verdict ' + tone;
    verdictTitle.textContent = title;
    verdictNote.textContent = notes.join(' ');
    verdict.hidden = false;
  }

  /* ---------------------------------------------------------------- 流程 */

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    if (verdict) verdict.hidden = true;

    channels.forEach(function (channel) {
      state[channel.key] = { status: PROBES[channel.key] ? 'running' : 'pending', entries: [], kind: '' };
    });
    if (state.site && P.ipKey(visibleIp)) {
      state.site = { status: 'done', entries: [{ ip: visibleIp, loc: '', sources: ['judgeip.com'] }], kind: '' };
    }

    var probed = channels.filter(function (channel) { return PROBES[channel.key]; });
    var done = 0;
    var step = function () {
      if (progress) progress.textContent = T('正在检测 ' + done + ' / ' + probed.length + ' 个通道…', 'Checking channels ' + done + ' / ' + probed.length + '…');
    };
    step();
    render();

    var jobs = probed.map(function (channel) {
      return PROBES[channel.key]().then(function (entries) {
        state[channel.key] = { status: 'done', entries: entries, kind: '' };
      }, function (failure) {
        state[channel.key] = { status: 'failed', entries: [], kind: failure && failure.kind };
      }).then(function () {
        done++;
        step();
        render();
        return Promise.all(entriesOf(channel.key).map(function (entry) { return lookup(entry.ip); }));
      });
    });
    jobs.push(Promise.all(entriesOf('site').map(function (entry) { return lookup(entry.ip); })));

    Promise.all(jobs).then(function () {
      conclude();

      var exits = {};
      channels.forEach(function (channel) {
        entriesOf(channel.key).forEach(function (entry) {
          if (channel.key !== 'dns') exits[P.exitKey(entry.ip)] = true;
        });
      });
      var count = Object.keys(exits).length;
      if (progress) progress.textContent = T('检测完成，共 ' + count + ' 个不同出口。', 'Done. ' + count + (count === 1 ? ' distinct egress.' : ' distinct egresses.'));
    }).then(function () {
      running = false;
      runButton.disabled = false;
    });
  }

  runButton.addEventListener('click', run);
  run();
})();
