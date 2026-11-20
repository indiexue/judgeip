/* JudgeIP — WebRTC 泄露检测。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   核心思路：每台 STUN 服务器单独建一个 RTCPeerConnection。
   把十台一起塞进 iceServers 时，浏览器只会给出去重后的候选地址，
   根本分不清是哪台回的、哪台压根没通——「国内通、国外全超时」这种
   真实网络状况就看不出来了。逐台测慢一点，但结论是可信的。 */
(function () {
  'use strict';

  var root = document.getElementById('webrtc');
  if (!root) return;

  var PROBE_TIMEOUT = 4000;
  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();

  var runButton = root.querySelector('[data-webrtc-run]');
  var progress = root.querySelector('[data-webrtc-progress]');
  var verdict = root.querySelector('[data-webrtc-verdict]');
  var verdictTitle = root.querySelector('[data-webrtc-verdict-title]');
  var verdictNote = root.querySelector('[data-webrtc-verdict-note]');
  var fixNote = root.querySelector('[data-webrtc-fix]');
  var publicCell = root.querySelector('[data-webrtc-public]');
  var localCell = root.querySelector('[data-webrtc-local]');
  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-stun-url]'));

  var PeerConnection = window.RTCPeerConnection ||
                       window.webkitRTCPeerConnection ||
                       window.mozRTCPeerConnection;

  /* ---------------------------------------------------------------- 工具 */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* 结果格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) cell.appendChild(nodes[i]);
  }

  function isPrivate(address) {
    if (address.indexOf(':') !== -1) {
      /* IPv6：fc00::/7 唯一本地、fe80::/10 链路本地 */
      var head = address.toLowerCase();
      return head.indexOf('fc') === 0 || head.indexOf('fd') === 0 || head.indexOf('fe8') === 0 ||
             head.indexOf('fe9') === 0 || head.indexOf('fea') === 0 || head.indexOf('feb') === 0;
    }
    var p = address.split('.').map(Number);
    if (p.length !== 4) return false;
    if (p[0] === 10 || p[0] === 127) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    /* 100.64.0.0/10 运营商级 NAT：不是内网，但也不是「你的」地址，单独不算泄露 */
    return false;
  }

  /* mDNS 混淆后的 host 候选，形如 a1b2c3d4-….local —— 这是浏览器的保护生效了，不是地址 */
  function isMdns(value) {
    return /\.local$/i.test(value);
  }

  /* 候选地址行的格式：
     candidate:842163049 1 udp 1677729535 1.2.3.4 54321 typ srflx raddr 0.0.0.0 rport 0 …
     现代浏览器已经把 address / type 拆成属性了，优先读属性，读不到再退回解析原始串。 */
  function parseCandidate(event) {
    var candidate = event.candidate;
    var line = candidate.candidate || '';
    var address = candidate.address || '';
    var type = candidate.type || '';

    if (!address || !type) {
      var parts = line.split(' ');
      if (parts.length >= 8) {
        if (!address) address = parts[4];
        if (!type) type = parts[7];
      }
    }

    return address ? { address: address, type: type || 'host' } : null;
  }

  /* ---------------------------------------------------------------- 单台探测 */

  function probe(url) {
    return new Promise(function (resolve) {
      var found = { srflx: [], host: [], relay: [] };
      var settled = false;
      var started = (window.performance && performance.now) ? performance.now() : Date.now();
      var pc;
      var timer;

      function finish(error) {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        try { pc.close(); } catch (e) { /* 已经关了就算了 */ }

        var now = (window.performance && performance.now) ? performance.now() : Date.now();
        resolve({
          url: url,
          error: error || null,
          ms: Math.round(now - started),
          srflx: found.srflx,
          host: found.host,
          relay: found.relay
        });
      }

      try {
        pc = new PeerConnection({ iceServers: [{ urls: url }] });
      } catch (e) {
        resolve({ url: url, error: 'reject', ms: 0, srflx: [], host: [], relay: [] });
        return;
      }

      timer = window.setTimeout(function () { finish('timeout'); }, PROBE_TIMEOUT);

      pc.onicecandidate = function (event) {
        /* candidate 为 null 是收集结束的信号，不是一条地址 */
        if (!event.candidate || !event.candidate.candidate) {
          finish(null);
          return;
        }

        var parsed = parseCandidate(event);
        if (!parsed) return;

        var bucket = parsed.type === 'srflx' || parsed.type === 'prflx' ? found.srflx
                   : parsed.type === 'relay' ? found.relay
                   : found.host;

        if (bucket.indexOf(parsed.address) === -1) bucket.push(parsed.address);
      };

      pc.onicegatheringstatechange = function () {
        if (pc.iceGatheringState === 'complete') finish(null);
      };

      /* 没有数据通道就没有媒体需求，ICE 不会启动 */
      try {
        pc.createDataChannel('ipcx-probe');
      } catch (e) {
        finish('reject');
        return;
      }

      pc.createOffer()
        .then(function (offer) { return pc.setLocalDescription(offer); })
        .catch(function () { finish('failed'); });
    });
  }

  /* ---------------------------------------------------------------- 渲染 */

  var ERRORS = { timeout: '超时', failed: '连接失败', reject: '不可用' };

  function renderRow(cell, result) {
    var nodes = [];

    if (result.srflx.length || result.relay.length) {
      result.srflx.concat(result.relay).forEach(function (address) {
        /* 与本站看到的地址不一致的那一条才是真正的泄露，单独标红 */
        var leaked = visibleIp !== '' && address !== visibleIp;
        nodes.push(el('span', 'tag ' + (leaked ? 'tag--leak' : 'tag--ok') + ' mono', address));
      });
    } else if (result.error) {
      nodes.push(el('span', 'tag tag--muted', ERRORS[result.error] || '失败'));
    } else {
      nodes.push(el('span', 'tag tag--ok', '无公网候选'));
    }

    nodes.push(el('span', 'stun__ms mono', result.ms + ' ms'));
    fill(cell, nodes);
  }

  function renderSummary(results) {
    var publics = [];
    var locals = [];

    results.forEach(function (result) {
      result.srflx.concat(result.relay).forEach(function (a) {
        if (publics.indexOf(a) === -1) publics.push(a);
      });
      result.host.forEach(function (a) {
        if (locals.indexOf(a) === -1) locals.push(a);
      });
    });

    /* 只有真实内网地址才算暴露；.local 是 mDNS 混淆，那是保护生效 */
    var realLocals = locals.filter(function (a) { return !isMdns(a) && isPrivate(a); });
    var leaked = publics.filter(function (a) { return visibleIp !== '' && a !== visibleIp; });
    var reachable = results.filter(function (r) { return !r.error; }).length;

    fill(publicCell, publics.length
      ? publics.map(function (a) {
          return el('span', 'tag ' + (visibleIp !== '' && a !== visibleIp ? 'tag--leak' : 'tag--ok') + ' mono', a);
        })
      : [el('span', 'dim', '未探测到')]);

    fill(localCell, locals.length
      ? locals.map(function (a) {
          return el('span', 'tag ' + (isMdns(a) ? 'tag--ok' : isPrivate(a) ? 'tag--warn' : 'tag--ok') + ' mono', a);
        })
      : [el('span', 'dim', '未探测到')]);

    var tone, title, note;

    if (leaked.length) {
      tone = 'is-bad';
      title = '检测到 WebRTC 泄露';
      note = 'WebRTC 探到的 ' + leaked.join('、') + ' 与本站看到的 ' + visibleIp +
             ' 不是同一个地址。任何网页都能用同样的方式拿到前者——你的代理没有兜住 UDP 流量。';
    } else if (publics.length) {
      tone = 'is-warn';
      title = '有公网地址暴露，但没有额外泄露';
      note = 'WebRTC 探到的地址与本站看到的一致，说明没有暴露出第二个身份。'
           + '若你并未使用代理，这就是正常状态；若你正在用代理，说明它已经正确接管了 UDP。';
    } else if (reachable === 0) {
      tone = 'is-warn';
      title = '所有 STUN 服务器都没有响应';
      note = '这不等于安全，只说明当前网络到这些服务器的 UDP 不通（可能被防火墙拦下）。'
           + '换个网络环境重测一次，才能确认浏览器本身有没有这条旁路。';
    } else {
      tone = 'is-good';
      title = '未发现公网地址泄露';
      note = reachable + ' 台服务器有响应，均未拿到你的公网地址。'
           + (realLocals.length ? '不过内网地址 ' + realLocals.join('、') + ' 仍然可见。' : '内网地址也未暴露。');
    }

    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    verdictNote.textContent = note;

    /* WebRTC 只要真的吐出了地址——不管是公网的还是内网的——这条旁路就是通的，
       此时才给出扩展链接；一个地址都没探到的人不需要被推销任何东西。 */
    if (fixNote) fixNote.hidden = !(publics.length || realLocals.length);
  }

  /* ---------------------------------------------------------------- 主流程 */

  function run() {
    if (!PeerConnection) {
      verdict.className = 'verdict is-warn';
      verdict.hidden = false;
      verdictTitle.textContent = '当前浏览器不支持 WebRTC';
      verdictNote.textContent = '没有 RTCPeerConnection 就没有这条旁路——从泄露的角度看，这是最安全的状态。';
      runButton.disabled = true;
      return;
    }

    runButton.disabled = true;
    verdict.hidden = true;
    if (fixNote) fixNote.hidden = true;
    rows.forEach(function (row) {
      fill(row.querySelector('[data-stun-result]'), [el('span', 'dim', '探测中…')]);
    });

    var results = [];
    var index = 0;

    /* 串行而不是并行：十条 PeerConnection 同时开着，慢的网络上互相抢 UDP 端口，
       超时数会虚高，测出来的「不通」并不真实。 */
    function next() {
      if (index >= rows.length) {
        progress.textContent = '检测完成，共 ' + rows.length + ' 台服务器。';
        renderSummary(results);
        runButton.disabled = false;
        runButton.textContent = '重新检测';
        return;
      }

      var row = rows[index];
      progress.textContent = '正在探测第 ' + (index + 1) + ' / ' + rows.length + ' 台…';

      probe(row.getAttribute('data-stun-url')).then(function (result) {
        results.push(result);
        renderRow(row.querySelector('[data-stun-result]'), result);
        index += 1;
        next();
      });
    }

    next();
  }

  runButton.addEventListener('click', run);
})();
