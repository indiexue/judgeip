/* JudgeIP — Cloudflare 节点检测。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   数据全部来自 Cloudflare 边缘的 /cdn-cgi/trace（任何 Cloudflare 站点都有，带 Access-Control-Allow-Origin: *）：
     1. 主 trace（speed.cloudflare.com）请求两次：第一次只为建连，第二次才展示——
        第一次握手时浏览器才收到 Alt-Svc，HTTP/3 最早也只可能出现在之后的连接上；
     2. trace 不给坐标：「节点离你多远」用的是本站对「它看到的你的地址」的位置记录（同源的 /geo/api?me=1，
        带 ASN、省市与坐标），而且只在那条地址与 trace 里的出口是同一个时才用——见 renderMe；
     3. 1.1.1.1 的 trace：IP 字面量只能走 IPv4；
     4. 七个不同等级的网络各预热 1 次、再测 3 次取最快，对比命中节点与延迟。
   主机名一律从 data-* 读——它们和 CSP 放行的源出自同一份 PHP 常量（CloudflareNode），
   脚本里不再写一份，免得改了清单、CSP 与脚本对不上。

   结果只留在当前页面里，不回传本站；问本站位置的那一次请求不带任何检测结果。 */
(function () {
  'use strict';

  var root = document.getElementById('cloudflare');
  if (!root) return;

  var P = window.IpcxProbe;

  var TIMEOUT = 6000;
  var ROUNDS = 3;
  var LANES = 4;
  /* 时钟偏差的告警线，单位是秒、按显示出来的数比。
     trace 的 ts 虽然写成三位小数，实测小数部分永远是 .000——边缘把时间向下取整到了秒，
     偏差因此只能估到整秒（见 renderTime）。显示「快约 3 秒」及以上才告警：这时真实偏差至少在 2 秒上下，
     同步正常的时钟（估出来 0～1 秒）不会被误报。
     节点远近的分档不在这里：用 probe.js 的 P.distanceClass，与 /cdn、首页同一套。 */
  var SKEW_WARN_S = 2;

  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var iataUrl = root.getAttribute('data-iata') || '';
  var mainHost = root.getAttribute('data-main') || '';
  var meUrl = root.getAttribute('data-me') || '';
  var ipv4Host = root.getAttribute('data-ipv4') || '';

  var runButton = root.querySelector('[data-cf-run]');
  var progress = root.querySelector('[data-cf-progress]');
  var verdict = root.querySelector('[data-cf-verdict]');
  var verdictTitle = root.querySelector('[data-cf-verdict-title]');
  var verdictNote = root.querySelector('[data-cf-verdict-note]');
  var maskButton = root.querySelector('[data-cf-mask]');
  var visibleNode = root.querySelector('[data-cf-visible]');
  var rawPre = root.querySelector('[data-cf-raw]');
  var tierRows = Array.prototype.slice.call(root.querySelectorAll('[data-cf-tier]'));
  var tierSum = root.querySelector('[data-cf-tier-sum]');

  var CELL_KEYS = ['ip', 'loc', 'asn', 'colo', 'ipv4', 'http', 'tls', 'sni', 'kex', 'warp', 'gateway', 'rbi', 'ts'];
  var cells = {};
  CELL_KEYS.forEach(function (key) {
    cells[key] = root.querySelector('[data-cf="' + key + '"]');
  });

  function setVerdict(tone, title, note) {
    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    verdictNote.textContent = note;
  }

  /* probe.js 没加载上（被拦、加载失败）或浏览器老到没有 fetch / Promise：说清楚，别留一页「待检测」。
     两种原因分开说：前者刷新一下多半就好，后者刷新也没用，得换浏览器。
     进度那一行原本写着「打开页面即自动开始」，也一并改掉，免得和结论自相矛盾 */
  if (!P || !window.fetch || !window.Promise) {
    if (!P) {
      setVerdict('is-warn', '检测脚本加载失败',
        '本站的检测脚本（probe.js）没能加载：可能是网络中断，也可能被浏览器扩展拦截了。请刷新页面重试；仍然不行，检查是否有扩展拦截了本站脚本。');
    } else {
      setVerdict('is-warn', '当前浏览器无法运行检测',
        '检测需要浏览器支持 fetch 与 Promise，当前浏览器太旧，请换用较新的浏览器。');
    }
    if (progress) progress.textContent = !P ? '检测脚本加载失败，请刷新页面重试。' : '当前浏览器不支持本页的检测。';
    if (runButton) runButton.disabled = true;
    return;
  }

  /* ---------------------------------------------------------------- 小工具 */

  /* 结果格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    if (!cell) return;
    cell.textContent = '';
    nodes.forEach(function (node) {
      if (node) cell.appendChild(node);
    });
  }

  function tag(text, tone) {
    return P.el('span', 'tag tag--' + tone, text);
  }

  function dim(text) {
    return P.el('span', 'dim', text);
  }

  /* 值下面的一行说明：为什么是这个结果、该怎么理解 */
  function note(text) {
    return P.el('span', 'cfnote', text);
  }

  /* 一行里并排的几个片段（地址、标签、毫秒数），间距交给 CSS */
  function line(nodes) {
    var wrap = P.el('span', 'cfline');
    nodes.forEach(function (node) {
      if (node) wrap.appendChild(node);
    });
    return wrap;
  }

  function family(ip) {
    return P.isIPv6(ip) ? 'IPv6' : 'IPv4';
  }

  /* IPv6 隐私地址会定期更换后 64 位，同一条线路上两次连接的地址可能不一样；前 64 位相同就算同一个出口 */
  var samePrefix64 = P.samePrefix64;

  function sameExit(a, b) {
    return P.sameIp(a, b) || samePrefix64(a, b);
  }

  function thousands(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function kmText(km) {
    return '约 ' + thousands(km) + ' 公里';
  }

  function num(value) {
    var n = typeof value === 'number' ? value : parseFloat(value);
    return isNaN(n) ? null : n;
  }

  /* ---------------------------------------------------------------- 隐藏 IP

     录屏、截图时把页面上所有地址打码，再点一下还原。打码规则与首页 IP 卡片一致（见 app.js）：
     IPv4 留前两段，IPv6 留前两组。真值留在 JS 里，DOM 上只写当前该显示的那一份。
     不落存储：刷新即回到显示状态。 */
  var masked = false;
  var ipNodes = [];
  var rawText = '';
  var visibleEntry = visibleNode && visibleIp ? { node: visibleNode, ip: visibleIp } : null;

  function maskIp(value) {
    if (value.indexOf(':') !== -1) return value.split(':').slice(0, 2).join(':') + ':*:*';
    var octets = value.split('.');
    return octets.length === 4 ? octets[0] + '.' + octets[1] + '.*.*' : '*.*.*.*';
  }

  function paintIp(entry) {
    entry.node.textContent = masked ? maskIp(entry.ip) : entry.ip;
  }

  function ipSpan(ip) {
    var entry = { node: P.el('span', 'mono'), ip: ip };
    ipNodes.push(entry);
    paintIp(entry);
    return entry.node;
  }

  function paintRaw() {
    if (!rawPre) return;
    if (!rawText) {
      rawPre.textContent = '尚未取得。';
      return;
    }
    rawPre.textContent = masked
      ? rawText.replace(/^ip=(.*)$/m, function (all, ip) { return 'ip=' + maskIp(ip.trim()); })
      : rawText;
  }

  if (maskButton) {
    maskButton.addEventListener('click', function () {
      masked = !masked;
      var label = masked ? '显示 IP 地址' : '隐藏 IP 地址';
      maskButton.setAttribute('aria-pressed', masked ? 'true' : 'false');
      maskButton.setAttribute('aria-label', label);
      maskButton.setAttribute('title', label);
      ipNodes.forEach(paintIp);
      paintRaw();
    });
  }

  /* ---------------------------------------------------------------- 字段解读 */

  /* 「🇭🇰 香港」+「HKG」。查不到的代码原样显示，不猜 */
  function coloNodes(info) {
    if (!info.code) return [dim('未知')];
    if (!info.known) return [P.el('span', 'mono', info.code), dim('（未收录的节点代码）')];
    var flag = P.flag(info.cc);
    return [
      P.el('span', 'cfcity', (flag ? flag + ' ' : '') + info.city),
      P.el('span', 'cfcode mono', info.code)
    ];
  }

  function coloTitle(info) {
    if (!info.code) return '未知';
    if (!info.known) return info.code;
    var flag = P.flag(info.cc);
    return (flag ? flag + ' ' : '') + info.city + '（' + info.code + '）';
  }

  /* loc：两位国家代码；T1 是 Cloudflare 给 Tor 出口的专用代码，XX 是查不到 */
  function countryText(loc) {
    var code = String(loc || '').toUpperCase();
    if (code === 'T1') return 'Tor 网络';
    if (!code || code === 'XX') return '';
    return P.country(code) || code;
  }

  /* trace 里的 http 是 http/1.1 | http/2 | http/3 */
  function httpInfo(value) {
    var h = String(value || '').toLowerCase();
    if (h === 'http/3') return { label: 'HTTP/3（QUIC）', short: 'HTTP/3', tone: 'ok' };
    if (h === 'http/2') return { label: 'HTTP/2', short: 'HTTP/2', tone: 'muted' };
    if (h.indexOf('http/1') === 0) return { label: h.toUpperCase(), short: h.toUpperCase(), tone: 'warn' };
    return { label: h ? h.toUpperCase() : '未知', short: h ? h.toUpperCase() : '—', tone: 'muted' };
  }

  function tlsLabel(value) {
    return String(value || '').replace(/^TLSv/i, 'TLS ') || '未知';
  }

  function warpLabel(value) {
    var w = String(value || 'off').toLowerCase();
    if (w === 'plus') return 'WARP+ 已开启';
    if (w === 'on') return 'WARP 已开启';
    return '';
  }

  /* ---------------------------------------------------------------- 请求 */

  /* 主 trace：预热一次，再取一次展示。
     第二次前后各记一次本机时间，与边缘的 ts 对照得出时钟偏差。
     预热失败时：很快失败的（被拦、连接重置）值得再试一次；超时的再试也是超时，直接判失败，
     不让访客对着「检测中」多等六秒。 */
  function mainTrace() {
    return P.trace(mainHost, TIMEOUT).then(function (warm) {
      var t0 = Date.now();
      return P.trace(mainHost, TIMEOUT).then(function (report) {
        report.t0 = t0;
        report.t1 = Date.now();
        return report;
      }, function () {
        /* 第二次没成，第一次的结果照样可用，只是没有时钟偏差 */
        return warm;
      });
    }, function (failure) {
      if (failure && failure.kind === 'timeout') return Promise.reject(failure);
      var t0 = Date.now();
      return P.trace(mainHost, TIMEOUT).then(function (report) {
        report.t0 = t0;
        report.t1 = Date.now();
        return report;
      });
    });
  }

  /* 本站对「它看到的你的地址」的位置记录（GeoApi 的 ?me=1）。取不到就当没有，只是少了 ASN 与距离。
     字段的类型服务端已经理过一遍，这里仍然只认数：页面不该因为一个怪值算出 NaN 公里。
     X-Requested-With 是给服务端认「这是本站页面上的脚本发的」用的（GeoApi::SCRIPT_HEADER，值是公开的）：
     不发 Sec-Fetch-Site 的旧浏览器里，服务端靠它把这一次请求和别的站点嵌的一张 <img> 分开。
     同源请求加头不触发预检；本页发给 Cloudflare 的请求一个自定义头都不带 */
  function fetchMe() {
    if (!meUrl) return Promise.resolve(null);
    return P.text(meUrl, { headers: { 'X-Requested-With': 'ipcx' } }, TIMEOUT).then(function (result) {
      var data = JSON.parse(result.text);
      if (!data || data.ok !== true || typeof data.ip !== 'string' || !data.ip) return null;
      var text = function (v) { return typeof v === 'string' ? v : ''; };
      return {
        ip: data.ip,
        country: text(data.country).toUpperCase(),
        region: text(data.region),
        city: text(data.city),
        lat: typeof data.lat === 'number' ? data.lat : null,
        lon: typeof data.lon === 'number' ? data.lon : null,
        asn: typeof data.asn === 'number' ? data.asn : null,
        org: text(data.org)
      };
    }).catch(function () {
      return null;
    });
  }

  function traceIpv4() {
    if (!ipv4Host) return Promise.resolve({ ok: false, kind: 'error' });
    return P.trace(ipv4Host, TIMEOUT).then(function (result) {
      return { ok: true, data: result.data, ms: result.ms };
    }, function (failure) {
      return { ok: false, kind: failure && failure.kind };
    });
  }

  /* ---------------------------------------------------------------- 渲染：主 trace */

  function renderExitIp(ip) {
    var nodes = [ipSpan(ip), tag(family(ip), 'muted')];
    var text = '';

    if (visibleIp) {
      var sameFamily = P.isIPv6(ip) === P.isIPv6(visibleIp);
      if (sameFamily && P.sameIp(ip, visibleIp)) {
        nodes.push(tag('与本站看到的一致', 'ok'));
      } else if (sameFamily && samePrefix64(ip, visibleIp)) {
        nodes.push(tag('与本站同一 /64 网段', 'ok'));
        text = 'IPv6 隐私地址会定期更换后 64 位，前 64 位相同就是同一条线路、同一个出口。';
      } else if (sameFamily) {
        nodes.push(tag('与本站看到的不同', 'warn'));
        text = '访问 Cloudflare 的流量走了另一个出口：常见于按域名分流的代理规则，或带多个出口的代理服务。';
      } else {
        /* 跨地址族没法比：两条都可能是你自己的出口，不报警 */
        text = '本站经 ' + family(visibleIp) + ' 看到你，Cloudflare 经 ' + family(ip)
          + ' 看到你——双栈网络下两边各选了一个地址族，这是正常现象，不是分流。';
      }
    }

    fill(cells.ip, [line(nodes), text ? note(text) : null]);
  }

  function renderHttp(value) {
    var info = httpInfo(value);
    var text = '';
    if (info.short === 'HTTP/2') {
      text = '首次访问通常为 HTTP/2：浏览器记住这个站点支持 HTTP/3 之后，新连接才会改走 QUIC，刷新后再测即可。';
    } else if (info.tone === 'warn') {
      text = '只协商到了 HTTP/1.x，通常说明中间有一层不支持新协议的代理或安全软件。';
    }
    fill(cells.http, [line([tag(info.label, info.tone)]), text ? note(text) : null]);
  }

  function renderTls(value) {
    var label = tlsLabel(value);
    var tone = /1\.3/.test(label) ? 'ok' : 'muted';
    var text = /1\.[0-2]$/.test(label) ? '能用，但不是当前的 TLS 1.3，可能经过了做 TLS 解密的代理或安全软件。' : '';
    fill(cells.tls, [line([tag(label, tone)]), text ? note(text) : null]);
  }

  function renderSni(value) {
    var s = String(value || '').toLowerCase();
    if (s === 'encrypted') {
      fill(cells.sni, [line([tag('加密 SNI（ECH）', 'ok')]), note('连沿途的网络设备也看不到你访问的是哪个域名。')]);
    } else if (s === 'plaintext') {
      fill(cells.sni, [line([tag('明文 SNI', 'muted')]),
        note('目前绝大多数连接都是如此：浏览器开启安全 DNS、且站点支持 ECH 时才会加密。')]);
    } else if (s === 'off') {
      fill(cells.sni, [line([tag('未发送 SNI', 'muted')])]);
    } else {
      fill(cells.sni, [line([P.el('span', 'mono', s || '未知')])]);
    }
  }

  function renderKex(value) {
    if (!value) {
      fill(cells.kex, [dim('未知')]);
      return;
    }
    var pq = /mlkem|kyber/i.test(value);
    fill(cells.kex, [
      line([P.el('span', 'mono', value), pq ? tag('后量子', 'ok') : tag('非后量子', 'muted')]),
      pq ? note('混合了 ML-KEM 的密钥交换：即使将来出现量子计算机，今天截获的流量也难以被解密。') : null
    ]);
  }

  function renderSwitch(cell, value, onText, onNote) {
    var v = String(value || '').toLowerCase();
    if (v === 'on') {
      fill(cell, [line([tag(onText, 'warn')]), note(onNote)]);
    } else if (v === 'off') {
      fill(cell, [line([tag('未启用', 'muted')])]);
    } else {
      fill(cell, [line([P.el('span', 'mono', v || '未知')])]);
    }
  }

  function renderWarp(value) {
    var label = warpLabel(value);
    if (label) {
      fill(cells.warp, [line([tag(label, 'warn')]),
        note('Cloudflare 看到的是 WARP 的出口，命中节点也按 WARP 出口调度。')]);
    } else {
      renderSwitch(cells.warp, value, '', '');
    }
  }

  function renderTime(data, t0, t1) {
    var edge = num(data.ts);
    if (edge === null) {
      fill(cells.ts, [dim('未知')]);
      return;
    }

    var edgeMs = edge * 1000;
    var stamp = new Date(edgeMs);
    var text;
    try {
      text = stamp.toLocaleString('zh-CN', { hour12: false });
    } catch (e) {
      text = stamp.toString();
    }

    var nodes = [P.el('span', 'mono', text)];

    /* 偏差 = 本机时间 − 边缘时间。本机时间取请求前后的中点：边缘生成 ts 的时刻大致落在往返的正中。

       边缘时间的精度要看数据本身：Cloudflare 的 ts 写成 1792986537.000，小数部分实测永远是 0——
       它是向下取整到秒的，真正的边缘时刻落在 [ts, ts+1) 里的某处。直接拿 ts 去减，
       同步得好好的时钟也会随机显示「+0.4 秒」「+0.9 秒」（平均偏 +0.5 秒的锯齿），告警线附近也会差出一秒。
       所以小数为零就按整秒分辨率处理：参照点取这一秒的正中（ts + 0.5 秒），偏差只报到整秒；
       哪天 ts 真带了毫秒，才报到 0.1 秒。告警看的是显示出来的数，标签与数字永远自洽。 */
    if (typeof t0 === 'number' && typeof t1 === 'number') {
      var coarse = Math.floor(edge) === edge;
      var skew = (t0 + t1) / 2 - (coarse ? edgeMs + 500 : edgeMs);
      var amount = coarse ? Math.round(Math.abs(skew) / 1000) : Math.round(Math.abs(skew) / 100) / 10;
      var shown = (coarse ? String(amount) : amount.toFixed(1)) + ' 秒';
      if (amount <= SKEW_WARN_S) {
        nodes.push(tag('本机时钟准确', 'ok'));
        if (amount > 0) {
          nodes.push(dim('偏差约 ' + (skew > 0 ? '+' : '−') + shown));
        } else {
          nodes.push(dim(coarse ? '在 1 秒的测量精度内与边缘时间一致' : '偏差不到 0.1 秒'));
        }
      } else {
        nodes.push(tag((skew > 0 ? '本机时钟快约 ' : '本机时钟慢约 ') + shown, 'warn'));
      }
    }

    fill(cells.ts, [line(nodes)]);
  }

  function renderMain(main, colos) {
    var data = main.data;
    renderExitIp(data.ip);
    renderHttp(data.http);
    renderTls(data.tls);
    renderSni(data.sni);
    renderKex(data.kex);
    renderWarp(data.warp);
    renderSwitch(cells.gateway, data.gateway, '已启用', '流量正经过某个组织配置的 Cloudflare Gateway（多见于公司设备）。');
    renderSwitch(cells.rbi, data.rbi, '已启用', '网页其实运行在 Cloudflare 的远程浏览器里，你看到的只是渲染结果。');
    renderTime(data, main.t0, main.t1);

    /* 国家与节点先按 trace 摆出来，本站的位置记录回来后再补上省市、ASN 与距离 */
    var country = countryText(data.loc);
    fill(cells.loc, [line([country ? P.el('span', '', country) : dim('未知')])]);
    fill(cells.asn, [dim('查询中…')]);
    fill(cells.colo, [line(coloNodes(P.colo(colos, data.colo)))]);
  }

  function renderMainFailure(failure) {
    var kind = failure && failure.kind;
    ['ip', 'loc', 'asn', 'colo', 'http', 'tls', 'sni', 'kex', 'warp', 'gateway', 'rbi', 'ts'].forEach(function (key) {
      fill(cells[key], [tag('未取到', 'muted')]);
    });

    var why = kind === 'csp'
      ? '本页的内容安全策略（CSP）没有放行 ' + mainHost + '——这是本站的部署问题，不是你的网络问题。'
      : (kind === 'timeout'
        ? '请求 ' + mainHost + '/cdn-cgi/trace 超时（' + TIMEOUT / 1000 + ' 秒）。'
        : '请求 ' + mainHost + '/cdn-cgi/trace 失败，或者返回的不是 trace 文本。');

    setVerdict('is-bad', 'Cloudflare 接口不可达',
      why + (kind === 'csp' ? '' : '最常见的原因是浏览器扩展（广告拦截、隐私保护类）或代理规则拦下了 cdn-cgi/trace，'
        + '公司网络的过滤网关也会这样做。') + '下方的 1.1.1.1 与节点等级对比仍会逐个尝试。');
  }

  /* 本站的位置记录回来之后：国家行补省市，ASN 行，节点行补距离与远近，最后给出结论。

     me 说的是「本站看到的那条地址」，不是 Cloudflare 看到的出口。只有两条是同一个出口
     （同一个 IPv4，或同一个 IPv6 /64）时，它的 ASN、省市与坐标说的才是这里的出口；
     对不上——分流代理把去 Cloudflare 的流量送去了别的出口，或双栈下两边各走了一个地址族——
     就一样也不套用：那是另一条地址的位置，拿来算距离只会得出一个看着很准的错数。退回只按国家判断远近。 */
  function renderMe(main, me, colos) {
    var data = main.data;
    var info = P.colo(colos, data.colo);
    var loc = String(data.loc || '').toUpperCase();
    var same = !!me && sameExit(me.ip, data.ip);
    var other = !!me && !same;

    var country = countryText(data.loc);
    var place = [];
    /* 省市是本站的库对这条地址的说法；它连国家都和 Cloudflare 报的不一样时不往上凑，免得一行里自相矛盾 */
    if (same && me.country === loc) {
      if (me.region) place.push(me.region);
      if (me.city && me.city !== me.region) place.push(me.city);
    }
    fill(cells.loc, [line([
      country ? P.el('span', '', country) : dim('未知'),
      place.length ? dim(place.join(' · ') + '（本站数据）') : null
    ])]);

    if (same && me.asn !== null) {
      fill(cells.asn, [line([P.el('span', 'mono', 'AS' + me.asn), me.org ? P.el('span', '', me.org) : null])]);
    } else if (same) {
      fill(cells.asn, [dim('本站没有查到这条地址的 ASN')]);
    } else if (other) {
      fill(cells.asn, [
        line([dim('未取到')]),
        note((P.isIPv6(me.ip) !== P.isIPv6(data.ip)
          ? '本站经 ' + family(me.ip) + '、Cloudflare 经 ' + family(data.ip) + ' 看到你，是两条不同的地址'
          : 'Cloudflare 看到的出口与本站看到的不是同一个地址')
          + '；本站只查得到它自己看到的那一条。')
      ]);
    } else {
      fill(cells.asn, [dim('未取到（本站的归属查询暂时不可用）')]);
    }

    var lat = same ? me.lat : null;
    var lon = same ? me.lon : null;
    var km = info.known ? P.distance(lat, lon, info.lat, info.lon) : null;
    /* 远近分档用 probe.js 的 P.distanceClass，与 /cdn、首页同一套规则、同一套标签。
       代码不在对照表里的节点不知道在哪，不分档 */
    var cls = info.known ? P.distanceClass(info, data.loc, km) : 'unknown';
    var label = P.DISTANCE_LABELS[cls];

    var coloLine = coloNodes(info);
    if (km !== null) coloLine.push(dim(kmText(km)));
    /* 「已识别」（认得出城市、算不出距离）是中性的灰标签；未收录的代码旁边已经写着「未收录」，不再标它 */
    if (label && info.known) coloLine.push(tag(label[0], label[1]));

    var coloNote = '';
    if (cls === 'far' && loc === 'CN') {
      coloNote = '中国大陆访客访问没有接入中国网络的站点时，常被调度到美国西海岸等远处机房，这是 Cloudflare 的调度策略，不是你的网络故障。';
    } else if (other) {
      coloNote = '本站查到的坐标属于另一条地址，不能用来估算这里的距离，只按国家判断远近。';
    } else if (lat === null || lon === null) {
      coloNote = '没有取到你的大致坐标，无法估算距离。';
    }
    fill(cells.colo, [line(coloLine), coloNote ? note(coloNote) : null]);

    renderVerdict(data, info, cls, km, other);
  }

  /* other：本站的位置记录属于另一条地址（见 renderMe），没有距离不是因为没取到，而是不能用 */
  function renderVerdict(data, info, cls, km, other) {
    var tone = cls === 'near' ? 'is-good' : cls === 'far' ? 'is-warn' : 'is-info';
    var name = coloTitle(info);
    /* 「马德里（MAD）节点」括号后不再空格；裸代码「XYZ 节点」要空一格 */
    var title = '命中 Cloudflare ' + name + (/）$/.test(name) ? '节点' : ' 节点');
    var parts = [];
    var where = km !== null ? '节点距你' + kmText(km) + '，' : '';
    var sameCountry = !!info.cc && info.cc === String(data.loc || '').toUpperCase();

    /* 超出距离档、却因为同国或周边表升了档的，把理由说出来：
       「约 1,243 公里，属于就近接入」不解释的话，读的人会以为本页的 1000 公里是随口说的 */
    if (cls === 'near' && km !== null && km > P.NEAR_KM) {
      parts.push(where + (sameCountry
        ? '与你的出口在同一个国家/地区，属于就近接入，这是理想状态。'
        : '是你所在地区的周边节点，属于就近接入——这已经是能给到的最近落点。'));
    } else if (cls === 'near') {
      parts.push(where + '属于就近接入，这是理想状态。');
    } else if (cls === 'region' && km !== null && km > P.REGION_KM) {
      parts.push(where + '但与你的出口在同一个国家/地区，属于区域内，延迟通常可以接受。');
    } else if (cls === 'region') {
      parts.push(where + '在同一区域内，延迟通常可以接受。');
    } else if (cls === 'far') {
      parts.push(where + '属于跨区接入：请求绕到了较远的机房，延迟会明显偏高。');
    } else if (!info.known) {
      parts.push('这个节点代码不在本站的对照表里，无法判断它在哪里。');
    } else if (other) {
      parts.push('本站查到的位置属于另一条地址，无法估算节点有多远。');
    } else {
      parts.push('没有取到你的大致坐标，无法估算节点有多远。');
    }

    if (warpLabel(data.warp)) {
      parts.push('当前经 WARP 访问，Cloudflare 看到的是 WARP 的出口，节点也按 WARP 出口调度。');
    }
    if (String(data.gateway).toLowerCase() === 'on') {
      parts.push('流量正经过 Zero Trust 网关。');
    }
    if (visibleIp && P.isIPv6(visibleIp) === P.isIPv6(data.ip) && !sameExit(visibleIp, data.ip)) {
      parts.push('另外，Cloudflare 看到的出口与本站看到的不同，访问 Cloudflare 的流量走了另一个出口。');
    }

    setVerdict(tone, title, parts.join(''));
  }

  /* 1.1.1.1：IP 字面量只能走 IPv4。它是 DNS / WARP 那张网络，和 CDN 的任播路由不是一回事——
     这里只报它看到的 IPv4 出口与落点，不拿它和主 trace 的节点比「IPv4 / IPv6 命中不同节点」，那个结论不成立。 */
  function renderIpv4(result, main, colos) {
    if (!result.ok) {
      fill(cells.ipv4, [
        line([tag('不可达', 'muted'), dim(P.failureText(result.kind))]),
        note(result.kind === 'csp'
          ? '本页的 CSP 没有放行 1.1.1.1（部署问题）。'
          : '没有可用的 IPv4 连接（纯 IPv6 网络），或 1.1.1.1 在当前网络被屏蔽、劫持。不影响上面的结果。')
      ]);
      return;
    }

    var ip = result.data.ip;
    var nodes = [ipSpan(ip)];
    var text = '';
    var mainIp = main && main.data ? main.data.ip : '';

    if (visibleIp && !P.isIPv6(visibleIp)) {
      if (P.sameIp(ip, visibleIp)) {
        nodes.push(tag('与本站看到的一致', 'ok'));
      } else {
        nodes.push(tag('与本站看到的不同', 'warn'));
        text = '访问 1.1.1.1 与访问本站走了不同的 IPv4 出口，说明有按目的地分流的规则。';
      }
    } else if (mainIp && !P.isIPv6(mainIp) && !P.sameIp(ip, mainIp)) {
      nodes.push(tag('与 ' + mainHost + ' 看到的不同', 'warn'));
      text = '访问 1.1.1.1 与访问 ' + mainHost + ' 走了不同的 IPv4 出口，说明有按目的地分流的规则。';
    }

    var info = P.colo(colos, result.data.colo);
    fill(cells.ipv4, [
      line(nodes),
      line(coloNodes(info).concat([dim(result.ms + ' ms')])),
      text ? note(text) : null
    ]);
  }

  /* ---------------------------------------------------------------- 节点等级对比 */

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function svg(tagName, attrs) {
    var node = document.createElementNS(SVG_NS, tagName);
    for (var key in attrs) node.setAttribute(key, attrs[key]);
    return node;
  }

  /* 和首页评分条同一个思路（View::scoreBar）：长度用 <rect width> 表达，
     CSP 的 style-src 只有 'self'，style="width:…" 会被整条丢掉。viewBox 取 100，宽度即百分比 */
  function barNode(pct, speed) {
    var bar = svg('svg', { 'class': 'cfbar cfbar--' + speed, viewBox: '0 0 100 6', 'aria-hidden': 'true', focusable: 'false' });
    bar.appendChild(svg('rect', { 'class': 'cfbar__track', x: 0, y: 0, width: 100, height: 6, rx: 3 }));
    bar.appendChild(svg('rect', { 'class': 'cfbar__fill', x: 0, y: 0, width: pct, height: 6, rx: 3 }));
    return bar;
  }

  function speedOf(ms) {
    return ms < 80 ? 'good' : ms < 200 ? 'ok' : 'slow';
  }

  /* 一个网络：预热 1 次（不计时），再连续 3 次取最快。预热就失败的直接判不可达，不再白等三轮 */
  function measureTier(host) {
    return P.trace(host, TIMEOUT).then(function () {
      var best = null;
      var lastKind = 'error';
      var round = 0;

      var next = function () {
        if (round >= ROUNDS) {
          return best ? { ok: true, ms: best.ms, data: best.data } : { ok: false, kind: lastKind };
        }
        round++;
        return P.trace(host, TIMEOUT).then(function (result) {
          if (!best || result.ms < best.ms) best = result;
        }, function (failure) {
          lastKind = failure && failure.kind;
        }).then(next);
      };

      return next();
    }, function (failure) {
      return { ok: false, kind: failure && failure.kind };
    });
  }

  /* 延迟条以当前最慢的那个为满格：每出一个结果就整列重画一次 */
  function paintBars(results) {
    var max = 0;
    results.forEach(function (r) {
      if (r && r.ok && r.ms > max) max = r.ms;
    });
    results.forEach(function (r) {
      if (!r || !r.ok) return;
      var pct = Math.max(4, Math.round(100 * r.ms / (max || 1)));
      fill(r.latCell, [
        barNode(pct, speedOf(r.ms)),
        P.el('span', 'cftier__ms mono', r.ms + ' ms'),
        P.el('span', 'cftier__proto', httpInfo(r.data.http).short)
      ]);
    });
  }

  function renderTier(r, colos) {
    if (!r.ok) {
      fill(r.nodeCell, [tag('不可达', 'muted')]);
      fill(r.latCell, [dim(P.failureText(r.kind))]);
      return;
    }

    var info = P.colo(colos, r.data.colo);
    var nodes = coloNodes(info);

    /* 中国网络只对中国大陆访客生效：loc=CN 却落在境外，是「没命中中国网络」，不是错误 */
    if (r.net === 'cn' && String(r.data.loc).toUpperCase() === 'CN') {
      nodes.push(info.cc === 'CN' ? tag('命中境内节点', 'ok') : tag('未命中中国网络', 'muted'));
    }

    fill(r.nodeCell, [line(nodes)]);
  }

  function summarize(results, colos) {
    var ok = results.filter(function (r) { return r.ok; });
    var failed = results.filter(function (r) { return !r.ok; });
    var lines = [];

    if (!ok.length) {
      fill(tierSum, [P.el('span', 'cftier__sumline', '所有网络都不可达：cdn-cgi/trace 很可能被浏览器扩展、代理或网关拦截了。')]);
      return;
    }

    var groups = [];
    var byCode = {};
    ok.forEach(function (r) {
      var code = String(r.data.colo || '').toUpperCase();
      if (!byCode[code]) {
        byCode[code] = { info: P.colo(colos, code), names: [] };
        groups.push(byCode[code]);
      }
      byCode[code].names.push(r.name);
    });

    if (groups.length === 1) {
      lines.push((ok.length > 1 ? '全部 ' + ok.length + ' 个网络都命中 ' : '命中 ') + coloTitle(groups[0].info)
        + (ok.length > 1 ? '：调度一致，这是理想状态。' : '。'));
    } else {
      lines.push(ok.length + ' 个网络分布在 ' + groups.length + ' 个节点：');
      groups.forEach(function (g) {
        lines.push(coloTitle(g.info) + '：' + g.names.join('、'));
      });
    }

    var fastest = ok[0];
    var slowest = ok[0];
    ok.forEach(function (r) {
      if (r.ms < fastest.ms) fastest = r;
      if (r.ms > slowest.ms) slowest = r;
    });
    if (ok.length > 1) {
      lines.push('最快 ' + fastest.name + ' ' + fastest.ms + ' ms，最慢 ' + slowest.name + ' ' + slowest.ms + ' ms。');
    }

    if (failed.length) {
      lines.push(failed.length + ' 个不可达：' + failed.map(function (r) { return r.name; }).join('、')
        + '。个别网络不通多半是被扩展或分流规则拦了，不影响其余结果。');
    }

    fill(tierSum, lines.map(function (text) { return P.el('span', 'cftier__sumline', text); }));
  }

  function runTiers(colos) {
    var queue = P.queue(LANES);
    var results = [];
    var finished = 0;

    fill(tierSum, [dim('正在对比…')]);

    return Promise.all(tierRows.map(function (row, index) {
      var nameNode = row.querySelector('.cftier__name');
      var nodeCell = row.querySelector('[data-cf-tier-node]');

      return queue.add(function () {
        fill(nodeCell, [dim('检测中…')]);
        return measureTier(row.getAttribute('data-host'));
      }).then(function (outcome) {
        /* net 是网络类型（ent / cn / …，来自 data-kind），kind 沿用 probe.js 的约定，是失败原因 */
        var r = {
          name: nameNode ? nameNode.textContent : row.getAttribute('data-host'),
          net: row.getAttribute('data-kind'),
          nodeCell: nodeCell,
          latCell: row.querySelector('[data-cf-tier-lat]'),
          ok: outcome.ok,
          ms: outcome.ms,
          data: outcome.data,
          kind: outcome.kind
        };
        results[index] = r;
        renderTier(r, colos);
        paintBars(results);
        finished++;
        progress.textContent = '正在对比 ' + tierRows.length + ' 个网络：已完成 ' + finished + ' / ' + tierRows.length;
      });
    })).then(function () {
      summarize(results, colos);
    });
  }

  /* ---------------------------------------------------------------- 主流程 */

  var running = false;

  function reset() {
    verdict.hidden = true;
    ipNodes = visibleEntry ? [visibleEntry] : [];
    rawText = '';
    paintRaw();
    CELL_KEYS.forEach(function (key) {
      fill(cells[key], [dim('检测中…')]);
    });
    /* 重测时上一轮的节点与延迟立刻清掉，免得主 trace 还没回来时表格里摆着旧结果 */
    tierRows.forEach(function (row) {
      fill(row.querySelector('[data-cf-tier-node]'), [dim('排队中…')]);
      fill(row.querySelector('[data-cf-tier-lat]'), []);
    });
    fill(tierSum, [dim('等待主 trace…')]);
  }

  function run() {
    if (running) return;
    running = true;
    runButton.disabled = true;
    var started = P.now();
    reset();
    progress.textContent = '正在读取 ' + mainHost + ' 的 trace…';

    var colosReady = P.iata(iataUrl);
    /* 同源的小请求，和主 trace 一起发：主 trace 回来时它多半已经到了。每轮都重新问——
       两次检测之间切换代理、换网络正是这一页的常见用法，上一轮的地址不能留到这一轮用 */
    var meReady = fetchMe();

    /* 主 trace 出结果之后，1.1.1.1 与等级对比同时开跑：
       1.1.1.1 在一些网络里被黑洞，要等满超时——
       排在对比表前面的话，整页会白白多等六秒。并发多出的这个请求很小，
       等级对比本身先预热、再取三次最快，对它引起的抖动不敏感。 */
    mainTrace().then(function (main) {
      rawText = main.text || '';
      paintRaw();
      return colosReady.then(function (colos) {
        renderMain(main, colos);
        return Promise.all([
          meReady.then(function (me) { renderMe(main, me, colos); }),
          traceIpv4().then(function (result) { renderIpv4(result, main, colos); }),
          runTiers(colos)
        ]);
      });
    }, function (failure) {
      renderMainFailure(failure);
      return colosReady.then(function (colos) {
        return Promise.all([
          traceIpv4().then(function (result) { renderIpv4(result, null, colos); }),
          runTiers(colos)
        ]);
      });
    }).then(function () {
      progress.textContent = '检测完成，用时 ' + ((P.now() - started) / 1000).toFixed(1) + ' 秒。';
    }, function () {
      /* 渲染代码自己出了错：至少把按钮还回去，别让页面停在「检测中」 */
      progress.textContent = '检测中断，请点击「重新检测」再试一次。';
    }).then(function () {
      running = false;
      runButton.disabled = false;
    });
  }

  /* 页面一打开就自动跑，按钮从此只承担「再测一次」 */
  runButton.textContent = '重新检测';
  runButton.addEventListener('click', run);
  run();
})();
