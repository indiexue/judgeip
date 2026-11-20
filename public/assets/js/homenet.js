/* JudgeIP — 首页「本机网络」：IPv4 / IPv6 双栈出口 + 命中的 Cloudflare 节点、协议与 WARP。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   三件事并行，各自填各自的行：
   - IPv4：问一个只有 A 记录的接口（api4.ipify.org），它回显的就是你的 IPv4 出口；
   - IPv6：同理问只有 AAAA 记录的 api6.ipify.org，连不上就是没有可用的 IPv6；
   - Cloudflare：speed.cloudflare.com 的一次 trace，取节点、HTTP / TLS 版本与 WARP 状态。
   接口地址从 data-* 读，与 CSP 放行的源出自同一份 PHP 常量（CloudflareNode）。

   等页面安顿下来才动手（见 whenSettled）：不和首屏的样式、图片抢连接，
   也不被统计、Turnstile 这类慢吞吞的第三方脚本拖住。
   结果只留在当前页面里，不回传本站。 */
(function () {
  'use strict';

  var root = document.querySelector('[data-homenet]');
  if (!root) return;

  var P = window.IpcxProbe;

  var TIMEOUT = 5000;

  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var iataUrl = root.getAttribute('data-iata') || '';
  var traceHost = root.getAttribute('data-trace') || '';
  var endpoints = {
    v4: (root.getAttribute('data-v4') || '').split(' ').filter(Boolean),
    v6: (root.getAttribute('data-v6') || '').split(' ').filter(Boolean)
  };

  var V4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  var V6 = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;

  function cell(key) {
    return root.querySelector('[data-net="' + key + '"] .row__value');
  }

  /* 检测做不了时把「检测中」换成一句实话，别让它永远转下去。两种原因的出路不同，分开说：
     probe.js 没加载上（网络抖了一下、被扩展拦了）刷新多半就好；浏览器太旧则刷新也没用。
     完整的那句话只写在第一行，其余几行写「未检测」——五行重复同一句长话，反而让人找不到重点。 */
  function unavailable(message) {
    ['v4', 'v6', 'colo', 'proto', 'warp'].forEach(function (key, i) {
      var c = cell(key);
      if (!c) return;
      c.textContent = '';
      var span = document.createElement('span');
      span.className = 'geo__note';
      span.textContent = i === 0 ? message : '未检测';
      c.appendChild(span);
    });
  }

  if (!P) {
    unavailable('检测脚本加载失败，请刷新页面重试');
    return;
  }

  if (!window.fetch || !window.Promise) {
    unavailable('当前浏览器太旧，无法检测');
    return;
  }

  /* ---------------------------------------------------------------- 小工具 */

  function fill(target, nodes) {
    if (!target) return;
    target.textContent = '';
    nodes.forEach(function (node) {
      if (node) target.appendChild(node);
    });
  }

  /* 首页不加载 cloudflare.css，并排的几段直接借 app.css 的 .tags（inline-flex + gap） */
  function group(nodes) {
    var wrap = P.el('span', 'tags');
    nodes.forEach(function (node) {
      if (node) wrap.appendChild(node);
    });
    return wrap;
  }

  function tag(text, tone) {
    return P.el('span', 'tag tag--' + tone, text);
  }

  function note(text) {
    return P.el('span', 'geo__note', text);
  }

  /* ---------------------------------------------------------------- 隐藏 IP

     首页 IP 卡片的遮罩按钮（app.js）只管卡片里那一个地址；这里的 IPv4 / IPv6 往往就是同一个地址，
     卡片藏了、这两行却还亮着，截图照样露底。所以跟着那枚按钮的状态走：它是唯一的开关，这里只读不写。
     app.js 的点击处理先注册、先执行，等它改完 aria-pressed 再读，用 setTimeout 0 兜住顺序。 */
  var ipNodes = [];

  function maskIp(value) {
    if (value.indexOf(':') !== -1) return value.split(':').slice(0, 2).join(':') + ':*:*';
    var octets = value.split('.');
    return octets.length === 4 ? octets[0] + '.' + octets[1] + '.*.*' : '*.*.*.*';
  }

  function isMasked() {
    var button = document.querySelector('[data-mask-toggle]');
    return !!button && button.getAttribute('aria-pressed') === 'true';
  }

  function paintIp(entry) {
    entry.node.textContent = isMasked() ? maskIp(entry.ip) : entry.ip;
  }

  function ipSpan(ip) {
    var entry = { node: P.el('span', 'mono'), ip: ip };
    ipNodes.push(entry);
    paintIp(entry);
    return entry.node;
  }

  document.addEventListener('click', function (event) {
    var target = event.target;
    if (!target || !target.closest || !target.closest('[data-mask-toggle]')) return;
    window.setTimeout(function () { ipNodes.forEach(paintIp); }, 0);
  });

  /* ---------------------------------------------------------------- 双栈 */

  var samePrefix64 = P.samePrefix64;

  /* ipify 回 {"ip":"…"}，icanhazip 回一行纯文本；两种都认 */
  function parseIp(text) {
    var value = String(text || '').trim();
    if (value.charAt(0) === '{') {
      try {
        value = String(JSON.parse(value).ip || '');
      } catch (e) {
        value = '';
      }
    }
    return value.trim();
  }

  /* 主接口失败再问备用——但只在「很快失败」时（多半是被广告拦截扩展拦了）。
     主接口超时说明这一族本身不通，再问一家也是超时，只会让「未检测到」晚出现几秒。 */
  function lookup(urls, pattern) {
    var ask = function (url) {
      return P.text(url, {}, TIMEOUT).then(function (result) {
        var ip = result.response.ok ? parseIp(result.text) : '';
        return pattern.test(ip) ? ip : Promise.reject({ kind: 'error' });
      });
    };

    if (!urls.length) return Promise.resolve('');

    return ask(urls[0]).catch(function (failure) {
      if (urls.length < 2 || (failure && failure.kind === 'timeout')) return Promise.reject(failure);
      return ask(urls[1]);
    }).catch(function () {
      return '';
    });
  }

  function renderAddress(key, ip) {
    var isV6 = key === 'v6';
    var sameFamily = visibleIp !== '' && P.isIPv6(visibleIp) === isV6;

    if (!ip) {
      /* 接口没回，但访客正是经这一族访问的本站——那这一族显然是通的，用本站看到的地址补上 */
      if (sameFamily) {
        fill(cell(key), [group([ipSpan(visibleIp), note('本站看到的地址（检测接口未响应）')])]);
      } else {
        fill(cell(key), [note(isV6 ? '未检测到 IPv6 连接' : '未检测到 IPv4 连接')]);
      }
      return;
    }

    var nodes = [ipSpan(ip)];
    if (sameFamily) {
      if (P.sameIp(ip, visibleIp)) {
        nodes.push(tag('与本站看到的一致', 'ok'));
      } else if (samePrefix64(ip, visibleIp)) {
        /* IPv6 隐私地址：同一条线路上两次连接可能换了后 64 位，不是另一个出口 */
        nodes.push(tag('与本站同一 /64 网段', 'ok'));
      } else {
        /* 同族却不同：访问本站与访问外部走了不同出口（按域名分流、多出口代理）。跨族不比——那只是双栈各走各的 */
        nodes.push(tag('与本站看到的不同', 'warn'));
        nodes.push(note('访问外部网站走了另一个出口'));
      }
    }
    fill(cell(key), [group(nodes)]);
  }

  /* 「访问本站使用」那一行的地址族由服务端写好，这里只在后面补一个双栈 / 单栈的结论 */
  function renderFamily(v4, v6) {
    var target = cell('family');
    var wrap = target && target.querySelector('.tags');
    if (!wrap) return;

    var hasV6 = !!v6 || (visibleIp !== '' && P.isIPv6(visibleIp));
    var hasV4 = !!v4 || (visibleIp !== '' && !P.isIPv6(visibleIp));

    if (hasV4 && hasV6) wrap.appendChild(tag('双栈', 'ok'));
    else if (hasV4) wrap.appendChild(tag('仅 IPv4', 'muted'));
    else if (hasV6) wrap.appendChild(tag('仅 IPv6', 'muted'));
  }

  /* ---------------------------------------------------------------- Cloudflare */

  function httpLabel(value) {
    var h = String(value || '').toLowerCase();
    if (h === 'http/3') return 'HTTP/3';
    if (h === 'http/2') return 'HTTP/2';
    return h ? h.toUpperCase() : '';
  }

  function renderTrace(data, colos) {
    var info = P.colo(colos, data.colo);
    var flag = P.flag(info.cc);
    var more = P.el('a', 'asn-link dim', '详情 ›');
    more.href = '/cloudflare';

    fill(cell('colo'), [group(info.known
      ? [P.el('span', '', (flag ? flag + ' ' : '') + info.city), P.el('span', 'mono dim', info.code), more]
      : [P.el('span', 'mono', info.code || '未知'), more])]);

    /* HTTP/2 不标成问题：首次连接本来就是 HTTP/2，浏览器记住 Alt-Svc 之后才会改走 HTTP/3 */
    var proto = [httpLabel(data.http), String(data.tls || '').replace(/^TLSv/i, 'TLS ')].filter(Boolean).join(' · ');
    fill(cell('proto'), [group([
      P.el('span', 'mono', proto || '未知'),
      String(data.sni).toLowerCase() === 'encrypted' ? tag('ECH', 'ok') : null,
      /mlkem|kyber/i.test(data.kex || '') ? tag('后量子', 'ok') : null
    ])]);

    var warp = String(data.warp || '').toLowerCase();
    fill(cell('warp'), [group([
      warp === 'plus' ? tag('WARP+ 已开启', 'warn')
        : warp === 'on' ? tag('WARP 已开启', 'warn')
          : P.el('span', '', '未启用'),
      String(data.gateway).toLowerCase() === 'on' ? tag('Zero Trust 网关', 'warn') : null
    ])]);
  }

  function renderTraceFailure(failure) {
    var text = failure && failure.kind === 'csp' ? 'CSP 未放行' : 'Cloudflare 接口不可达';
    ['colo', 'proto', 'warp'].forEach(function (key) {
      fill(cell(key), [note(text)]);
    });
  }

  /* ---------------------------------------------------------------- 主流程 */

  /* 页面「安顿下来」：window 的 load 与「本脚本运行后 SETTLE_MS」两者谁先到算谁。
     只等 load 不行：load 要等所有 async 脚本（统计、Turnstile）都下载完，第三方一慢或被墙，
     这几行就一直停在「检测中」，最坏要等到 TCP 连接超时。defer 脚本在 DOMContentLoaded 前一刻运行，
     所以这个计时器差不多就是从 DOMContentLoaded 起算：正常情况下 load 早就到了，第三方卡住时最多晚这么久。
     connectivity.js 里有一份一模一样的，两块挨在首页上，要同时动手。 */
  var SETTLE_MS = 1500;

  function whenSettled(callback) {
    if (document.readyState === 'complete') {
      callback();
      return;
    }
    var done = false;
    var timer = 0;
    var go = function () {
      if (done) return;
      done = true;
      window.removeEventListener('load', go);
      window.clearTimeout(timer);
      callback();
    };
    window.addEventListener('load', go);
    timer = window.setTimeout(go, SETTLE_MS);
  }

  function start() {
    var colosReady = P.iata(iataUrl);

    var v4 = lookup(endpoints.v4, V4).then(function (ip) {
      renderAddress('v4', ip);
      return ip;
    });
    var v6 = lookup(endpoints.v6, V6).then(function (ip) {
      renderAddress('v6', ip);
      return ip;
    });
    Promise.all([v4, v6]).then(function (pair) {
      renderFamily(pair[0], pair[1]);
    });

    if (!traceHost) {
      renderTraceFailure(null);
      return;
    }
    P.trace(traceHost, TIMEOUT).then(function (result) {
      return colosReady.then(function (colos) {
        renderTrace(result.data, colos);
      });
    }).catch(renderTraceFailure);
  }

  whenSettled(start);
})();
