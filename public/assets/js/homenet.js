/* JudgeIP — 首页「本机网络」+ 双栈自动优先主显 IPv4
   Cloudflare 边缘默认启用双栈（A + AAAA），双栈网络的浏览器会优先经 IPv6 访问本站。
   当检测到访客经 IPv6 连入且本机同时拥有可用公网 IPv4 时，自动把顶部「你的公网 IP」大卡片、
   「网络属性」、「地理位置」与「多库定位」全部无缝刷新为访客的 IPv4（与 ip.cx 默认显示 IPv4 保持一致），
   同时在「本机网络」栏完整保留 IPv4 与 IPv6 双栈地址。 */
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

  function fill(target, nodes) {
    if (!target) return;
    target.textContent = '';
    nodes.forEach(function (node) {
      if (node) target.appendChild(node);
    });
  }

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

  var samePrefix64 = P.samePrefix64;

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

  function lookupChain(urls, pattern, idx) {
    var i = idx || 0;
    if (i >= urls.length) return Promise.resolve('');
    return P.text(urls[i], {}, TIMEOUT).then(function (result) {
      var ip = result.response.ok ? parseIp(result.text) : '';
      if (pattern.test(ip)) return ip;
      return lookupChain(urls, pattern, i + 1);
    }).catch(function (failure) {
      if (failure && failure.kind === 'timeout' && i >= 1) return '';
      return lookupChain(urls, pattern, i + 1);
    });
  }

  function renderAddress(key, ip) {
    var isV6 = key === 'v6';
    var sameFamily = visibleIp !== '' && P.isIPv6(visibleIp) === isV6;

    if (!ip) {
      if (sameFamily) {
        fill(cell(key), [group([ipSpan(visibleIp), note('本站看到的地址')])]);
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
        nodes.push(tag('与本站同一 /64 网段', 'ok'));
      } else {
        nodes.push(tag('与本站看到的不同', 'warn'));
        nodes.push(note('访问外部网站走了另一个出口'));
      }
    } else if (!isV6) {
      nodes.push(tag('当前默认展示', 'ok'));
    }
    fill(cell(key), [group(nodes)]);
  }

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

  /* ---------------------------------------------------------------- 当首屏是 IPv6 时，自动把顶部卡片与属性表切换为公网 IPv4 */

  function setFieldHtml(name, html) {
    var el = document.querySelector('[data-field="' + name + '"]');
    if (el) el.innerHTML = html;
  }

  function setFieldText(name, text) {
    var el = document.querySelector('[data-field="' + name + '"]');
    if (el) el.textContent = text;
  }

  function esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function refreshMultiGeoForIp(v4) {
    var geoSec = document.querySelector('[data-geo]');
    if (!geoSec) return;
    geoSec.setAttribute('data-ip', v4);

    var SHORT_NAMES = { CN: '中国大陆', HK: '中国香港', MO: '中国澳门', TW: '中国台湾' };
    var regionNames = null;
    try {
      if (window.Intl && Intl.DisplayNames) regionNames = new Intl.DisplayNames(['zh-CN'], { type: 'region' });
    } catch (e) { regionNames = null; }

    function countryLabel(code) {
      if (!/^[A-Z]{2}$/.test(code || '')) return '';
      var flag = String.fromCodePoint
        ? String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65, 0x1F1E6 + code.charCodeAt(1) - 65) + ' '
        : '';
      var name = SHORT_NAMES[code] || code;
      if (!SHORT_NAMES[code]) {
        try { name = (regionNames && regionNames.of(code)) || code; } catch (e) { name = code; }
      }
      return flag + name;
    }

    function fillGeoRow(key, place, noteText) {
      var c = geoSec.querySelector('[data-geo-source="' + key + '"] .row__value');
      if (!c) return;
      var parts = [];
      if (place) {
        var cnt = countryLabel((place.country || '').toUpperCase());
        var reg = place.region || '';
        var cty = place.city || '';
        if (cnt) parts.push(cnt);
        if (reg) parts.push(reg);
        if (cty && cty.toLowerCase() !== reg.toLowerCase()) parts.push(cty);
      }
      c.textContent = '';
      if (!parts.length) {
        c.appendChild(P.el('span', 'geo__note', noteText || '库中无位置数据'));
        return;
      }
      for (var i = 0; i < parts.length; i++) {
        if (i > 0) {
          var sep = P.el('span', 'geo__sep', '/');
          sep.setAttribute('aria-hidden', 'true');
          c.appendChild(sep);
        }
        c.appendChild(P.el('span', '', parts[i]));
      }
    }

    window.fetch('/geo/api?ip=' + encodeURIComponent(v4), {
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-Requested-With': 'ipcx' }
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data || !data.ok || !data.sources) return;
        ['ip2location', 'dbip', 'ipinfo', 'maxmind'].forEach(function (key) {
          var item = data.sources[key];
          if (item && item.status === 'ok') fillGeoRow(key, item, '');
        });
      })
      .catch(function () {});
  }

  function promoteIpv4ToMainCard(v4) {
    var currentIpEl = document.getElementById('current-ip');
    if (currentIpEl) {
      if (isMasked()) {
        currentIpEl.setAttribute('data-copy-value', v4);
        currentIpEl.textContent = maskIp(v4);
      } else {
        currentIpEl.removeAttribute('data-copy-value');
        currentIpEl.textContent = v4;
      }
    }
    document.title = v4 + ' 的 IP 归属与威胁情报查询 · JudgeIP';

    window.fetch('/api/ipinfo?ip=' + encodeURIComponent(v4), {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' }
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (!res || !res.ok || !res.info) return;
        var info = res.info;

        setFieldHtml(
          'ipType',
          '<span class="badge badge--' + esc(info.ipTypeTone) + '">' + esc(info.ipTypeLabel) + '</span>' +
          (!info.isBogon
            ? '<span class="badge badge--' + (info.isNative ? 'green' : 'amber') + '" style="margin-left:6px;">' + (info.isNative ? '原生 IP' : '广播 IP') + '</span>'
            : '')
        );
        setFieldText('isp', info.isp);
        setFieldText('org', info.org);
        if (info.asn) {
          setFieldHtml(
            'asn',
            '<a class="asn-link mono" href="/whois?q=' + esc(info.asnCode) + '" title="查看 ' + esc(info.asnCode) + ' 注册信息">' + esc(info.asnCode) + '</a>' +
            '<span class="botratio"><span class="botratio__bracket">[</span><span class="botratio__human">Human ' + esc(info.humanPct) + '</span><span class="botratio__sep">|</span><span class="botratio__bot">Bot ' + esc(info.botPct) + '</span><span class="botratio__bracket">]</span></span>'
          );
        }
        setFieldText('domain', info.domain);
        setFieldText('rirName', info.rirName);
        setFieldHtml('datacenter', '<span class="badge badge--' + (info.isDatacenter ? 'danger' : 'green') + '">' + (info.isDatacenter ? '是' : '否') + '</span>');
        setFieldHtml('threat', '<span class="badge badge--' + (info.hasThreat ? 'danger' : 'green') + '">' + esc(info.threatLabel) + '</span>');
        setFieldHtml('proxy', '<span class="badge badge--' + (info.isProxy ? 'amber' : 'green') + '">' + esc(info.proxyLabel) + '</span>');
        setFieldHtml(
          'score',
          '<span class="score score--' + esc(info.scoreTone) + '">' +
          '<svg class="score__bar" viewBox="0 0 100 6" role="img" aria-label="IP 评分 ' + Number(info.score) + ' 分，满分 100 分">' +
          '<rect class="score__track" x="0" y="0" width="100" height="6" rx="3"></rect>' +
          '<rect class="score__fill" x="0" y="0" width="' + Number(info.score) + '" height="6" rx="3"></rect></svg>' +
          '<span class="score__num mono">' + Number(info.score) + '<span class="score__total">/100</span></span></span>'
        );

        setFieldHtml(
          'country',
          (info.flagEmoji ? '<span class="flag">' + esc(info.flagEmoji) + '</span> ' : '') +
          esc(info.countryZh) +
          (info.countryCode ? ' <span class="dim mono">' + esc(info.countryCode) + '</span>' : '')
        );
        setFieldText('region', info.region);
        setFieldText('city', info.city);
        setFieldHtml(
          'coords',
          '<span class="mono">' + (info.latitude !== null && info.longitude !== null ? esc(info.latitude + ', ' + info.longitude) : '—') + '</span>'
        );
        setFieldHtml(
          'timezone',
          '<span class="mono">' + esc(info.timezone) + '</span>' +
          (info.localTimeHm ? '<span class="dim"> · 当地 </span><span class="mono">' + esc(info.localTimeHm) + '</span>' : '')
        );
        setFieldText('continent', info.continentZh);
      })
      .catch(function () {});

    refreshMultiGeoForIp(v4);
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

  /* 若连接时是 IPv6，无需等待 1500ms，立即在首帧就去拿公网 IPv4 并替换主卡片！ */
  var initialIsV6 = visibleIp !== '' && P.isIPv6(visibleIp);

  function start() {
    var colosReady = P.iata(iataUrl);

    var v4Promise = lookupChain(endpoints.v4, V4, 0).then(function (ip) {
      if (ip && initialIsV6) {
        promoteIpv4ToMainCard(ip);
      }
      renderAddress('v4', ip);
      return ip;
    });

    var v6Promise = lookupChain(endpoints.v6, V6, 0).then(function (ip) {
      renderAddress('v6', ip);
      return ip;
    });

    Promise.all([v4Promise, v6Promise]).then(function (pair) {
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

  if (initialIsV6) {
    start();
  } else if (document.readyState === 'complete') {
    start();
  } else {
    var settled = false;
    var go = function () {
      if (settled) return;
      settled = true;
      start();
    };
    window.addEventListener('load', go);
    window.setTimeout(go, 800);
  }
})();
