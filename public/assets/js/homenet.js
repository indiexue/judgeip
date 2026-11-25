/* JudgeIP — 首页「本机网络」+ 双栈自动优先主显 IPv4
   Cloudflare 边缘默认启用双栈（A + AAAA），双栈网络的浏览器会优先经 IPv6 访问本站。
   当检测到访客经 IPv6 连入且本机同时拥有可用公网 IPv4 时，自动把顶部「你的公网 IP」大卡片、
   「网络属性」、「地理位置」与「多库定位」全部无缝刷新为访客的 IPv4（与 ip.cx 默认显示 IPv4 保持一致），
   同时在「本机网络」栏完整保留 IPv4 与 IPv6 双栈地址。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };
  var lp = function (p) { return window.I18N ? I18N.path(p) : p; };

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
      span.textContent = i === 0 ? message : T('未检测', 'Not checked');
      c.appendChild(span);
    });
  }

  if (!P) {
    unavailable(T('检测脚本加载失败，请刷新页面重试', 'Failed to load the check script. Reload the page and try again'));
    return;
  }

  if (!window.fetch || !window.Promise) {
    unavailable(T('当前浏览器太旧，无法检测', 'This browser is too old to run the check'));
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

  var onMaskClick = function (event) {
    if (!root.isConnected) {
      document.removeEventListener('click', onMaskClick);
      return;
    }
    var target = event.target;
    if (!target || !target.closest || !target.closest('[data-mask-toggle]')) return;
    window.setTimeout(function () { ipNodes.forEach(paintIp); }, 0);
  };
  document.addEventListener('click', onMaskClick);
  document.addEventListener('judgeip:before-swap', function onLeave() {
    document.removeEventListener('click', onMaskClick);
    document.removeEventListener('judgeip:before-swap', onLeave);
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
        fill(cell(key), [group([ipSpan(visibleIp), note(T('本站看到的地址', 'Address seen by this site'))])]);
      } else {
        fill(cell(key), [note(isV6 ? T('未检测到 IPv6 连接', 'No IPv6 connection detected') : T('未检测到 IPv4 连接', 'No IPv4 connection detected'))]);
      }
      return;
    }

    var nodes = [ipSpan(ip)];
    if (sameFamily) {
      if (P.sameIp(ip, visibleIp)) {
        nodes.push(tag(T('与本站看到的一致', 'Same as seen by this site'), 'ok'));
      } else if (samePrefix64(ip, visibleIp)) {
        nodes.push(tag(T('与本站同一 /64 网段', 'Same /64 as seen by this site'), 'ok'));
      } else {
        nodes.push(tag(T('与本站看到的不同', 'Differs from what this site sees'), 'warn'));
        nodes.push(note(T('访问外部网站走了另一个出口', 'External sites are reached through a different exit')));
      }
    } else if (!isV6) {
      nodes.push(tag(T('当前默认展示', 'Shown by default'), 'ok'));
    }
    fill(cell(key), [group(nodes)]);
  }

  function renderFamily(v4, v6) {
    var target = cell('family');
    var wrap = target && target.querySelector('.tags');
    if (!wrap) return;

    var hasV6 = !!v6 || (visibleIp !== '' && P.isIPv6(visibleIp));
    var hasV4 = !!v4 || (visibleIp !== '' && !P.isIPv6(visibleIp));

    if (hasV4 && hasV6) wrap.appendChild(tag(T('双栈', 'Dual stack'), 'ok'));
    else if (hasV4) wrap.appendChild(tag(T('仅 IPv4', 'IPv4 only'), 'muted'));
    else if (hasV6) wrap.appendChild(tag(T('仅 IPv6', 'IPv6 only'), 'muted'));
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

  function ptrCell(info, cls) {
    if (info.ptrStatus === 'found' || (!info.ptrStatus && info.ptrRecord && info.ptrRecord !== '—')) {
      return '<span class="' + (cls || 'mono') + '">' + esc(info.ptrRecord) + '</span>';
    }
    return '<span class="geo__note">' + (info.ptrStatus === 'none' ? T('未设置', 'Not set') : T('查询失败', 'Lookup failed')) + '</span>';
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

    var SHORT_NAMES = { CN: T('中国大陆', 'Mainland China'), HK: T('中国香港', 'Hong Kong'), MO: T('中国澳门', 'Macau'), TW: T('中国台湾', 'Taiwan') };
    var regionNames = null;
    try {
      if (window.Intl && Intl.DisplayNames) regionNames = new Intl.DisplayNames([window.I18N ? I18N.locale : 'zh-CN'], { type: 'region' });
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
        c.appendChild(P.el('span', 'geo__note', noteText || T('库中无位置数据', 'No location in this database')));
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

  function scoreRiskTier(score, version, factors) {
    if (typeof score !== 'number') {
      return {
        cls: 'muted',
        badge: 'gray',
        label: T('暂未评分', 'No score'),
        desc: version === 6
          ? T('端口与黑名单数据仅覆盖 IPv4，暂不出综合分', 'Port and blocklist feeds cover IPv4 only')
          : T('部分公开数据源未及时返回，暂不出分', 'Some upstream sources did not respond in time')
      };
    }
    // 分级名称描述适用程度，说明写出最主要的扣分项（与服务端渲染一致）
    var top = (factors || []).filter(function (f) { return f.delta < 0 && f.key !== 'clamp'; }).sort(function (a, b) { return a.delta - b.delta; })[0];
    var desc = top
      ? T('主要扣分：' + top.status + '（' + top.delta + '）', 'Main deduction: ' + top.status + ' (' + top.delta + ')')
      : T('已查来源未见扣分项，不保证平台放行', 'No deductions in checked sources; platform acceptance is not guaranteed');
    if (score >= 90) return { cls: 'excellent', badge: 'green', label: T('优', 'Excellent'), desc: desc };
    if (score >= 80) return { cls: 'good', badge: 'green', label: T('良好', 'Good'), desc: desc };
    if (score >= 68) return { cls: 'ok', badge: 'green', label: T('一般', 'Fair'), desc: desc };
    if (score >= 50) return { cls: 'warn', badge: 'amber', label: T('受限', 'Restricted'), desc: desc };
    if (score >= 30) return { cls: 'bad', badge: 'danger', label: T('风险较高', 'Elevated risk'), desc: desc };
    return { cls: 'danger', badge: 'danger', label: T('高风险', 'High risk'), desc: desc };
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
    setFieldText('protoVersion', 'IPv4');
    setFieldText('cliCmd', 'curl -sL judgeip.com/' + v4);
    var cardLink = document.getElementById('share-card-link');
    if (cardLink) cardLink.href = lp('/card') + '?ip=' + encodeURIComponent(v4);
    var pfLink = document.getElementById('platforms-check-link');
    if (pfLink) pfLink.href = lp('/platforms') + '?ip=' + encodeURIComponent(v4);
    var cmpLink = document.getElementById('compare-ips-link');
    if (cmpLink) cmpLink.href = lp('/compare') + '?ips=' + encodeURIComponent(v4) + ',8.8.8.8,1.1.1.1';
    document.title = v4 + T(' 的 IP 归属与威胁情报查询 · JudgeIP', ': owner, network type and threat data · JudgeIP');

    window.fetch('/api/ipinfo?ip=' + encodeURIComponent(v4) + (window.I18N && I18N.lang === 'en' ? '&lang=en' : ''), {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' }
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (!res || !res.ok || !res.info) return;
        var info = res.info;

        setFieldHtml(
          'ipType',
          '<span class="badge badge--solid badge--' + esc(info.ipTypeTone) + '">' + esc(info.ipTypeLabel) + '</span>' +
          (info.isDualIsp ? '<span class="badge badge--solid badge--green">' + T('双 ISP', 'Dual ISP') + '</span>' : '') +
          (!info.isBogon
            ? '<span class="badge badge--solid badge--' + (info.isNative === null ? 'gray' : info.isNative ? 'green' : 'amber') + '">' + (info.isNative === null ? T('原生未知', 'Origin unknown') : info.isNative ? T('原生 IP', 'Native IP') : T('广播 IP', 'Geo-announced')) + '</span>'
            : '') +
          (info.isProxy ? '<span class="badge badge--solid badge--danger">' + esc(info.proxyLabel) + '</span>' : '')
        );
        setFieldText('isp', info.isp);
        setFieldText('org', info.org);
        if (info.asn) {
          setFieldHtml(
            'asn',
            '<a class="asn-link mono" href="' + lp('/whois') + '?q=' + esc(info.asnCode) + T('" title="查看 ', '" title="View registration data for ') + esc(info.asnCode) + T(' 注册信息">', '">') + esc(info.asnCode) + '</a>'
          );
        } else {
          setFieldText('asn', '—');
        }
        var domEl = document.querySelector('[data-field="domain"]');
        if (domEl) {
          domEl.textContent = info.domain || '—';
          domEl.hidden = !info.domain || info.domain === '—';
        }
        setFieldText('rirName', info.rirName);
        setFieldHtml('datacenter', info.isDatacenter ? '<span class="badge badge--danger">' + T('机房 / IDC', 'IDC / Hosting') + '</span>' : '');
        setFieldHtml('threat', '<span class="badge badge--' + (info.hasThreat === null ? 'gray' : info.hasThreat ? 'danger' : 'green') + '">' + esc(info.threatLabel) + '</span>');
        setFieldHtml('proxy', '<span class="badge badge--' + (info.isProxy === null ? 'gray' : info.isProxy ? 'amber' : 'green') + '">' + esc(info.proxyLabel) + '</span>');

        var tier = typeof info.score === 'number' && info.reputationCoverage !== 'complete' && info.hasThreat !== true
          ? { cls: 'muted', badge: 'gray', label: T('信誉证据不足', 'Limited reputation evidence'), desc: T('分数受证据上限限制；不代表已发现滥用，也不能判为纯净', 'Score capped for missing evidence; neither proof of abuse nor a clean verdict') }
          : scoreRiskTier(info.score, info.version, info.factors);
        var scoreEl = document.querySelector('[data-field="score"]');
        if (scoreEl) {
          scoreEl.className = 'hero-score__main is-' + tier.cls;
          scoreEl.innerHTML =
            '<span class="hero-score__num mono">' + (typeof info.score === 'number' ? Number(info.score) : '—') + '</span>' +
            '<div class="hero-score__verdict">' +
              '<span class="hero-score__pill badge badge--solid badge--' + tier.badge + '">' + esc(tier.label) + '</span>' +
              '<p class="hero-score__desc">' + esc(tier.desc) + '</p>' +
            '</div>';
        }
        var gradeEl = document.querySelector('[data-field="gradeBadge"]');
        if (gradeEl) {
          var confText = info.scoreConfidence === 'high' ? T('置信度 高', 'Confidence high')
            : info.scoreConfidence === 'medium' ? T('置信度 中', 'Confidence medium')
              : T('置信度 低', 'Confidence low');
          gradeEl.className = 'badge badge--' + (info.scoreConfidence === 'high' ? 'green' : typeof info.score === 'number' ? 'amber' : 'gray');
          gradeEl.textContent = typeof info.score === 'number' ? T('等级 ', 'Grade ') + info.grade + ' · ' + confText : T('数据源不可达', 'Unavailable');
        }
        var scoreSpectrum = document.querySelector('[data-field="scoreSpectrum"]');
        if (scoreSpectrum) scoreSpectrum.hidden = info.hasThreat === null;
        var specEl = document.querySelector('[data-field="spectrumThumb"]');
        if (specEl) {
          var oldThumb = specEl.querySelector('.spectrum__thumb');
          if (oldThumb) oldThumb.remove();
          if (typeof info.score === 'number') {
            var thumb = document.createElement('span');
            thumb.className = 'spectrum__thumb is-' + tier.cls;
            thumb.style.left = Math.max(2, Math.min(98, Number(info.score))) + '%';
            specEl.appendChild(thumb);
          }
        }
        if (Array.isArray(info.factors)) {
          var signDelta = function (d) { return d > 0 ? '+' + d : d < 0 ? '−' + Math.abs(d) : '0'; };
          var negs = info.factors.filter(function (f) { return f.delta < 0 && f.key !== 'clamp'; });
          var reasonsHtml = '';
          if (negs.length > 0) {
            reasonsHtml = negs.map(function (f) {
              return '<li class="hero-reasons__item ' + (f.key === 'coverage' ? 'is-muted' : 'is-bad') + '"><span class="hero-reasons__dot">' + (f.key === 'coverage' ? '·' : '×') + '</span><span>' + esc(f.label) + '：' + esc(f.status) + '（<span class="mono">' + signDelta(f.delta) + '</span>）</span></li>';
            }).join('');
          } else if (typeof info.score === 'number') {
            reasonsHtml =
              '<li class="hero-reasons__item is-good"><span class="hero-reasons__dot">✓</span><span>' + T('网络类型与注册归属核验正常，无扣分项', 'Network type and RIR origin verified with zero deductions') + '</span></li>' +
              '<li class="hero-reasons__item is-good"><span class="hero-reasons__dot">✓</span><span>' + T((info.dnsblTotal || 4) + ' 个 DNSBL 黑名单与威胁库均未命中', 'Clean across all ' + (info.dnsblTotal || 4) + ' DNSBLs and threat feeds') + '</span></li>';
          } else {
            reasonsHtml = '<li class="hero-reasons__item is-muted"><span class="hero-reasons__dot">·</span><span>' + esc(tier.desc) + '</span></li>';
          }
          setFieldHtml('heroReasons', reasonsHtml);
        }
        if (window.JudgeIPRankings) window.JudgeIPRankings(info);

        setFieldHtml(
          'country',
          (info.flagEmoji ? '<span class="flag">' + esc(info.flagEmoji) + '</span> ' : '') +
          '<strong>' + esc(info.countryZh) + '</strong>' +
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
          (info.localTimeHm ? '<span class="dim"> · </span><span class="mono">' + esc(info.localTimeHm) + '</span>' : '')
        );
        setFieldText('continent', info.continentZh);

        if (Array.isArray(info.scenes)) {
var scenesHtml = info.scenes.map(function (sc) {
return '<div class="scene-card is-' + esc(sc.tone) + '">' +
              '<div class="scene-card__top"><span class="scene-card__name">' + esc(sc.label) + '</span>' +
              '<span class="tag tag--' + esc(sc.tone) + '">' + esc(sc.status) + '</span></div>' +
              '<div class="scene-card__mid">' +
'<span class="scene-card__note">' + esc(sc.note) + '</span>' +
              '</div></div>';
          }).join('');
          setFieldHtml('scenes', scenesHtml || '<p class="geo__note">' + T('数据不足，暂不提供用途判断', 'Insufficient data for use-case estimates') + '</p>');
        }

        if (Array.isArray(info.factors)) {
          var sign = function (d) { return d > 0 ? '+' + d : d < 0 ? '−' + Math.abs(d) : '0'; };
          var factorsHtml = '<div class="factor factor--fixed"><span class="factor__name">' + T('基础分', 'Base score') +
            '</span><span class="factor__delta mono">' + esc(info.scoreBase) + '</span></div>' +
            info.factors.map(function (f) {
              var rows = (f.evidence || []).map(function (e) {
                return '<div class="factor__ev"><span>' + esc(e.source) + '</span><span class="mono">' + esc(e.field) +
                  '</span><span class="mono">' + esc(e.value) + '</span></div>';
              }).join('');
              return '<details class="factor"><summary><span class="factor__name">' + esc(f.label) + '</span>' +
                '<span class="tag tag--' + esc(f.tone) + '">' + esc(f.status) + '</span>' +
                '<span class="factor__delta mono' + (f.delta < 0 ? ' is-minus' : f.delta > 0 ? ' is-plus' : '') + '">' + sign(f.delta) + '</span></summary>' +
                '<div class="factor__body">' + (rows || '<p class="geo__note">' + T('这一项没有拿到原始数据', 'No raw data was returned for this item') + '</p>') + '</div></details>';
            }).join('') +
            '<div class="factor factor--fixed factor--total"><span class="factor__name">' + T('最终得分', 'Final score') + '</span>' +
            (info.score === null || info.score === undefined
              ? '<span class="factor__note">' + T('有数据源未返回，暂不出分', 'A data source did not respond, so no score is given') + '</span>'
              : '<span class="factor__delta mono">' + esc(info.score) + ' · ' + esc(info.grade) + '</span>') + '</div>';
          setFieldHtml('factors', factorsHtml);
        }

        if (Array.isArray(info.riskChecks)) {
          var rtHtml = info.riskChecks.map(function (rc) {
            return '<div class="row"><span class="row__label">' + esc(rc.label) + '</span>' +
              '<span class="row__value"><span class="tag tag--' + esc(rc.tone) + '">' + esc(rc.status) + '</span></span></div>';
          }).join('');
          var bgpCell = info.bgpPrefix && info.bgpPrefix !== '—'
            ? '<a class="asn-link mono" href="' + lp('/ip-calc') + '?q=' + encodeURIComponent(info.bgpPrefix) + '">' + esc(info.bgpPrefix) + '</a>'
            : '<span class="mono">—</span>';
          var rpkiTone = info.rpkiStatus === 'valid' ? 'ok' : info.rpkiStatus === 'invalid' ? 'leak' : 'muted';
          var portsCell = info.openPorts && info.openPorts.length > 0
            ? '<span class="mono">' + esc(info.openPorts.join(', ')) + '</span>'
            : '<span class="geo__note">' + (info.version !== 4 ? T('仅支持 IPv4', 'IPv4 only') : !info.portsKnown ? T('端口数据未取得', 'Port data unavailable') : T('已查来源未见开放端口', 'No open ports in checked source')) + '</span>';
          rtHtml +=
            T('<div class="row"><span class="row__label">BGP 路由前缀</span><span class="row__value">', '<div class="row"><span class="row__label">BGP prefix</span><span class="row__value">') + bgpCell + '</span></div>' +
            T('<div class="row"><span class="row__label">RPKI 路由授权</span><span class="row__value"><span class="tag tag--', '<div class="row"><span class="row__label">RPKI</span><span class="row__value"><span class="tag tag--') + rpkiTone + '">' + esc(info.rpkiLabel) + '</span></span></div>' +
            T('<div class="row"><span class="row__label">反向解析 (PTR)</span><span class="row__value"><span class="mono">', '<div class="row"><span class="row__label">Reverse DNS (PTR)</span><span class="row__value">') + ptrCell(info) + '</span></div>' +
            T('<div class="row"><span class="row__label">开放服务端口</span><span class="row__value">', '<div class="row"><span class="row__label">Open ports</span><span class="row__value">') + portsCell + '</span></div>';
          if (info.abuseEmail && info.abuseEmail !== '—') {
            rtHtml += T('<div class="row"><span class="row__label">滥用举报邮箱</span><span class="row__value"><span class="mono">', '<div class="row"><span class="row__label">Abuse contact</span><span class="row__value"><span class="mono">') + esc(info.abuseEmail) + '</span></span></div>';
          }
          setFieldHtml('riskTech', rtHtml);
        }

        if (Array.isArray(info.dnsblChecks) && info.dnsblChecks.length > 0) {
          var chips = info.dnsblChecks.map(function (c) {
            var icon = c.status === 'not_listed' ? '✓' : c.status === 'listed' ? '×' : '?';
            return '<span class="dnsbl-chip is-' + esc(c.status) + '"><span class="dnsbl-chip__icon">' + icon + '</span><span>' + esc(c.name) + '</span></span>';
          }).join('');
          setFieldHtml('dnsblStrip', '<span class="dnsbl-strip__label">' + T('黑名单实时核验', 'Live DNSBLs') + '</span><div class="dnsbl-strip__chips">' + chips + '</div>');
        }
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
    var more = P.el('a', 'asn-link dim', T('详情 ›', 'Details ›'));
    more.href = lp('/cloudflare');

    fill(cell('colo'), [group(info.known
      ? [P.el('span', '', (flag ? flag + ' ' : '') + info.city), P.el('span', 'mono dim', info.code), more]
      : [P.el('span', 'mono', info.code || T('未知', 'Unknown')), more])]);

    var proto = [httpLabel(data.http), String(data.tls || '').replace(/^TLSv/i, 'TLS ')].filter(Boolean).join(' · ');
    fill(cell('proto'), [group([
      P.el('span', 'mono', proto || T('未知', 'Unknown')),
      String(data.sni).toLowerCase() === 'encrypted' ? tag('ECH', 'ok') : null,
      /mlkem|kyber/i.test(data.kex || '') ? tag(T('后量子', 'Post-quantum'), 'ok') : null
    ])]);

    var warp = String(data.warp || '').toLowerCase();
    fill(cell('warp'), [group([
      warp === 'plus' ? tag(T('WARP+ 已开启', 'WARP+ on'), 'warn')
        : warp === 'on' ? tag(T('WARP 已开启', 'WARP on'), 'warn')
          : P.el('span', '', T('未启用', 'Off')),
      String(data.gateway).toLowerCase() === 'on' ? tag(T('Zero Trust 网关', 'Zero Trust gateway'), 'warn') : null
    ])]);
  }

  function renderTraceFailure(failure) {
    var text = failure && failure.kind === 'csp' ? T('CSP 未放行', 'Blocked by CSP') : T('Cloudflare 接口不可达', 'Cloudflare endpoint unreachable');
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
