/* JudgeIP — 实时多数据源流式聚合查询（/ 与 /ip/<ip>）。
   提交搜索框或点击「重新聚合」时，立即将 Hero 大卡片切为 IPFinal 同款骨架屏 + 右侧多源聚合进度面板，
   通过 /api/ipinfo/stream 逐行读取每个上游数据源的真实完成状态并点亮对应徽标、推进进度条与秒表，
   聚合完成后无刷新更新整页全部卡片（含评分、场景圆环、证据明细、风险路由、多库定位）并同步 URL。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };
  var lp = function (p) { return window.I18N ? window.I18N.path(p) : p; };
  var isEn = !!(window.I18N && window.I18N.lang === 'en');

  var heroBox = document.getElementById('ip-hero');
  var form = document.querySelector('[data-ip-search-form]');
  if (!heroBox || !form || !window.fetch || !window.ReadableStream) return;

  var searchInput = form.querySelector('[data-ip-search-input]');
  var searchBtn = form.querySelector('[data-ip-search-btn]');
  var refreshBtn = document.querySelector('[data-ip-refresh]');
  var errorBox = document.querySelector('[data-search-error]');
  var errorText = document.querySelector('[data-search-error-text]');

  var aggTitle = heroBox.querySelector('[data-agg-title]');
  var aggElapsed = heroBox.querySelector('[data-agg-elapsed]');
  var aggBar = heroBox.querySelector('[data-agg-bar]');
  var aggChips = heroBox.querySelectorAll('[data-agg-source]');
  var totalSources = aggChips.length || 10;

  var activeController = null;
  var elapsedTimer = null;

  function esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function maskIp(value) {
    if (value.indexOf(':') !== -1) return value.split(':').slice(0, 2).join(':') + ':*:*';
    var octets = value.split('.');
    return octets.length === 4 ? octets[0] + '.' + octets[1] + '.*.*' : '*.*.*.*';
  }

  function isMasked() {
    var button = document.querySelector('[data-mask-toggle]');
    return !!button && button.getAttribute('aria-pressed') === 'true';
  }

  function setFieldHtml(name, html) {
    var el = document.querySelector('[data-field="' + name + '"]');
    if (el) el.innerHTML = html;
  }

  function setFieldText(name, text) {
    var el = document.querySelector('[data-field="' + name + '"]');
    if (el) el.textContent = text;
  }

  function showError(msg) {
    if (!errorBox || !errorText) return;
    if (!msg) {
      errorBox.hidden = true;
      errorText.textContent = '';
    } else {
      errorText.textContent = msg;
      errorBox.hidden = false;
    }
  }

  function scoreRiskTier(score, version) {
    if (typeof score !== 'number') {
      return {
        cls: 'muted',
        badge: 'gray',
        label: T('暂未评分', 'No score'),
        desc: version === 6
          ? T('端口与黑名单数据仅覆盖 IPv4，暂不出综合分', 'Port and blocklist feeds cover IPv4 only')
          : T('基础归属或风险数据源未返回，暂不出分', 'Core network or risk sources did not respond')
      };
    }
    if (score >= 90) return { cls: 'excellent', badge: 'green', label: T('已查风险较少', 'Few observed risks'), desc: T('仅反映已查来源，不能保证平台放行', 'Checked sources only; platform acceptance is not guaranteed') };
    if (score >= 80) return { cls: 'good', badge: 'green', label: T('纯净', 'Clean'), desc: T('已查信号有限，不代表没有滥用记录', 'Limited observed signals do not rule out abuse') };
    if (score >= 68) return { cls: 'ok', badge: 'green', label: T('正常', 'Normal'), desc: T('规则参考分，请结合信誉覆盖与原始证据', 'Rule-based estimate; review coverage and raw evidence') };
    if (score >= 50) return { cls: 'warn', badge: 'amber', label: T('低风险', 'Low risk'), desc: T('信誉证据可能不足，或存在网络与风险标记', 'Reputation evidence may be limited, or risk flags were found') };
    if (score >= 30) return { cls: 'bad', badge: 'danger', label: T('中风险', 'Medium risk'), desc: T('已查风险或证据缺口较大，使用前需核实', 'Risk flags or material evidence gaps; verify before use') };
    return { cls: 'danger', badge: 'danger', label: T('高风险', 'High risk'), desc: T('已查证据触发高风险规则，建议核对来源', 'Observed evidence triggered high-risk rules; review the sources') };
  }

  function refreshMultiGeo(ip) {
    var geoSec = document.querySelector('[data-geo]');
    if (!geoSec) return;
    geoSec.setAttribute('data-ip', ip);

    var cfVal = geoSec.querySelector('[data-geo-source="cloudflare"] .row__value');
    if (cfVal) {
      cfVal.innerHTML = '<span class="geo__note">' + T('仅支持查询本机 IP', 'Only your own IP can be looked up') + '</span>';
    }
    ['maxmind', 'ipinfo', 'ip2location', 'dbip'].forEach(function (k) {
      var v = geoSec.querySelector('[data-geo-source="' + k + '"] .row__value');
      if (v) v.innerHTML = '<span class="geo__note">' + T('查询中…', 'Looking up…') + '</span>';
    });

    var SHORT_NAMES = { CN: T('中国大陆', 'Mainland China'), HK: T('中国香港', 'Hong Kong'), MO: T('中国澳门', 'Macau'), TW: T('中国台湾', 'Taiwan') };
    var regionNames = null;
    try {
      if (window.Intl && Intl.DisplayNames) regionNames = new Intl.DisplayNames([window.I18N ? window.I18N.locale : 'zh-CN'], { type: 'region' });
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
        var noteSpan = document.createElement('span');
        noteSpan.className = 'geo__note';
        noteSpan.textContent = noteText || T('库中无位置数据', 'No location in this database');
        c.appendChild(noteSpan);
        return;
      }
      for (var i = 0; i < parts.length; i++) {
        if (i > 0) {
          var sep = document.createElement('span');
          sep.className = 'geo__sep';
          sep.setAttribute('aria-hidden', 'true');
          sep.textContent = '/';
          c.appendChild(sep);
        }
        var sp = document.createElement('span');
        sp.textContent = parts[i];
        c.appendChild(sp);
      }
    }

    window.fetch('/geo/api?ip=' + encodeURIComponent(ip), {
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'X-Requested-With': 'ipcx' }
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data || !data.ok || !data.sources) return;
        ['ip2location', 'dbip', 'ipinfo', 'maxmind'].forEach(function (key) {
          var item = data.sources[key];
          if (item && item.status === 'ok') fillGeoRow(key, item, '');
          else fillGeoRow(key, null, item && item.reason === 'limited' ? T('查询额度已用完', 'Lookup quota used up') : T('查询失败', 'Lookup failed'));
        });
      })
      .catch(function () {});
  }

  function applyReportToDom(info, isSelfMode) {
    var currentIpEl = document.getElementById('current-ip');
    if (currentIpEl) {
      if (isMasked()) {
        currentIpEl.setAttribute('data-copy-value', info.ip);
        currentIpEl.textContent = maskIp(info.ip);
      } else {
        currentIpEl.removeAttribute('data-copy-value');
        currentIpEl.textContent = info.ip;
      }
    }
    setFieldText('protoVersion', 'IPv' + info.version);
    setFieldText('cliCmd', 'curl -sL judgeip.com/' + info.ip);
    setFieldText('eyebrowTag', isSelfMode ? T('当前出口', 'Your Egress') : T('指定查询', 'Queried IP'));
    var backLink = document.querySelector('[data-field="backMyIp"]');
    if (backLink) backLink.hidden = !!isSelfMode;

    var selfPanels = document.querySelectorAll('[data-self-only]');
    for (var s = 0; s < selfPanels.length; s++) {
      selfPanels[s].hidden = !isSelfMode;
    }

    var publicPanels = document.querySelectorAll('[data-public-panel]');
    for (var p = 0; p < publicPanels.length; p++) {
      publicPanels[p].hidden = !!info.isBogon;
    }

    var cardLink = document.getElementById('share-card-link');
    if (cardLink) cardLink.href = lp('/card') + '?ip=' + encodeURIComponent(info.ip);
    var pfLink = document.getElementById('platforms-check-link');
    if (pfLink) pfLink.href = lp('/platforms') + '?ip=' + encodeURIComponent(info.ip);
    var cmpLink = document.getElementById('compare-ips-link');
    if (cmpLink) cmpLink.href = lp('/compare') + '?ips=' + encodeURIComponent(info.ip) + ',8.8.8.8,1.1.1.1';
    document.title = info.ip + T(' 的 IP 归属与威胁情报查询 · JudgeIP', ': owner, network type and threat data · JudgeIP');

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
    var domSep = document.querySelector('[data-field="domainSep"]');
    var hasDom = !!(info.domain && info.domain !== '—');
    if (domSep) domSep.hidden = !hasDom;
    if (domEl) {
      domEl.textContent = info.domain || '—';
      domEl.hidden = !hasDom;
    }

    var rirPrefixHtml = '<span data-field="rirName">' + esc(info.rirName) + '</span>' +
      (info.rirCountry ? '<span class="dim mono"> (' + esc(info.rirCountry) + ')</span>' : '') +
      (info.bgpPrefix && info.bgpPrefix !== '—'
        ? '<span class="dim"> · </span><a class="asn-link mono" href="' + lp('/ip-calc') + '?q=' + encodeURIComponent(info.bgpPrefix) + '">' + esc(info.bgpPrefix) + '</a>'
        : '');
    setFieldHtml('rirPrefix', rirPrefixHtml);

    setFieldHtml('datacenter', info.isDatacenter ? '<span class="badge badge--danger">' + T('机房 / IDC', 'IDC / Hosting') + '</span>' : '');
    setFieldHtml('threat', '<span class="badge badge--' + (info.hasThreat === null ? 'gray' : info.hasThreat ? 'danger' : 'green') + '">' + esc(info.threatLabel) + '</span>');
    setFieldHtml('proxy', '<span class="badge badge--' + (info.isProxy === null ? 'gray' : info.isProxy ? 'amber' : 'green') + '">' + esc(info.proxyLabel) + '</span>');

    var ptrRow = document.querySelector('[data-ptr-row]');
    if (ptrRow) {
      var hasPtr = !!(info.ptrRecord && info.ptrRecord !== '—');
      ptrRow.hidden = !hasPtr;
      if (hasPtr) setFieldText('heroPtr', info.ptrRecord);
    }

    var tier = typeof info.score === 'number' && info.reputationCoverage !== 'complete' && info.hasThreat !== true
          ? { cls: 'muted', badge: 'gray', label: T('信誉证据不足', 'Limited reputation evidence'), desc: T('分数受证据上限限制；不代表已发现滥用，也不能判为纯净', 'Score capped for missing evidence; neither proof of abuse nor a clean verdict') }
          : scoreRiskTier(info.score, info.version);
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
      var confText = info.scoreConfidence === 'high' ? T('证据覆盖 高', 'Coverage high')
        : info.scoreConfidence === 'medium' ? T('证据覆盖 中', 'Coverage medium')
          : T('证据覆盖 低', 'Coverage low');
      gradeEl.className = 'badge badge--' + (info.scoreConfidence === 'high' ? 'green' : typeof info.score === 'number' ? 'amber' : 'gray');
      gradeEl.textContent = typeof info.score === 'number'
        ? T('等级 ', 'Grade ') + info.grade + ' · ' + confText
        : info.isBogon ? T('内网保留', 'Reserved') : T('数据源不可达', 'Unavailable');
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

    if (info.isBogon) {
      setFieldHtml('heroReasons', '<li class="hero-reasons__item is-muted"><span class="hero-reasons__dot">·</span><span>' + esc(info.bogonReason || T('保留或内网地址，不参与公网纯净度评分', 'Private or reserved range; not scored')) + '</span></li>');
    } else if (Array.isArray(info.factors)) {
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

    var kpiWrap = document.querySelector('[data-field="heroKpis"]');
    if (kpiWrap) {
      kpiWrap.hidden = !!info.isBogon;
      if (!info.isBogon) {
        var listedCount = Array.isArray(info.dnsblListed) ? info.dnsblListed.length : 0;
        var totalCount = info.dnsblTotal || 4;
        var openLen = Array.isArray(info.openPorts) ? info.openPorts.length : 0;
        var rpkiText = info.rpkiStatus === 'valid' ? 'VALID' : info.rpkiStatus === 'invalid' ? 'INVALID' : '—';
        kpiWrap.innerHTML =
          '<div class="hero-kpi"><span class="hero-kpi__label">' + T('DNSBL 黑名单', 'Blocklists') + '</span><span class="hero-kpi__val mono ' + (listedCount > 0 ? 'is-bad' : 'is-good') + '">' + (info.version !== 4 ? 'IPv4' : listedCount + ' / ' + totalCount) + '</span></div>' +
          '<div class="hero-kpi"><span class="hero-kpi__label">' + T('公网开放端口', 'Open ports') + '</span><span class="hero-kpi__val mono">' + (info.version !== 4 ? '—' : !info.portsKnown ? '?' : openLen) + '</span></div>' +
          '<div class="hero-kpi"><span class="hero-kpi__label">' + T('RPKI 路由签名', 'RPKI ROA') + '</span><span class="hero-kpi__val mono ' + (info.rpkiStatus === 'valid' ? 'is-good' : info.rpkiStatus === 'invalid' ? 'is-bad' : '') + '">' + rpkiText + '</span></div>';
      }
    }

    setFieldHtml(
      'country',
      (info.flagEmoji ? '<span class="flag">' + esc(info.flagEmoji) + '</span> ' : '') +
      '<strong>' + esc(info.countryZh) + '</strong>' +
      (info.countryCode ? ' <span class="dim mono">' + esc(info.countryCode) + '</span>' : '')
    );
    setFieldText('region', info.region);
    setFieldText('city', info.city);
    setFieldHtml('coords', '<span class="mono">' + (info.latitude !== null && info.longitude !== null ? esc(info.latitude + ', ' + info.longitude) : '—') + '</span>');
    setFieldHtml('timezone', '<span class="mono">' + esc(info.timezone) + '</span>' + (info.localTimeHm ? '<span class="dim"> · </span><span class="mono">' + esc(info.localTimeHm) + '</span>' : ''));
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
        '<div class="row"><span class="row__label">' + T('BGP 路由前缀', 'BGP prefix') + '</span><span class="row__value">' + bgpCell + '</span></div>' +
        '<div class="row"><span class="row__label">' + T('RPKI 路由授权', 'RPKI') + '</span><span class="row__value"><span class="tag tag--' + rpkiTone + '">' + esc(info.rpkiLabel) + '</span></span></div>' +
        '<div class="row"><span class="row__label">' + T('反向解析 (PTR)', 'Reverse DNS (PTR)') + '</span><span class="row__value"><span class="mono">' + esc(info.ptrRecord || '—') + '</span></span></div>' +
        '<div class="row"><span class="row__label">' + T('公网开放端口', 'Open ports') + '</span><span class="row__value">' + portsCell + '</span></div>';
      setFieldHtml('riskTech', rtHtml);
    }

    var dnsblStrip = document.querySelector('[data-field="dnsblStrip"]');
    if (dnsblStrip) {
      var showStrip = info.version === 4 && Array.isArray(info.dnsblChecks) && info.dnsblChecks.length > 0 && !info.isBogon;
      dnsblStrip.hidden = !showStrip;
      if (showStrip) {
        var chips = info.dnsblChecks.map(function (c) {
          var icon = c.status === 'not_listed' ? '✓' : c.status === 'listed' ? '×' : '?';
          return '<span class="dnsbl-chip is-' + esc(c.status) + '"><span class="dnsbl-chip__icon">' + icon + '</span><span>' + esc(c.name) + '</span></span>';
        }).join('');
        dnsblStrip.innerHTML = '<span class="dnsbl-strip__label">' + T('黑名单实时核验', 'Live DNSBLs') + '</span><div class="dnsbl-strip__chips">' + chips + '</div>';
      }
    }

    if (!info.isBogon && !isSelfMode) {
      refreshMultiGeo(info.ip);
    }
  }

  function enterLoading() {
    showError('');
    heroBox.classList.add('is-loading');
    form.classList.add('is-loading');
    if (searchBtn) searchBtn.disabled = true;
    if (refreshBtn) refreshBtn.disabled = true;

    for (var i = 0; i < aggChips.length; i++) {
      aggChips[i].classList.remove('is-ok', 'is-skip', 'is-fail');
    }
    if (aggBar) {
      aggBar.classList.remove('is-determinate');
      aggBar.style.width = '24%';
    }
    if (aggTitle) {
      aggTitle.textContent = T('正在聚合 ' + totalSources + ' 个数据源并计算评分…', 'Aggregating ' + totalSources + ' data sources & scoring…');
    }

    var started = Date.now();
    if (aggElapsed) aggElapsed.textContent = '0.0s';
    window.clearInterval(elapsedTimer);
    elapsedTimer = window.setInterval(function () {
      var sec = ((Date.now() - started) / 1000).toFixed(1);
      if (aggElapsed) aggElapsed.textContent = sec + 's';
    }, 100);
  }

  function exitLoading() {
    window.clearInterval(elapsedTimer);
    elapsedTimer = null;
    heroBox.classList.remove('is-loading');
    form.classList.remove('is-loading');
    if (searchBtn) searchBtn.disabled = false;
    if (refreshBtn) refreshBtn.disabled = false;
  }

  function markSourceChip(id, status, completedCount, totalCount) {
    var chip = heroBox.querySelector('[data-agg-source="' + id + '"]');
    if (chip) {
      chip.classList.remove('is-ok', 'is-skip', 'is-fail');
      chip.classList.add('is-' + (status === 'ok' ? 'ok' : status === 'skip' ? 'skip' : 'fail'));
    }
    if (aggBar && totalCount > 0) {
      var pct = Math.min(100, Math.max(12, Math.round((completedCount / totalCount) * 100)));
      aggBar.classList.add('is-determinate');
      aggBar.style.width = pct + '%';
    }
    if (aggTitle) {
      aggTitle.textContent = T(
        '正在聚合 ' + totalCount + ' 个数据源并计算评分… (' + completedCount + '/' + totalCount + ')',
        'Aggregating ' + totalCount + ' data sources & scoring… (' + completedCount + '/' + totalCount + ')'
      );
    }
  }

  function runStreamQuery(rawTarget, options) {
    var opts = options || {};
    var trimmed = String(rawTarget || '').trim();
    var isSelfMode = trimmed === '' || trimmed.toLowerCase() === 'me';

    if (activeController) {
      try { activeController.abort(); } catch (e) {}
    }
    activeController = window.AbortController ? new AbortController() : null;

    var startedAt = Date.now();
    enterLoading();

    var streamUrl = '/api/ipinfo/stream?ip=' + encodeURIComponent(isSelfMode ? 'me' : trimmed) +
      (isEn ? '&lang=en' : '') +
      (opts.fresh ? '&fresh=1' : '');

    window.fetch(streamUrl, {
      credentials: 'same-origin',
      headers: { Accept: 'application/x-ndjson, application/json' },
      signal: activeController ? activeController.signal : undefined
    }).then(function (resp) {
      if (!resp.ok) {
        return resp.json().catch(function () { return {}; }).then(function (errData) {
          throw { status: resp.status, data: errData };
        });
      }
      if (!resp.body || !resp.body.getReader) {
        return resp.text().then(function (txt) {
          var lines = txt.split('\n').filter(Boolean);
          var finalEvent = null;
          var doneCount = 0;
          lines.forEach(function (line) {
            try {
              var msg = JSON.parse(line);
              if (msg.type === 'source') {
                doneCount++;
                markSourceChip(msg.id, msg.status, doneCount, totalSources);
              } else if (msg.type === 'done') {
                finalEvent = msg;
              }
            } catch (e) {}
          });
          return finalEvent;
        });
      }

      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var buffer = '';
      var completed = 0;
      var total = totalSources;
      var finalPayload = null;

      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) {
            if (buffer.trim()) {
              try {
                var tail = JSON.parse(buffer.trim());
                if (tail.type === 'done') finalPayload = tail;
              } catch (e) {}
            }
            return finalPayload;
          }
          buffer += decoder.decode(chunk.value, { stream: true });
          var idx;
          while ((idx = buffer.indexOf('\n')) !== -1) {
            var line = buffer.slice(0, idx).trim();
            buffer = buffer.slice(idx + 1);
            if (!line) continue;
            try {
              var msg = JSON.parse(line);
              if (msg.type === 'start' && msg.total) {
                total = msg.total;
              } else if (msg.type === 'source') {
                completed++;
                markSourceChip(msg.id, msg.status, completed, total);
              } else if (msg.type === 'done') {
                finalPayload = msg;
              } else if (msg.type === 'error') {
                throw { status: 500, data: msg };
              }
            } catch (err) {
              if (err && err.status) throw err;
            }
          }
          return pump();
        });
      }
      return pump();
    }).then(function (finalMsg) {
      if (!finalMsg || !finalMsg.ok || !finalMsg.info) {
        throw { status: 500 };
      }
      // 超出查询预算时服务端没有请求上游，保留页面上现有的结果，只提示稍后再试
      if (finalMsg.info.lookupStatus === 'limited') {
        throw { status: 429, data: { retryAfter: finalMsg.info.retryAfter } };
      }
      // 命中节点内存缓存时（< 280ms），给 280ms 最小过场让全绿徽标与满格进度条平滑呈现，避免生硬闪烁
      var elapsed = Date.now() - startedAt;
      var waitMs = elapsed < 280 ? 280 - elapsed : 0;
      return new Promise(function (resolve) {
        window.setTimeout(function () { resolve(finalMsg.info); }, waitMs);
      });
    }).then(function (info) {
      applyReportToDom(info, isSelfMode);
      if (searchInput && !isSelfMode) searchInput.value = info.ip;
      if (!opts.skipHistory && window.history && window.history.pushState) {
        var nextUrl = isSelfMode ? lp('/') : lp('/?ip=' + encodeURIComponent(info.ip));
        if (window.location.pathname + window.location.search !== nextUrl) {
          window.history.pushState({ ip: isSelfMode ? '' : info.ip }, '', nextUrl);
        }
      }
      exitLoading();
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return;
      exitLoading();
      if (err && err.status === 400) {
        showError(
          isEn
            ? '"' + trimmed.slice(0, 60) + '" is not a valid IPv4 or IPv6 address.'
            : '「' + trimmed.slice(0, 60) + '」不是有效的 IPv4 或 IPv6 地址。'
        );
      } else if (err && err.status === 429) {
        var retry = err.data && Number(err.data.retryAfter);
        showError(retry > 0
          ? T('查询请求过于频繁，请在 ' + retry + ' 秒后再试。', 'Too many lookup requests. Try again in ' + retry + 's.')
          : T('查询请求过于频繁，请稍后再试。', 'Too many lookup requests. Please try again in a moment.'));
      } else {
        showError(T('聚合查询未完成，请点击重新聚合或稍后再试。', 'Lookup did not complete. Please retry in a moment.'));
      }
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var val = searchInput ? searchInput.value.trim() : '';
    runStreamQuery(val, { fresh: false, skipHistory: false });
  });

  if (refreshBtn) {
    refreshBtn.addEventListener('click', function () {
      var currentIpEl = document.getElementById('current-ip');
      var currentIp = currentIpEl ? (currentIpEl.getAttribute('data-copy-value') || currentIpEl.textContent || '').trim() : '';
      var isSelfNow = heroBox.getAttribute('data-is-self') === '1' && (!searchInput || !searchInput.value.trim());
      runStreamQuery(isSelfNow ? 'me' : currentIp, { fresh: true, skipHistory: true });
    });
  }

  var onPopState = function (event) {
    if (!heroBox.isConnected) return;
    /* 只有回到首页路径（/ 或 /en）才由 ip-search.js 就地流式更新；跨路由后退交给 spa.js */
    var path = window.location.pathname;
    if (path !== '/' && path !== '/en' && path !== '/en/') return;
    var params = new URLSearchParams(window.location.search);
    var q = (event.state && event.state.ip !== undefined)
      ? event.state.ip
      : (params.get('ip') || params.get('q') || '').trim();
    if (searchInput) searchInput.value = q;
    runStreamQuery(q || 'me', { fresh: false, skipHistory: true });
  };
  window.addEventListener('popstate', onPopState);

  var onBeforeSwap = function () {
    if (activeController) {
      try { activeController.abort(); } catch (e) {}
      activeController = null;
    }
    if (elapsedTimer) {
      window.clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
    window.removeEventListener('popstate', onPopState);
    document.removeEventListener('judgeip:before-swap', onBeforeSwap);
  };
  document.addEventListener('judgeip:before-swap', onBeforeSwap);
})();
