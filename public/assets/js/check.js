/* JudgeIP — 网络与浏览器环境体检。未完成的项目不计通过，也不参与总评分。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };
  var en = window.I18N && I18N.lang === 'en';
  var root = document.getElementById('envcheck');
  if (!root) return;

  var runBtn = root.querySelector('[data-check-run]');
  var progress = root.querySelector('[data-check-progress]');
  var verdict = root.querySelector('[data-check-verdict]');
  var verdictTitle = root.querySelector('[data-check-verdict-title]');
  var verdictNote = root.querySelector('[data-check-verdict-note]');
  var scoreCell = root.querySelector('[data-check-score]');
  var passCell = root.querySelector('[data-check-passed]');
  var ipCell = root.querySelector('[data-check-ip]');
  var keys = ['purity', 'webrtc', 'dns', 'consistency', 'stealth', 'ai'];
  var running = false;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    node.className = cls || '';
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function result(state, status, note, penalty) {
    return { state: state, status: status, note: note || '', penalty: penalty || 0 };
  }

  function incomplete(note) {
    return result('incomplete', T('未完成', 'Incomplete'), note);
  }

  function paint(key, value) {
    var cell = root.querySelector('[data-dim="' + key + '"] [data-dim-val]');
    if (!cell) return value;
    cell.textContent = '';
    var wrap = el('span', 'tags');
    var label = value.state === 'pass' ? T('通过', 'Passed') : value.state === 'warn' ? T('警告', 'Warning') : T('未完成', 'Incomplete');
    var tone = value.state === 'pass' ? 'ok' : value.state === 'warn' ? 'warn' : 'muted';
    wrap.appendChild(el('span', 'tag tag--' + tone, label === value.status ? label : label + ' · ' + value.status));
    if (value.note) wrap.appendChild(el('span', 'geo__note', value.note));
    cell.appendChild(wrap);
    return value;
  }

  function country(code, fallback) {
    if (en && /^[A-Z]{2}$/.test(code || '')) {
      try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(code); } catch (e) {}
    }
    return en ? (code || 'Unknown') : (fallback || code || '未知');
  }

  /* The deadline covers the response body as well as connection setup. */
  function request(url, options, format, timeout) {
    return new Promise(function (resolve, reject) {
      var ctl = window.AbortController ? new AbortController() : null;
      var opts = Object.assign({ cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }, options || {});
      if (ctl) opts.signal = ctl.signal;
      var timer = window.setTimeout(function () {
        if (ctl) ctl.abort();
        reject(new Error('timeout'));
      }, timeout || 5000);
      window.fetch(url, opts).then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return format === 'json' ? response.json() : response.text();
      }).then(function (body) {
        clearTimeout(timer);
        resolve(body);
      }).catch(function (error) {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  function validV4(value) {
    var parts = String(value).split('.');
    return parts.length === 4 && parts.every(function (v) { return /^\d{1,3}$/.test(v) && Number(v) <= 255; });
  }

  function detectPublicV4() {
    var urls = ['https://ipv4.icanhazip.com/', 'https://v4.ident.me/', 'https://checkip.amazonaws.com/'];
    function tryAt(index) {
      if (index >= urls.length) return Promise.resolve('');
      return request(urls[index], {}, 'text', 3000).then(function (text) {
        var ip = String(text).trim();
        return validV4(ip) ? ip : tryAt(index + 1);
      }).catch(function () { return tryAt(index + 1); });
    }
    return tryAt(0);
  }

  function probeWebRtc(knownIps) {
    return new Promise(function (resolve) {
      var PC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
      if (!PC) { resolve(incomplete(T('WebRTC 不可用，未执行 STUN 检测', 'WebRTC unavailable; STUN check was not run'))); return; }
      var addresses = [];
      var settled = false;
      var timer;
      var pc;
      function finish(failed) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { pc.close(); } catch (e) {}
        if (failed || !addresses.length) {
          resolve(incomplete(T('未取得 STUN 公网地址，无法判断出口是否一致', 'No STUN public address obtained; exits could not be compared')));
          return;
        }
        var compare = window.IpcxProbe && window.IpcxProbe.compareExit;
        if (!compare) { resolve(incomplete(T('地址比较工具不可用', 'Address comparison unavailable'))); return; }
        var different = addresses.filter(function (ip) { return compare(ip, knownIps) === 'different'; });
        var unpaired = addresses.some(function (ip) { return compare(ip, knownIps) === 'uncompared'; });
        resolve(different.length
          ? result('warn', T('发现同协议族出口差异', 'Same-family exit differs'), different.join(', ') + T('；不能仅据此断定代理泄露', '; this alone does not prove a proxy leak'), 25)
          : unpaired ? incomplete(T('缺少同协议族 HTTP 地址，不能比较；IPv6 按 /64 归并', 'No same-family HTTP address to compare; IPv6 uses /64 grouping'))
            : result('pass', T('与已知出口一致', 'Matches a known exit'), addresses.join(', ') + T('（IPv6 按 /64 比较）', ' (IPv6 compared by /64)')));
      }
      try {
        pc = new PC({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }, { urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('judgeip-check');
        pc.onicecandidate = function (event) {
          if (!event.candidate) { finish(false); return; }
          var parts = String(event.candidate.candidate || '').split(' ');
          var addr = event.candidate.address || parts[4] || '';
          var type = event.candidate.type || parts[7] || '';
          if (addr && (type === 'srflx' || type === 'prflx') && addresses.indexOf(addr) === -1) addresses.push(addr);
        };
        timer = window.setTimeout(function () { finish(false); }, 3500);
        pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); }).catch(function () { finish(true); });
      } catch (e) { finish(true); }
    });
  }

  function probeDnsLeak(clientIp) {
    var jobs = [0, 1, 2, 3].map(function () {
      var sub = Math.random().toString(36).slice(2) + Date.now().toString(36);
      return request('https://' + sub + '.edns.ip-api.com/json', {}, 'json', 4000)
        .catch(function () { return request('https://edns.ip-api.com/json?t=' + sub, {}, 'json', 4000); })
        .then(function (data) { return data && data.dns && data.dns.ip ? String(data.dns.ip) : ''; })
        .catch(function () { return ''; });
    });
    return Promise.all(jobs).then(function (ips) {
      var unique = ips.filter(function (ip, i) { return ip && ips.indexOf(ip) === i; });
      if (!unique.length) return incomplete(T('未收到 DNS 探测响应', 'No DNS probe response'));
      return request('/dnsleak/api' + (en ? '?lang=en' : ''), {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ clientIp: clientIp, resolvers: unique.map(function (ip) { return { ip: ip, queries: 1 }; }) })
      }, 'json', 10000).then(function (data) {
        var resolvers = data && data.ok && Array.isArray(data.resolvers) ? data.resolvers : [];
        var cc = data && data.client && data.client.country_code;
        if (!cc || resolvers.length !== unique.length || resolvers.some(function (r) { return !r || !r.country_code || ['public', 'isp', 'hosting'].indexOf(r.type) === -1; })) {
          return incomplete(T('解析器或出口资料不完整，无法比较地区', 'Resolver or exit data incomplete; regions could not be compared'));
        }
        var cross = resolvers.filter(function (r) { return r.country_code !== cc; });
        if (cross.length) return result('warn', T('解析地区与出口不同', 'DNS region differs from exit'), country(cross[0].country_code, cross[0].country), 10);
        return result('pass', T('已捕获解析器与出口同区', 'Captured resolvers match exit region'), String(resolvers.length));
      }).catch(function () { return incomplete(T('DNS 归属查询未完成', 'DNS enrichment did not complete')); });
    });
  }

  function probeConsistency(info) {
    var timezone = '';
    try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
    var ipTimezone = info && info.timezone;
    var cc = info && info.countryCode;
    if (!timezone || !ipTimezone || ipTimezone === '—' || !cc) {
      return incomplete(T('缺少时区或出口地区资料', 'Timezone or exit region data missing'));
    }
    var langs = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || '']).slice(0, 2).join(', ');
    if (!langs) return incomplete(T('浏览器语言资料不可用', 'Browser language data unavailable'));
    var mismatch = timezone !== ipTimezone || (['CN', 'HK', 'MO', 'TW', 'SG'].indexOf(cc) === -1 && /zh-CN|zh-Hans/i.test(langs));
    return result(mismatch ? 'warn' : 'pass', mismatch ? T('时区或语言有差异', 'Timezone or language differs') : T('未见时区或语言差异', 'No timezone or language differences flagged'), timezone + ' / ' + ipTimezone + ' · ' + langs, mismatch ? 12 : 0);
  }

  function probeStealth() {
    var flags = [];
    if (navigator.webdriver) flags.push('navigator.webdriver=true');
    if (!navigator.languages || !navigator.languages.length) flags.push(T('语言列表为空', 'Empty language list'));
    if (window.outerWidth === 0 && window.outerHeight === 0) flags.push(T('窗口尺寸为零', 'Zero window dimensions'));
    return flags.length ? result('warn', T('发现自动化标记', 'Automation flags found'), flags.join(', '), 20)
      : result('pass', T('未见常见自动化标记', 'No common automation flags found'));
  }

  function probeAiReachability() {
    return request('https://chatgpt.com/cdn-cgi/trace', {}, 'text', 5000).then(function (text) {
      var loc = /(?:^|\n)loc=([A-Z]{2})(?:\n|$)/.exec(text);
      var ip = /(?:^|\n)ip=([^\s]+)(?:\n|$)/.exec(text);
      if (!loc || !ip) return incomplete(T('未收到有效的 ChatGPT 边缘数据', 'No valid ChatGPT edge data received'));
      var restricted = ['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP'].indexOf(loc[1]) !== -1;
      return result(restricted ? 'warn' : 'pass', restricted ? T('地区可能受限', 'Region may be restricted') : T('已收到边缘响应', 'Edge response received'), loc[1] + ' · ' + T('不代表已登录服务或 API 可用', 'Does not confirm signed-in service or API access'), restricted ? 15 : 0);
    }).catch(function (error) {
      return incomplete(T('ChatGPT 探测未完成：', 'ChatGPT probe incomplete: ') + error.message);
    });
  }

  function summarize(values) {
    var passed = values.filter(function (v) { return v.state === 'pass'; }).length;
    var warned = values.filter(function (v) { return v.state === 'warn'; }).length;
    var missing = values.length - passed - warned;
    passCell.textContent = T('通过 ', 'Passed ') + passed + ' / 6 · ' + T('警告 ', 'Warnings ') + warned + ' · ' + T('未完成 ', 'Incomplete ') + missing;
    scoreCell.textContent = missing ? T('未完成，暂不评分', 'Incomplete; no score')
      : Math.max(5, 100 - values.reduce(function (sum, v) { return sum + v.penalty; }, 0)) + ' / 100';
    verdict.hidden = false;
    verdict.className = 'verdict ' + (missing || warned ? 'is-warn' : 'is-good');
    verdictTitle.textContent = missing ? T('部分检测未完成', 'Some checks are incomplete') : warned ? T('部分项目需要复查', 'Some checks need review') : T('已完成检测未见明显差异', 'Completed checks found no major differences');
    verdictNote.textContent = missing ? T('未完成项目未计为通过，也不生成总评分。请查看明细并重试或使用单项工具。', 'Incomplete checks are not counted as passed, and no overall score is generated. Review the details and retry or use the individual tools.')
      : T('结果仅供排查，不代表第三方平台判断，也不能保证账号安全或服务可用。', 'Results are for troubleshooting only, not a platform assessment or a guarantee of account safety or service access.');
    progress.textContent = missing ? T('本轮检测结束，部分项目未完成。', 'Run finished; some checks remain incomplete.') : T('检测已完成，请查看各项结果。', 'Checks complete. Review the individual results.');
  }

  function run() {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    verdict.hidden = true;
    scoreCell.textContent = T('检测中…', 'Checking…');
    passCell.textContent = T('检测中…', 'Checking…');
    progress.textContent = T('正在检查网络与浏览器环境…', 'Checking network and browser settings…');
    keys.forEach(function (key) { paint(key, result('incomplete', T('检测中…', 'Checking…'))); });
    var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
    detectPublicV4().then(function (v4) {
      var ip = v4 || visibleIp;
      ipCell.textContent = ip;
      return request('/api/ipinfo?ip=' + encodeURIComponent(ip) + (en ? '&lang=en' : ''), { headers: { Accept: 'application/json' } }, 'json', 10000)
        .catch(function () { return null; }).then(function (response) {
          var info = response && response.ok ? response.info : null;
          var ipScore = info && info.score;
          var d1 = typeof ipScore !== 'number' || !isFinite(ipScore) || typeof info.isDatacenter !== 'boolean' || typeof info.isProxy !== 'boolean'
            ? incomplete(T('IP 资料不足，暂不评分', 'Insufficient IP data to score'))
            : result(ipScore >= 75 && !info.isDatacenter && !info.isProxy ? 'pass' : 'warn', info.ipTypeLabel + ' · ' + ipScore + '/100', info.countryZh + ' · ' + info.asnCode, Math.round((100 - ipScore) * 0.35));
          paint('purity', d1);
          var d4 = paint('consistency', probeConsistency(info));
          var d5 = paint('stealth', probeStealth());
          return Promise.all([
            probeWebRtc([visibleIp, v4].filter(Boolean)).then(function (v) { return paint('webrtc', v); }),
            probeDnsLeak(ip).then(function (v) { return paint('dns', v); }),
            probeAiReachability().then(function (v) { return paint('ai', v); })
          ]).then(function (asyncValues) { summarize([d1, asyncValues[0], asyncValues[1], d4, d5, asyncValues[2]]); });
        });
    }).catch(function () {
      var values = keys.map(function (key) { return paint(key, incomplete(T('请求或页面处理失败，请重试', 'Request or page processing failed; try again'))); });
      summarize(values);
    }).then(function () {
      running = false;
      runBtn.disabled = false;
      runBtn.textContent = T('重新检测', 'Run again');
    });
  }

  runBtn.addEventListener('click', run);
  if (document.readyState === 'complete') run();
  else window.addEventListener('load', run);
})();
