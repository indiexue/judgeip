/* JudgeIP — 一键环境体检（6 大维度交叉校验：IP 纯净度 / WebRTC 泄露 / DNS 泄露 / 时区语言一致性 / 浏览器自动化 / AI 可用性） */
(function () {
  'use strict';

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

  var running = false;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function setDimCell(key, badgeTone, badgeText, noteText) {
    var row = root.querySelector('[data-dim="' + key + '"] [data-dim-val]');
    if (!row) return;
    row.textContent = '';
    var wrap = el('span', 'tags');
    wrap.appendChild(el('span', 'tag tag--' + badgeTone, badgeText));
    if (noteText) wrap.appendChild(el('span', 'geo__note', noteText));
    row.appendChild(wrap);
  }

  function detectPublicV4() {
    var urls = ['https://ipv4.icanhazip.com/', 'https://v4.ident.me/', 'https://checkip.amazonaws.com/'];
    var tryAt = function (idx) {
      if (idx >= urls.length) return Promise.resolve('');
      var ctl = window.AbortController ? new AbortController() : null;
      var timer = window.setTimeout(function () { if (ctl) ctl.abort(); }, 3000);
      return window.fetch(urls[idx], { cache: 'no-store', credentials: 'omit', signal: ctl ? ctl.signal : undefined })
        .then(function (r) { clearTimeout(timer); return r.ok ? r.text() : ''; })
        .then(function (t) {
          var v = String(t || '').trim();
          return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) ? v : tryAt(idx + 1);
        })
        .catch(function () { clearTimeout(timer); return tryAt(idx + 1); });
    };
    return tryAt(0);
  }

  function probeWebRtc(knownIps) {
    return new Promise(function (resolve) {
      var PC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
      if (!PC) {
        resolve({ ok: true, status: '已禁用 WebRTC', note: '无 UDP 旁路风险', penalty: 0 });
        return;
      }
      var srflx = [];
      var settled = false;
      var pc;
      var finish = function () {
        if (settled) return;
        settled = true;
        try { pc.close(); } catch (e) {}
        var leaked = srflx.filter(function (ip) { return knownIps.indexOf(ip) === -1; });
        if (leaked.length) {
          resolve({ ok: false, tone: 'leak', status: '发现泄露 (' + leaked[0] + ')', note: 'UDP 未走当前代理出口', penalty: 25 });
        } else if (srflx.length) {
          resolve({ ok: true, tone: 'ok', status: '一致无泄露', note: 'STUN 回显 ' + srflx[0], penalty: 0 });
        } else {
          resolve({ ok: true, tone: 'ok', status: '已受保护', note: '无公网候选暴露 / mDNS 生效', penalty: 0 });
        }
      };
      try {
        pc = new PC({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }, { urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('judgeip-check');
        pc.onicecandidate = function (ev) {
          if (!ev.candidate || !ev.candidate.candidate) { finish(); return; }
          var line = ev.candidate.candidate;
          var parts = line.split(' ');
          var addr = ev.candidate.address || (parts.length >= 5 ? parts[4] : '');
          var typ = ev.candidate.type || (parts.length >= 8 ? parts[7] : '');
          if (addr && (typ === 'srflx' || typ === 'prflx') && srflx.indexOf(addr) === -1) srflx.push(addr);
        };
        window.setTimeout(finish, 2600);
        pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(finish);
      } catch (e) {
        resolve({ ok: true, tone: 'ok', status: '已屏蔽', note: '连接受限无泄露', penalty: 0 });
      }
    });
  }

  function probeDnsLeak(clientIp) {
    var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var makeSub = function () {
      var s = '';
      for (var i = 0; i < 28; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
      return s;
    };
    var jobs = [0, 1, 2, 3].map(function () {
      var sub = makeSub();
      var ctl = window.AbortController ? new AbortController() : null;
      var timer = window.setTimeout(function () { if (ctl) ctl.abort(); }, 4500);
      return window.fetch('https://' + sub + '.edns.ip-api.com/json', {
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: ctl ? ctl.signal : undefined
      })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { clearTimeout(timer); return d && d.dns && d.dns.ip ? d.dns.ip : ''; })
        .catch(function () { clearTimeout(timer); return ''; });
    });

    return Promise.all(jobs).then(function (ips) {
      var uniq = [];
      ips.forEach(function (ip) { if (ip && uniq.indexOf(ip) === -1) uniq.push(ip); });
      if (!uniq.length) {
        return { ok: true, tone: 'muted', status: '未捕获探测回显', note: '可前往「DNS 泄露检测」单独详测', penalty: 0 };
      }
      return window.fetch('/dnsleak/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ clientIp: clientIp, resolvers: uniq.map(function (ip) { return { ip: ip, queries: 1 }; }) })
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (!data || !data.ok || !data.resolvers || !data.resolvers.length) {
            return { ok: true, tone: 'muted', status: '已捕获 ' + uniq.length + ' 台', note: uniq[0], penalty: 0 };
          }
          var cc = data.client && data.client.country_code;
          var crossIsp = data.resolvers.filter(function (rv) { return rv.type === 'isp' && rv.country_code && cc && rv.country_code !== cc; });
          var crossAny = data.resolvers.filter(function (rv) { return rv.country_code && cc && rv.country_code !== cc; });
          if (crossIsp.length) {
            return { ok: false, tone: 'leak', status: '运营商 DNS 泄露', note: crossIsp[0].country + ' · ' + crossIsp[0].isp, penalty: 22 };
          }
          if (crossAny.length) {
            return { ok: false, tone: 'warn', status: '跨区解析 (' + crossAny[0].country_code + ')', note: '出口 ' + cc + '，解析在 ' + crossAny[0].country, penalty: 10 };
          }
          return { ok: true, tone: 'ok', status: '同区一致 (' + data.resolvers.length + ' 台)', note: data.resolvers[0].isp, penalty: 0 };
        })
        .catch(function () {
          return { ok: true, tone: 'muted', status: '部分完成', note: uniq[0] || '', penalty: 0 };
        });
    });
  }

  function probeConsistency(ipInfo) {
    var sysTz = '';
    try { sysTz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { sysTz = ''; }
    var ipTz = (ipInfo && ipInfo.timezone) || '';
    var ipCc = ((ipInfo && ipInfo.countryCode) || '').toUpperCase();
    var langs = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || '']).slice(0, 2).join(', ');

    var tzMatch = !ipTz || !sysTz || sysTz === ipTz;
    var cnLocaleOnForeign = ipCc && ['CN', 'HK', 'MO', 'TW', 'SG'].indexOf(ipCc) === -1 && /zh-CN|zh-Hans/i.test(langs);

    if (!tzMatch && cnLocaleOnForeign) {
      return { ok: false, tone: 'leak', status: '时区与语言双重不一致', note: '系统 ' + sysTz + ' ≠ IP ' + ipTz + '，且首选 ' + langs, penalty: 18 };
    }
    if (!tzMatch) {
      return { ok: false, tone: 'warn', status: '时区不一致', note: '本地 ' + sysTz + ' vs IP ' + ipTz, penalty: 12 };
    }
    if (cnLocaleOnForeign) {
      return { ok: false, tone: 'warn', status: '语言偏好暴露', note: '出口 ' + ipCc + ' 但首选语言为 ' + langs, penalty: 8 };
    }
    return { ok: true, tone: 'ok', status: '时区与区域一致', note: sysTz + ' · ' + langs, penalty: 0 };
  }

  function probeStealth() {
    var issues = [];
    if (navigator.webdriver) issues.push('navigator.webdriver=true');
    if (!navigator.languages || navigator.languages.length === 0) issues.push('无语言列表');
    if (window.outerWidth === 0 && window.outerHeight === 0) issues.push('无头窗口尺寸异常');

    if (issues.length) {
      return { ok: false, tone: 'leak', status: '发现自动化特征', note: issues.join('、'), penalty: 20 };
    }
    return { ok: true, tone: 'ok', status: '真人浏览器特征', note: 'WebDriver 正常 · 硬件线程 ' + (navigator.hardwareConcurrency || '—'), penalty: 0 };
  }

  function probeAiReachability(ipInfo) {
    var blockedCc = ['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP'];
    var cc = ((ipInfo && ipInfo.countryCode) || '').toUpperCase();
    var ctl = window.AbortController ? new AbortController() : null;
    var timer = window.setTimeout(function () { if (ctl) ctl.abort(); }, 4000);

    return window.fetch('https://chatgpt.com/cdn-cgi/trace', {
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: ctl ? ctl.signal : undefined
    })
      .then(function (r) { clearTimeout(timer); return r.ok ? r.text() : ''; })
      .then(function (txt) {
        var locMatch = /(?:^|\n)loc=([A-Z]{2})/.exec(txt || '');
        var aiLoc = locMatch ? locMatch[1] : cc;
        if (blockedCc.indexOf(aiLoc) !== -1) {
          return { ok: false, tone: 'leak', status: 'AI 地区受限 (' + aiLoc + ')', note: 'ChatGPT / Claude 不支持该出口地区', penalty: 15 };
        }
        return { ok: true, tone: 'ok', status: '可达且地区受支持 (' + aiLoc + ')', note: 'ChatGPT 边缘连通正常', penalty: 0 };
      })
      .catch(function () {
        clearTimeout(timer);
        if (blockedCc.indexOf(cc) !== -1) {
          return { ok: false, tone: 'leak', status: '连接受阻 / 地区受限', note: '当前网络无法直连海外 AI 服务', penalty: 15 };
        }
        return { ok: false, tone: 'warn', status: '连接超时', note: '未能连通 chatgpt.com 边缘接口', penalty: 8 };
      });
  }

  function run() {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    verdict.hidden = true;
    progress.textContent = '正在执行 6 大维度环境交叉校验…';

    ['purity', 'webrtc', 'dns', 'consistency', 'stealth', 'ai'].forEach(function (k) {
      setDimCell(k, 'muted', '检测中…', '');
    });

    var serverVisibleIp = (root.getAttribute('data-visible-ip') || '').trim();

    detectPublicV4().then(function (v4) {
      var primaryIp = v4 || serverVisibleIp;
      var knownIps = [serverVisibleIp, v4].filter(Boolean);
      if (ipCell) ipCell.innerHTML = '<span class="mono">' + primaryIp + '</span>';

      return window.fetch('/api/ipinfo?ip=' + encodeURIComponent(primaryIp), { headers: { Accept: 'application/json' } })
        .then(function (r) { return r.json(); })
        .then(function (ipRes) {
          var info = (ipRes && ipRes.ok && ipRes.info) ? ipRes.info : null;

          // Dim 1: IP Purity
          var ipScore = info ? info.score : 70;
          var d1Ok = ipScore >= 75 && !(info && info.isDatacenter) && !(info && info.isProxy);
          var d1Tone = d1Ok ? 'ok' : ipScore >= 55 ? 'warn' : 'leak';
          var d1Penalty = Math.max(0, Math.round((100 - ipScore) * 0.35));
          setDimCell(
            'purity',
            d1Tone,
            info ? info.ipTypeLabel + ' · ' + info.score + '/100 (' + info.grade + ')' : '已读取',
            info ? (info.isNative ? '原生 IP · ' : '广播 IP · ') + info.countryZh + ' ' + info.asnCode : ''
          );

          // Dim 4 & 5 synchronous
          var d4 = probeConsistency(info);
          setDimCell('consistency', d4.tone, d4.status, d4.note);

          var d5 = probeStealth();
          setDimCell('stealth', d5.tone, d5.status, d5.note);

          return Promise.all([
            probeWebRtc(knownIps).then(function (r) { setDimCell('webrtc', r.tone, r.status, r.note); return r; }),
            probeDnsLeak(primaryIp).then(function (r) { setDimCell('dns', r.tone, r.status, r.note); return r; }),
            probeAiReachability(info).then(function (r) { setDimCell('ai', r.tone, r.status, r.note); return r; })
          ]).then(function (asyncRes) {
            var d2 = asyncRes[0];
            var d3 = asyncRes[1];
            var d6 = asyncRes[2];

            var allDims = [
              { ok: d1Ok, penalty: d1Penalty },
              d2, d3, d4, d5, d6
            ];
            var passCount = allDims.filter(function (x) { return x.ok; }).length;
            var totalPenalty = allDims.reduce(function (sum, x) { return sum + (x.penalty || 0); }, 0);
            var envScore = Math.max(5, Math.min(100, 100 - totalPenalty));
            var sTone = envScore >= 80 ? 'good' : envScore >= 55 ? 'warn' : 'bad';

            if (scoreCell) {
              scoreCell.innerHTML =
                '<span class="score score--' + sTone + '">' +
                '<svg class="score__bar" viewBox="0 0 100 6"><rect class="score__track" x="0" y="0" width="100" height="6" rx="3"></rect>' +
                '<rect class="score__fill" x="0" y="0" width="' + envScore + '" height="6" rx="3"></rect></svg>' +
                '<span class="score__num mono">' + envScore + '<span class="score__total">/100</span></span></span>';
            }
            if (passCell) {
              passCell.innerHTML = '<span class="mono">' + passCount + ' / 6 项通过</span>';
            }

            verdict.hidden = false;
            if (envScore >= 82 && passCount >= 5) {
              verdict.className = 'verdict is-good';
              verdictTitle.textContent = '环境高度纯净一致（综合 ' + envScore + ' 分）';
              verdictNote.textContent = 'IP 属性、WebRTC/DNS 隧道与本地浏览器时区语言高度自洽，适合对风控敏感的跨境电商、社媒与 AI 平台使用。';
            } else if (envScore >= 55) {
              verdict.className = 'verdict is-warn';
              verdictTitle.textContent = '环境存在轻微破绽（综合 ' + envScore + ' 分）';
              verdictNote.textContent = '共有 ' + (6 - passCount) + ' 个维度出现警告（常见于机房出口、时区未跟随代理地区、或跨区 DNS），登录高敏账号前建议按下方提示修正。';
            } else {
              verdict.className = 'verdict is-bad';
              verdictTitle.textContent = '环境存在明显泄漏或高风险特征（综合 ' + envScore + ' 分）';
              verdictNote.textContent = '多项核心指标未通过交叉核验，网站风控很容易识别出代理异常，请逐项排查标红维度。';
            }

            running = false;
            runBtn.disabled = false;
            runBtn.textContent = '重新体检';
            progress.textContent = '6 大维度交叉校验已完成。';
          });
        });
    }).catch(function () {
      running = false;
      runBtn.disabled = false;
      runBtn.textContent = '重试体检';
      progress.textContent = '部分检测请求异常，请点击重试。';
    });
  }

  runBtn.addEventListener('click', run);
  // 打开页面即自动开始体检
  if (document.readyState === 'complete') run();
  else window.addEventListener('load', run);
})();
