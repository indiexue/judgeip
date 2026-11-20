/* JudgeIP — 一键环境体检（6 大维度交叉校验：IP 纯净度 / WebRTC 泄露 / DNS 泄露 / 时区语言一致性 / 浏览器自动化 / AI 可用性） */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };
  var en = window.I18N && I18N.lang === 'en';
  function country(code, fallback) {
    if (en && /^[A-Z]{2}$/.test(code || '')) {
      try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(code); } catch (e) {}
    }
    return en ? (code || 'Unknown') : fallback;
  }

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
        resolve({ ok: true, tone: 'muted', status: T('WebRTC 不可用', 'WebRTC unavailable'), note: T('未执行 STUN 检测', 'STUN check was not run'), penalty: 0 });
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
          resolve({ ok: false, tone: 'leak', status: T('发现不同出口 (', 'Different exit found (') + leaked[0] + ')', note: T('UDP 出口与已知 HTTP 出口不同', 'UDP exit differs from the known HTTP exits'), penalty: 25 });
        } else if (srflx.length) {
          resolve({ ok: true, tone: 'ok', status: T('与已知出口一致', 'Matches a known exit'), note: T('STUN 回显 ', 'STUN address: ') + srflx[0], penalty: 0 });
        } else {
          resolve({ ok: true, tone: 'ok', status: T('未发现公网候选地址', 'No public candidates found'), note: T('可能受浏览器设置或网络限制', 'Browser settings or network restrictions may affect this result'), penalty: 0 });
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
        resolve({ ok: true, tone: 'ok', status: T('WebRTC 连接失败', 'WebRTC connection failed'), note: T('未能完成 STUN 检测', 'Could not complete the STUN check'), penalty: 0 });
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
        return { ok: true, tone: 'muted', status: T('未收到探测响应', 'No probe response'), note: T('可用 DNS 泄露工具复查', 'Use the DNS leak tool to investigate'), penalty: 0 };
      }
      return window.fetch('/dnsleak/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ clientIp: clientIp, resolvers: uniq.map(function (ip) { return { ip: ip, queries: 1 }; }) })
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (!data || !data.ok || !data.resolvers || !data.resolvers.length) {
            return { ok: true, tone: 'muted', status: T('已捕获解析地址：', 'Resolver addresses found: ') + uniq.length, note: uniq[0], penalty: 0 };
          }
          var cc = data.client && data.client.country_code;
          var crossIsp = data.resolvers.filter(function (rv) { return rv.type === 'isp' && rv.country_code && cc && rv.country_code !== cc; });
          var crossAny = data.resolvers.filter(function (rv) { return rv.country_code && cc && rv.country_code !== cc; });
          if (crossIsp.length) {
            return { ok: false, tone: 'leak', status: T('运营商 DNS 地区不同', 'ISP DNS region differs'), note: country(crossIsp[0].country_code, crossIsp[0].country) + ' · ' + crossIsp[0].isp, penalty: 22 };
          }
          if (crossAny.length) {
            return { ok: false, tone: 'warn', status: T('跨区解析 (', 'Cross-region DNS (') + crossAny[0].country_code + ')', note: T('出口 ', 'Exit: ') + cc + T('，解析在 ', '; DNS: ') + country(crossAny[0].country_code, crossAny[0].country), penalty: 10 };
          }
          return { ok: true, tone: 'ok', status: T('同区解析：', 'Same-region resolvers: ') + data.resolvers.length, note: data.resolvers[0].isp, penalty: 0 };
        })
        .catch(function () {
          return { ok: true, tone: 'muted', status: T('部分完成', 'Partially completed'), note: uniq[0] || '', penalty: 0 };
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
      return { ok: false, tone: 'leak', status: T('时区与语言均有差异', 'Timezone and language differ'), note: T('系统 ', 'System: ') + sysTz + ' ≠ IP ' + ipTz + T('，首选语言 ', '; languages: ') + langs, penalty: 18 };
    }
    if (!tzMatch) {
      return { ok: false, tone: 'warn', status: T('时区不同', 'Timezone differs'), note: T('本地 ', 'Local: ') + sysTz + ' vs IP ' + ipTz, penalty: 12 };
    }
    if (cnLocaleOnForeign) {
      return { ok: false, tone: 'warn', status: T('语言与出口地区不同', 'Language differs from exit region'), note: T('出口 ', 'Exit: ') + ipCc + T('，首选语言 ', '; languages: ') + langs, penalty: 8 };
    }
    return { ok: true, tone: 'ok', status: T('未见时区或语言差异', 'No timezone or language differences flagged'), note: sysTz + ' · ' + langs, penalty: 0 };
  }

  function probeStealth() {
    var issues = [];
    if (navigator.webdriver) issues.push('navigator.webdriver=true');
    if (!navigator.languages || navigator.languages.length === 0) issues.push(T('语言列表为空', 'Empty language list'));
    if (window.outerWidth === 0 && window.outerHeight === 0) issues.push(T('窗口尺寸为零', 'Zero window dimensions'));

    if (issues.length) {
      return { ok: false, tone: 'leak', status: T('发现自动化标记', 'Automation flags found'), note: issues.join(T('、', ', ')), penalty: 20 };
    }
    return { ok: true, tone: 'ok', status: T('未见常见自动化标记', 'No common automation flags found'), note: T('未见 WebDriver 标记 · 硬件线程 ', 'No WebDriver flag · hardware threads: ') + (navigator.hardwareConcurrency || '—'), penalty: 0 };
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
          return { ok: false, tone: 'leak', status: T('地区可能受限 (', 'Region may be restricted (') + aiLoc + ')', note: T('地区规则仅供参考，请使用单项工具复查', 'Region rules are indicative; verify with the individual tools'), penalty: 15 };
        }
        return { ok: true, tone: 'ok', status: T('已收到边缘响应 (', 'Edge response received (') + aiLoc + ')', note: T('边缘响应不代表已登录服务或 API 可用', 'An edge response does not confirm signed-in service or API access'), penalty: 0 };
      })
      .catch(function () {
        clearTimeout(timer);
        if (blockedCc.indexOf(cc) !== -1) {
          return { ok: false, tone: 'leak', status: T('连接失败，地区可能受限', 'Connection failed; region may be restricted'), note: T('未能连接 ChatGPT 探测接口', 'Could not reach the ChatGPT probe endpoint'), penalty: 15 };
        }
        return { ok: false, tone: 'warn', status: T('未收到有效响应', 'No valid response'), note: T('未能连通 chatgpt.com 边缘接口', 'Could not reach the chatgpt.com edge endpoint'), penalty: 8 };
      });
  }

  function run() {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    verdict.hidden = true;
    progress.textContent = T('正在检查网络与浏览器环境…', 'Checking network and browser settings…');

    ['purity', 'webrtc', 'dns', 'consistency', 'stealth', 'ai'].forEach(function (k) {
      setDimCell(k, 'muted', T('检测中…', 'Checking…'), '');
    });

    var serverVisibleIp = (root.getAttribute('data-visible-ip') || '').trim();

    detectPublicV4().then(function (v4) {
      var primaryIp = v4 || serverVisibleIp;
      var knownIps = [serverVisibleIp, v4].filter(Boolean);
      if (ipCell) ipCell.innerHTML = '<span class="mono">' + primaryIp + '</span>';

      return window.fetch('/api/ipinfo?ip=' + encodeURIComponent(primaryIp) + (en ? '&lang=en' : ''), { headers: { Accept: 'application/json' } })
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
            info ? info.ipTypeLabel + ' · ' + info.score + '/100 (' + info.grade + ')' : T('未能读取 IP 数据', 'Could not load IP data'),
            info ? (info.isNative ? T('原生 IP · ', 'Native IP · ') : T('广播 IP · ', 'Geo-announced IP · ')) + info.countryZh + ' ' + info.asnCode : ''
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
              passCell.textContent = passCount + T(' / 6 项通过', ' / 6 checks passed');
            }

            verdict.hidden = false;
            if (envScore >= 82 && passCount >= 5) {
              verdict.className = 'verdict is-good';
              verdictTitle.textContent = T('未见明显差异（参考评分 ', 'No major differences found (score ') + envScore + '/100)';
              verdictNote.textContent = T('已完成的检测未见明显差异。这不代表所有请求都使用同一出口，也不保证账号安全或服务可用。', 'Completed checks found no major differences. This does not confirm all requests use the same exit or guarantee account safety or service access.');
            } else if (envScore >= 55) {
              verdict.className = 'verdict is-warn';
              verdictTitle.textContent = T('部分项目需要复查（参考评分 ', 'Some checks need review (score ') + envScore + '/100)';
              verdictNote.textContent = T('需要复查的项目：', 'Checks to review: ') + (6 - passCount) + T('。请查看下方明细，确认是否符合你的网络设置。', '. Review the details below against your network settings.');
            } else {
              verdict.className = 'verdict is-bad';
              verdictTitle.textContent = T('发现多项差异或风险标记（参考评分 ', 'Multiple differences or risk flags found (score ') + envScore + '/100)';
              verdictNote.textContent = T('请逐项查看结果。地区差异、浏览器设置和请求失败都可能影响评分，不能据此判断平台会如何处理账号。', 'Review each result. Region differences, browser settings and failed requests can affect this score; it cannot predict how a platform will treat an account.');
            }

            running = false;
            runBtn.disabled = false;
            runBtn.textContent = T('重新检测', 'Run again');
            progress.textContent = T('检测已完成，请结合各项结果判断。', 'Checks complete. Review the individual results.');
          });
        });
    }).catch(function () {
      running = false;
      runBtn.disabled = false;
      runBtn.textContent = T('重试', 'Try again');
      progress.textContent = T('部分请求失败，请重试。', 'Some requests failed. Try again.');
    });
  }

  runBtn.addEventListener('click', run);
  // 打开页面即自动开始体检
  if (document.readyState === 'complete') run();
  else window.addEventListener('load', run);
})();
