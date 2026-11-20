/* JudgeIP — Claude 中国用户检测。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   信号清单、权重与打分规则来自开源项目 FuckClaude（MIT，© LinXiaoTao）
   https://github.com/LinXiaoTao/FuckClaude —— 原项目是 TypeScript + Astro，
   这里按本站「无构建、无框架」的约定重写成一段 ES5。
   权重不写在这里：它们由 src/ClaudeSignals.php 渲染进每一行的 data-weight，
   脚本从 DOM 上读回来，页面上印着的数字和脚本里算的永远是同一份。

   全部检测只读浏览器 API，探到的值不会离开这个页面。 */
(function () {
  'use strict';

  var root = document.getElementById('claude');
  if (!root) return;

  /* 逐项点亮的节奏：每一项至少停这么久，快得像一闪而过就看不出分数是从哪几项涨起来的 */
  var STEP_MS = 320;
  var WEBRTC_TIMEOUT = 2500;

  /* 与 ClaudeSignals::HIT / STRONG / BAND_* 一致 */
  var HIT = 0.25;
  var STRONG = 0.6;
  var BAND_LOW = 30;
  var BAND_MEDIUM = 60;

  var visibleIp = (root.getAttribute('data-visible-ip') || '').trim();
  var stunUrls = (root.getAttribute('data-stun') || '').split(' ').filter(Boolean);

  var runButton = root.querySelector('[data-claude-run]');
  var progress = root.querySelector('[data-claude-progress]');
  var verdict = root.querySelector('[data-claude-verdict]');
  var verdictTitle = root.querySelector('[data-claude-verdict-title]');
  var verdictNote = root.querySelector('[data-claude-verdict-note]');
  var fixNote = root.querySelector('[data-claude-fix]');
  var scoreCell = root.querySelector('[data-claude-score]');
  var bandCell = root.querySelector('[data-claude-band]');
  var hitsCell = root.querySelector('[data-claude-hits]');
  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-signal]'));

  /* ---------------------------------------------------------------- 数据表 */

  var CN_TIMEZONES = ['Asia/Shanghai', 'Asia/Urumqi', 'Asia/Chongqing', 'Asia/Chungking', 'Asia/Harbin', 'Asia/Kashgar'];
  /* 港澳在 Anthropic 的受限名单里，计部分风险；台湾不在，Asia/Taipei 不计分 */
  var GREATER_CN_TIMEZONES = ['Asia/Hong_Kong', 'Asia/Macau'];

  var FONTS_SC = [
    'Microsoft YaHei', 'Microsoft YaHei UI', 'SimSun', 'NSimSun', 'SimHei', 'KaiTi', 'FangSong', 'DengXian',
    'PingFang SC', 'Hiragino Sans GB', 'STHeiti', 'STSong', 'Songti SC',
    'Source Han Sans CN', 'Source Han Sans SC', 'Noto Sans CJK SC', 'Noto Serif CJK SC',
    'WenQuanYi Micro Hei', 'WenQuanYi Zen Hei'
  ];
  var FONTS_TC = [
    'Microsoft JhengHei', 'PMingLiU', 'MingLiU', 'DFKai-SB', 'PingFang TC', 'PingFang HK',
    'Source Han Sans TW', 'Noto Sans CJK TC'
  ];
  /* 国产厂商随系统预装、或国产软件顺手装上的字体（WPS 带方正 FZ*），境外环境几乎不会有 */
  var FONTS_CN_VENDOR = [
    'MiSans', 'MIUI', 'HarmonyOS Sans SC', 'HarmonyOS Sans', 'HONOR Sans', 'OPPO Sans', 'vivo Sans',
    'Alibaba PuHuiTi', 'Alibaba Sans', 'DingTalk JinBuTi', 'Douyin Sans', 'HYQiHei',
    'FZShuSong-Z01S', 'FZKai-Z03S', 'FZHei-B01S', 'FZFangSong-Z02S'
  ];

  /* 国产浏览器与应用内 WebView，同时匹配 UA 与 UA-CH brands */
  var CN_BROWSERS = [
    [/micromessenger|wxwork/i, '微信'],
    [/mqqbrowser|qqbrowser|\bqq\//i, 'QQ 浏览器'],
    [/quark/i, '夸克'],
    [/ucbrowser|ucweb/i, 'UC 浏览器'],
    [/baiduboxapp|bidubrowser|baidubrowser/i, '百度'],
    [/miuibrowser|xiaomi\/|mibrowser/i, '小米浏览器'],
    [/huaweibrowser/i, '华为浏览器'],
    [/heytapbrowser|oppobrowser/i, 'HeyTap（OPPO）'],
    [/vivobrowser/i, 'vivo 浏览器'],
    [/sogoumobilebrowser|\bmetasr\b|\bse 2\.x\b/i, '搜狗'],
    [/maxthon/i, '傲游'],
    [/360se|360ee|qihoobrowser|\bqhbrowser\b/i, '360 浏览器'],
    [/2345explorer|2345browser/i, '2345'],
    [/lbbrowser/i, '猎豹'],
    [/theworld/i, '世界之窗'],
    [/aweme|bytedancewebview|newsarticle|toutiaomicroapp/i, '抖音 / 头条'],
    [/alipayclient/i, '支付宝'],
    [/dingtalk/i, '钉钉'],
    [/weibo/i, '微博'],
    [/xiaohongshu|xhsminiapp/i, '小红书'],
    [/\bbilibili\b/i, 'Bilibili']
  ];

  /* 国产品牌设备。鸿蒙是决定性的；在海外也卖的品牌打低一点 */
  var CN_DEVICES = [
    [/harmonyos|openharmony/i, 'HarmonyOS', 1],
    [/huawei|\bhonor\b/i, '华为 / 荣耀', 0.8],
    [/meizu/i, '魅族', 0.8],
    [/nubia|\bzte\b/i, '中兴 / 努比亚', 0.7],
    [/xiaomi|redmi|\bpoco\b|\bm2\d{3}[a-z0-9]+\b/i, '小米', 0.6],
    [/oppo|\bpd[a-z]m\d{2}\b/i, 'OPPO', 0.6],
    [/vivo|\bv2\d{3}[a-z]{1,2}\b/i, 'vivo', 0.6],
    [/realme|\brmx\d{4}\b/i, 'realme', 0.6],
    [/oneplus/i, '一加', 0.6],
    [/\blenovo\b|\bzuk\b/i, '联想', 0.5]
  ];

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

  function outcome(raw, score) {
    return { raw: raw, score: Math.max(0, Math.min(1, score)) };
  }

  function now() {
    return (window.performance && performance.now) ? performance.now() : Date.now();
  }

  function timezoneName() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (e) {
      return '';
    }
  }

  /* UA-CH 的 brands 是 UA 缩减之后仅剩的、还能看出国产壳的地方 */
  function uaProbe() {
    var brands = '';
    var data = navigator.userAgentData;
    if (data && data.brands && data.brands.length) {
      brands = data.brands.map(function (b) { return b.brand; }).join(' ');
    }
    return (navigator.userAgent || '') + ' ' + brands;
  }

  /* ---------------------------------------------------------------- 探测函数 */

  /* 每个函数返回 { raw, score }：raw 是给人看的检测值，score 是 0–1 的「中国相似度」。
     可以同步返回，也可以返回 Promise；异常由主流程兜住，这里不必自己 try。 */

  function detectTimezone() {
    var tz = timezoneName();
    var score = CN_TIMEZONES.indexOf(tz) !== -1 ? 1
              : GREATER_CN_TIMEZONES.indexOf(tz) !== -1 ? 0.6
              : 0;
    return outcome(tz || '未知', score);
  }

  function detectTimezoneOffset() {
    var offset = new Date().getTimezoneOffset();
    var hours = -offset / 60;
    var raw = 'UTC' + (hours >= 0 ? '+' : '-') + Math.abs(hours);
    return outcome(raw, offset === -480 ? 0.7 : 0);
  }

  /* 语言列表的打分。zh-TW 是台湾，Anthropic 完全支持，不计分——连它后面浏览器自动补上的
     那个裸 "zh" 也一并忽略（"zh-TW, zh, en" 里的 zh 只是回退，不是偏好）；
     zh-HK / zh-MO 属受限地区，保留一半风险。 */
  function scoreLanguages(langs) {
    var list = [];
    var i;
    for (i = 0; i < langs.length; i++) {
      var l = (langs[i] || '').toLowerCase();
      if (l) list.push(l);
    }

    function isTW(l) { return l.indexOf('zh-tw') === 0 || (l.indexOf('hant') !== -1 && l.indexOf('tw') !== -1); }
    function isHKMO(l) { return l.indexOf('zh-hk') === 0 || l.indexOf('zh-mo') === 0; }
    function isTrad(l) { return isTW(l) || isHKMO(l) || l.indexOf('hant') !== -1; }

    var firstTrad = -1;
    for (i = 0; i < list.length; i++) {
      if (isTrad(list[i])) { firstTrad = i; break; }
    }

    /* 裸 "zh" 只有在它不是繁体偏好后面的回退项时才算简体 / 大陆 */
    function isHansCN(l, index) {
      return l.indexOf('zh-cn') === 0 || l.indexOf('hans') !== -1 ||
             (l === 'zh' && (firstTrad === -1 || index < firstTrad));
    }

    var kept = [];
    for (i = 0; i < list.length; i++) {
      if (isTW(list[i])) continue;
      if (list[i] === 'zh' && firstTrad !== -1 && i > firstTrad) continue;
      kept.push({ l: list[i], i: i });
    }

    if (!kept.length) return 0;
    if (isHansCN(kept[0].l, kept[0].i)) return 1;
    if (isHKMO(kept[0].l) || kept[0].l.indexOf('hant') !== -1) return 0.5;
    for (i = 0; i < kept.length; i++) {
      if (isHansCN(kept[i].l, kept[i].i)) return 0.7;
    }
    for (i = 0; i < kept.length; i++) {
      if (kept[i].l.indexOf('zh') === 0) return 0.4;
    }
    return 0;
  }

  function detectLanguage() {
    var langs = (navigator.languages && navigator.languages.length)
      ? Array.prototype.slice.call(navigator.languages)
      : [navigator.language];
    return outcome(langs.join(', ') || '未知', scoreLanguages(langs));
  }

  function detectIntlLocale() {
    var locale = '';
    try {
      locale = Intl.DateTimeFormat().resolvedOptions().locale || '';
    } catch (e) { /* 老浏览器没有 resolvedOptions，当作未知 */ }

    var l = locale.toLowerCase();
    var score = 0;
    if (l.indexOf('zh-cn') === 0 || l.indexOf('hans') !== -1 || l === 'zh') score = 1;
    else if (l.indexOf('zh') === 0 && l.indexOf('zh-tw') !== 0) score = 0.5;
    return outcome(locale || '未知', score);
  }

  /* canvas 量字宽：指定字体画出来的宽度和回退字体不一样，说明这个字体真的装着 */
  function fontContext() {
    var canvas = document.createElement('canvas');
    return canvas.getContext ? canvas.getContext('2d') : null;
  }

  function hasFont(ctx, font) {
    var text = '中文字体检测ABCabc012';
    var bases = ['monospace', 'sans-serif', 'serif'];
    for (var i = 0; i < bases.length; i++) {
      ctx.font = '72px ' + bases[i];
      var base = ctx.measureText(text).width;
      ctx.font = '72px "' + font + '", ' + bases[i];
      if (Math.abs(ctx.measureText(text).width - base) > 0.5) return true;
    }
    return false;
  }

  function probeFonts(ctx, list) {
    return list.filter(function (font) { return hasFont(ctx, font); });
  }

  function summarize(hit, limit) {
    return hit.slice(0, limit).join(', ') + (hit.length > limit ? '…（共 ' + hit.length + ' 种）' : '');
  }

  function detectFonts() {
    var ctx = fontContext();
    if (!ctx) return outcome('canvas 不可用', 0);

    var sc = probeFonts(ctx, FONTS_SC);
    var tc = probeFonts(ctx, FONTS_TC);

    var score = 0;
    if (sc.length) score = Math.min(1, 0.75 + 0.08 * sc.length);
    /* 只有繁体字体是台湾环境的典型形态，又分不清台湾与港澳——压在命中线以下 */
    else if (tc.length) score = 0.2;

    var hit = sc.concat(tc);
    return outcome(hit.length ? summarize(hit, 4) : '未检出', score);
  }

  function detectVendorFonts() {
    var ctx = fontContext();
    if (!ctx) return outcome('canvas 不可用', 0);

    var hit = probeFonts(ctx, FONTS_CN_VENDOR);
    /* 一种厂商字体就几乎定案，两种以上不再有疑问 */
    var score = hit.length >= 2 ? 1 : hit.length === 1 ? 0.8 : 0;
    return outcome(hit.length ? summarize(hit, 3) : '未检出', score);
  }

  function detectCnBrowser() {
    var probe = uaProbe();
    for (var i = 0; i < CN_BROWSERS.length; i++) {
      if (CN_BROWSERS[i][0].test(probe)) return outcome(CN_BROWSERS[i][1], 1);
    }
    return outcome('未检出', 0);
  }

  /* UA 缩减之后 Android 的机型只剩 "K"，真正的型号要向 UA-CH 要高熵值；拿不到就退回纯 UA */
  function detectDeviceVendor() {
    var data = navigator.userAgentData;
    var extra = Promise.resolve('');

    if (data && typeof data.getHighEntropyValues === 'function') {
      extra = data.getHighEntropyValues(['model', 'platform', 'platformVersion']).then(function (high) {
        return ' ' + String(high.model || '') + ' ' + String(high.platform || '');
      }, function () {
        return '';
      });
    }

    return extra.then(function (more) {
      var probe = (navigator.userAgent || '') + more;
      for (var i = 0; i < CN_DEVICES.length; i++) {
        if (CN_DEVICES[i][0].test(probe)) return outcome(CN_DEVICES[i][1], CN_DEVICES[i][2]);
      }
      return outcome('未检出', 0);
    });
  }

  /* emoji 由操作系统渲染，猜的是厂商。Apple 用户在海外占比更高、Linux 桌面在国内开发者里更常见，
     但这只是统计上的弱相关，所以权重只有 3 */
  function detectEmoji() {
    var p = ((navigator.platform || '') + ' ' + (navigator.userAgent || '')).toLowerCase();
    var vendor = /iphone|ipad|ipod|mac/.test(p) ? 'Apple'
               : /android/.test(p) ? 'Google'
               : /win/.test(p) ? 'Microsoft'
               : /cros/.test(p) ? 'Google'
               : /linux/.test(p) ? 'Linux / 其他'
               : '未知';
    var SCORES = { 'Apple': 0.25, 'Google': 0.35, 'Microsoft': 0.4, 'Linux / 其他': 0.5, '未知': 0.4 };
    return outcome(vendor + ' 风格', SCORES[vendor]);
  }

  function sameFamily(a, b) {
    return (a.indexOf(':') !== -1) === (b.indexOf(':') !== -1);
  }

  /* WebRTC：一次 ICE 收集，看浏览器会不会交出地址。
     与 /webrtc 那一页同一个判据——探到的公网地址 ≠ 本站在 HTTP 层看到的地址，才是真的漏了（记满分）；
     地址一致或只探到内网地址，是「这条旁路通着」（原项目的口径，记一半）；
     .local 结尾的是 mDNS 混淆，那是浏览器的保护生效了，不算地址。 */
  function detectWebrtc() {
    return new Promise(function (resolve) {
      var PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
      if (!PeerConnection || !stunUrls.length) {
        resolve(outcome('浏览器不支持 WebRTC', 0));
        return;
      }

      var publics = [];
      var locals = [];
      var settled = false;
      var pc;
      var timer;

      function finish() {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        try { pc.close(); } catch (e) { /* 已经关了就算了 */ }

        var comparable = publics.filter(function (a) { return visibleIp !== '' && sameFamily(a, visibleIp); });
        var leaked = comparable.filter(function (a) { return a !== visibleIp; });

        if (leaked.length) {
          resolve(outcome('公网地址 ' + leaked.join('、') + ' 与本站看到的 ' + visibleIp + ' 不一致', 1));
        } else if (publics.length) {
          resolve(outcome('探到公网地址 ' + publics.join('、') + (comparable.length ? '，与本站看到的一致' : ''), 0.5));
        } else if (locals.length) {
          resolve(outcome('探到内网地址 ' + locals.join('、'), 0.5));
        } else {
          resolve(outcome('未探到任何地址', 0));
        }
      }

      try {
        pc = new PeerConnection({ iceServers: [{ urls: stunUrls }] });
      } catch (e) {
        resolve(outcome('无法建立探测连接', 0));
        return;
      }

      pc.onicecandidate = function (event) {
        /* candidate 为 null 是收集结束的信号，不是一条地址 */
        if (!event.candidate || !event.candidate.candidate) {
          finish();
          return;
        }

        var candidate = event.candidate;
        var address = candidate.address || '';
        var type = candidate.type || '';

        if (!address || !type) {
          var parts = (candidate.candidate || '').split(' ');
          if (parts.length >= 8) {
            if (!address) address = parts[4];
            if (!type) type = parts[7];
          }
        }

        if (!address || /\.local$/i.test(address)) return;

        var bucket = (type === 'srflx' || type === 'prflx' || type === 'relay') ? publics : locals;
        if (bucket.indexOf(address) === -1) bucket.push(address);
      };

      pc.onicegatheringstatechange = function () {
        if (pc.iceGatheringState === 'complete') finish();
      };

      /* 没有数据通道就没有媒体需求，ICE 不会启动 */
      try {
        pc.createDataChannel('ipcx-claude');
      } catch (e) {
        finish();
        return;
      }

      pc.createOffer()
        .then(function (offer) { return pc.setLocalDescription(offer); })
        .catch(function () { finish(); });

      timer = window.setTimeout(finish, WEBRTC_TIMEOUT);
    });
  }

  var DETECTORS = {
    timezone: detectTimezone,
    language: detectLanguage,
    fonts: detectFonts,
    vendorFonts: detectVendorFonts,
    webrtcLeak: detectWebrtc,
    cnBrowser: detectCnBrowser,
    deviceVendor: detectDeviceVendor,
    intlLocale: detectIntlLocale,
    timezoneOffset: detectTimezoneOffset,
    emoji: detectEmoji
  };

  /* ---------------------------------------------------------------- 渲染 */

  /* 三档与页面其他检测共用同一套标签色：绿 = 不像、琥珀 = 命中、红 = 强命中 */
  function tone(score) {
    return score >= STRONG ? 'leak' : score >= HIT ? 'warn' : 'ok';
  }

  var BANDS = {
    low: {
      badge: 'green', score: 'good', tone: 'is-good', name: '低风险',
      title: '低风险：浏览器环境不像中国用户',
      note: '从浏览器可见的这几项指纹看，你的环境没有明显的中国痕迹。注意这只是本地环境的判断——'
          + '出口 IP 的归属、支付方式与账号行为都不在本页的观察范围内。'
    },
    medium: {
      badge: 'amber', score: 'warn', tone: 'is-warn', name: '中等风险',
      title: '中等风险：部分信号指向中国环境',
      note: '有几项指纹指向中国环境，叠在一起已经足以让风控系统提高警惕。'
          + '时区与语言权重最高、也最容易改，先从它们下手，改完回到本页重测。'
    },
    high: {
      badge: 'red', score: 'bad', tone: 'is-bad', name: '高风险',
      title: '高风险：很可能被判为中国用户',
      note: '多项高权重信号同时命中。以 Claude Code 已披露的机制看，这样的环境每一次请求都会带上「像中国用户」的标记。'
          + '按下文的清单逐项处理，尤其是系统时区。'
    }
  };

  function bandOf(total) {
    return total <= BAND_LOW ? BANDS.low : total <= BAND_MEDIUM ? BANDS.medium : BANDS.high;
  }

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function svg(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    for (var key in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, key)) node.setAttribute(key, String(attrs[key]));
    }
    return node;
  }

  /* 和首页 IP 评分同一个组件（View::scoreBar）：进度用 <rect width> 表达，
     CSP 里 style-src 只有 'self'，行内 style 会被整条丢掉；表现属性不受约束，宽度即分数。 */
  function scoreNode(total) {
    var band = bandOf(total);
    var wrap = el('span', 'score score--' + band.score);
    var bar = svg('svg', { 'class': 'score__bar', viewBox: '0 0 100 6', role: 'img',
                           'aria-label': '风险分 ' + total + ' 分，满分 100 分' });
    bar.appendChild(svg('rect', { 'class': 'score__track', x: 0, y: 0, width: 100, height: 6, rx: 3 }));
    if (total > 0) {
      bar.appendChild(svg('rect', { 'class': 'score__fill', x: 0, y: 0, width: total, height: 6, rx: 3 }));
    }
    wrap.appendChild(bar);

    var num = el('span', 'score__num mono', String(total));
    num.appendChild(el('span', 'score__total', '/100'));
    wrap.appendChild(num);
    return wrap;
  }

  function renderRow(cell, result, points) {
    var t = tone(result.score);
    fill(cell, [
      el('span', 'tag tag--' + t + ' sig__value', result.raw),
      el('span', 'sig__points mono' + (t === 'ok' ? '' : ' sig__points--' + t), '+' + points)
    ]);
  }

  function hitsNode(hits) {
    var tags = el('span', 'tags');
    hits.forEach(function (hit) {
      tags.appendChild(el('span', 'tag tag--' + tone(hit.score), hit.name + ' +' + hit.points));
    });
    return tags;
  }

  function finalize(total, hits) {
    var band = bandOf(total);

    fill(scoreCell, [scoreNode(total)]);
    fill(bandCell, [el('span', 'badge badge--' + band.badge, band.name)]);
    fill(hitsCell, hits.length ? [hitsNode(hits)] : [el('span', 'tag tag--ok', '无')]);

    verdict.className = 'verdict ' + band.tone;
    verdict.hidden = false;
    verdictTitle.textContent = total + ' / 100 · ' + band.title;
    verdictNote.textContent = band.note + (hits.length
      ? '命中 ' + hits.length + ' 项：' + hits.map(function (hit) { return hit.name + '（+' + hit.points + '）'; }).join('、') + '。'
      : '没有命中任何信号。');

    /* 低风险的人不需要被塞一份整改清单 */
    if (fixNote) fixNote.hidden = band === BANDS.low;

    progress.textContent = '检测完成，共 ' + rows.length + ' 项信号，命中 ' + hits.length + ' 项。';
    runButton.disabled = false;
    runButton.textContent = '重新检测';
  }

  /* ---------------------------------------------------------------- 主流程 */

  function run() {
    runButton.disabled = true;
    verdict.hidden = true;
    if (fixNote) fixNote.hidden = true;

    rows.forEach(function (row) {
      row.classList.remove('is-active', 'is-done');
      fill(row.querySelector('[data-sig-result]'), [el('span', 'dim', '待检测')]);
    });
    fill(scoreCell, [scoreNode(0)]);
    fill(bandCell, [el('span', 'dim', '检测中…')]);
    fill(hitsCell, [el('span', 'dim', '检测中…')]);

    var total = 0;
    var hits = [];
    var index = 0;

    /* 串行逐项：分数是一项一项涨上去的，读者要能看到它从哪几项上涨起来 */
    function next() {
      if (index >= rows.length) {
        finalize(total, hits);
        return;
      }

      var row = rows[index];
      var id = row.getAttribute('data-signal');
      var name = row.getAttribute('data-name') || id;
      var weight = parseInt(row.getAttribute('data-weight'), 10) || 0;
      var cell = row.querySelector('[data-sig-result]');
      var detector = DETECTORS[id];
      var started = now();

      row.classList.add('is-active');
      fill(cell, [el('span', 'dim', '检测中…')]);
      progress.textContent = '正在检测第 ' + (index + 1) + ' / ' + rows.length + ' 项：' + name + '…';

      Promise.resolve()
        .then(function () { return detector ? detector() : outcome('未实现', 0); })
        .catch(function () { return outcome('检测失败', 0); })
        .then(function (result) {
          /* 探测本身几毫秒就完，补足到 STEP_MS 再落地，节奏才看得见 */
          window.setTimeout(function () {
            var points = Math.round(result.score * weight);
            total = Math.min(100, total + points);
            if (result.score >= HIT) hits.push({ name: name, points: points, score: result.score });

            row.classList.remove('is-active');
            row.classList.add('is-done');
            renderRow(cell, result, points);
            fill(scoreCell, [scoreNode(total)]);

            index += 1;
            next();
          }, Math.max(0, STEP_MS - (now() - started)));
        });
    }

    next();
  }

  runButton.addEventListener('click', run);
})();
