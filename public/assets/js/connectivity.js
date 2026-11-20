/* JudgeIP — 网络连通性。/connectivity 整页与首页「网络连通性」卡片共用这一个文件。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   原理：对每个站点发 no-cors 的 HEAD 请求，只看「有没有响应、花了多久」——
   跨站响应的内容读不到，也不需要读：404、403 一样说明线路是通的，只有网络错误与超时算失败。
   请求本身由 IpcxProbe.timing 发出（不带 Cookie、不带 Referer、不走缓存、3 秒超时），这里只管调度与解读。

   几处刻意的取舍：
   - 每个站点先发一次不计入结果的预热：第一次请求要做 DNS + TCP + TLS，比后面几轮慢好几倍，
     计进去中位数就被它带偏了。之后几轮复用同一条连接，测到的才是线路本身。
   - 6 路并发、轮间加随机间隔：几十个请求同一瞬间发出去会互相抢带宽，测出来的延迟比真实值高一截。
   - 预热和前两轮全失败就不再测剩下几轮：没开代理时国际站点成片超时，每个都硬等 6 × 3 秒，
     一页要卡一分多钟，换来的只是同一个「不可达」。跳过的轮次画成空心圆，不冒充测过。
   - 结论里「中国大陆网络」那套措辞只在数据像大陆网络时才用（见 verdictFor）：
     同样是「国内站点慢、国外快」，在上海是开了全局代理，在法兰克福只是正常的物理距离。

   首页卡片自动开始，但要等页面安顿下来、卡片滚进视口：不抢首屏带宽，也不替没往下看的访客去请求第三方。
   整页一安顿下来就自动开始——访客点进这一页就是为了看结果。「安顿下来」的定义见 whenSettled。

   每一格测完后整格是一个按钮：点一下（鼠标、触屏都行，键盘 Tab 到它按回车也行）展开这一格的详情——
   每一轮的延迟、失败原因、探测地址。这些以前只放在 title 里，触屏和键盘根本看不到。

   结果只留在当前页面里，不回传本站。 */
(function (window, document) {
  'use strict';

  var roots = document.querySelectorAll('[data-conn]');
  if (!roots.length) return;

  var P = window.IpcxProbe;

  var TIMEOUT = 3000;
  var LANES = 6;
  /* 一轮结束到下一轮开始至少隔这么久，再加一段随机抖动，几个站点的请求就不会齐步走 */
  var MIN_GAP = 80;
  var JITTER = 120;
  var GOOD_MS = 100;
  var OK_MS = 250;
  /* 预热失败、且还一次都没成功时，再连续失败这么多轮就判不可达 */
  var GIVE_UP_AFTER = 2;
  /* 一个站点的每一次失败（含预热）都比这还快，就不可能是网络往返：多半是扩展、安全软件在本地拦下了。
     只看「最近一次」不行——域名解析失败的结果会被缓存，第二次起同样是瞬间失败，
     但它的第一次（预热）要真的去问一趟 DNS，慢得多。 */
  var INSTANT_MS = 50;

  /* 系统时区落在中国大陆。只用来决定结论的措辞，不离开这个页面 */
  var MAINLAND_TZ = ['Asia/Shanghai', 'Asia/Urumqi', 'Asia/Chongqing', 'Asia/Chungking', 'Asia/Harbin', 'Asia/Kashgar', 'PRC'];

  /* 每一格的详情块要有全页唯一的 id（aria-controls 指向它）；站点键在两个检测区之间可能重复，用计数器 */
  var detailSeq = 0;

  var GROUP_NAMES = {
    cn: '国内', intl: '国际', ai: 'AI 服务', social: '社交与流媒体', dev: '开发与游戏', region: '地区'
  };

  /* 探测做不了的两种情况，都要说清楚，而不是让格子永远停在「待检测」：
     - probe.js 没加载上（网络抖了一下、被扩展拦了）：刷新多半就好，照实说；
     - 太老的浏览器（没有 fetch / Promise）：刷新也没用，请他换浏览器。
     整页把话写在进度提示那一行；首页卡片没有进度行，写在卡片自带的 data-conn-notice 里。 */
  function unavailable(message, stateText) {
    Array.prototype.forEach.call(roots, function (root) {
      var hint = root.querySelector('[data-conn-progress]') || root.querySelector('[data-conn-notice]');
      var run = root.querySelector('[data-conn-run]');
      if (hint) {
        hint.textContent = message;
        hint.hidden = false;
      }
      if (run) run.disabled = true;
      Array.prototype.forEach.call(root.querySelectorAll('[data-conn-regroup]'), function (button) {
        button.disabled = true;
      });
      /* 沿用「待检测」那枚小字的样式（.conntile__wait），只换字 */
      Array.prototype.forEach.call(root.querySelectorAll('[data-conn-state]'), function (cell) {
        var word = document.createElement('span');
        word.className = 'conntile__wait';
        word.textContent = stateText;
        cell.textContent = '';
        cell.appendChild(word);
      });
    });
  }

  if (!P) {
    unavailable('检测脚本加载失败，请刷新页面重试。', '未加载');
    return;
  }

  if (!window.fetch || !window.Promise) {
    unavailable('当前浏览器太旧，不支持网页发起这类探测请求，换用较新版本的 Chrome、Edge、Firefox 或 Safari 即可。', '不支持');
    return;
  }

  /* 全页共用一条队列：整页检测、分组重测同时进行时，总并发也不会超过 LANES */
  var queue = P.queue(LANES);

  var mainlandTz = (function () {
    try {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      return MAINLAND_TZ.indexOf(tz) !== -1;
    } catch (e) {
      return false;
    }
  })();

  /* ---------------------------------------------------------------- 工具 */

  var el = P.el;

  function fill(cell, nodes) {
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) cell.appendChild(nodes[i]);
  }

  function toArray(list) {
    return Array.prototype.slice.call(list);
  }

  function tone(ms) {
    return ms <= GOOD_MS ? 'good' : ms <= OK_MS ? 'ok' : 'slow';
  }

  function showMs(ms) {
    return Math.min(ms, 999) + 'ms';
  }

  /* 失败原因：IpcxProbe 给出三类（timeout / csp / error），「连接失败」再按耗时拆出「本地拦截」。
     slowest 是这个站点所有失败里最慢的一次 */
  function failText(kind, slowest) {
    if (kind === 'csp') {
      return P.failureText(kind) + '：本站的内容安全策略没有放行这个地址（地址在清单里却仍被拦，多半是它跳转到了别的主机）';
    }
    if (kind === 'timeout') {
      return P.failureText(kind) + '：' + (TIMEOUT / 1000) + ' 秒内没有任何响应';
    }
    if (typeof slowest === 'number' && slowest >= 0 && slowest < INSTANT_MS) {
      return '瞬间失败（' + slowest + 'ms 内）：请求没有真正发出去，多半是浏览器扩展或安全软件在本地拦下了它，不一定是网络不通';
    }
    return P.failureText(kind) + '：连接被重置、证书错误或域名解析失败';
  }

  function tag(text, kind) {
    return el('span', 'tag ' + kind, text);
  }

  /* 「百度、微信、淘宝 等 5 个」 */
  function names(list, max) {
    var shown = list.slice(0, max).map(function (t) { return t.name; }).join('、');
    return list.length > max ? shown + ' 等 ' + list.length + ' 个' : shown;
  }

  /* 页面「安顿下来」：window 的 load 与「本脚本运行后 SETTLE_MS」两者谁先到算谁。
     只等 load 不行：load 要等所有 async 脚本（统计、Turnstile）都下载完，第三方一慢或被墙，
     整块就一直停在「待检测」，最坏要等到 TCP 连接超时。defer 脚本在 DOMContentLoaded 前一刻运行，
     所以这个计时器差不多就是从 DOMContentLoaded 起算：正常情况下 load 早就到了，第三方卡住时最多晚这么久。
     homenet.js 里有一份一模一样的，两块挨在首页上，要同时动手。 */
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

  /* 后台标签页里的定时器会被节流，测出来的延迟全是虚高的——等页面真的被看到再开始 */
  function whenShown(callback) {
    if (!document.hidden) {
      callback();
      return;
    }
    var onChange = function () {
      if (document.hidden) return;
      document.removeEventListener('visibilitychange', onChange);
      callback();
    };
    document.addEventListener('visibilitychange', onChange);
  }

  function whenInView(node, callback) {
    if (!('IntersectionObserver' in window)) {
      window.setTimeout(callback, 1500);
      return;
    }
    var observer = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          observer.disconnect();
          callback();
          return;
        }
      }
    });
    observer.observe(node);
  }

  /* ---------------------------------------------------------------- 统计 */

  /* 一组格子的结果：CSP 拦下的不计入——那是本站的配置问题，不是访客的网络 */
  function stats(tiles) {
    var counted = tiles.filter(function (t) { return t.done && !t.csp; });
    var reached = counted.filter(function (t) { return t.samples.length > 0; });
    return {
      n: counted.length,
      reach: reached.length,
      ratio: counted.length ? reached.length / counted.length : NaN,
      mid: P.median(reached.map(function (t) { return t.median; })),
      down: counted.filter(function (t) { return t.samples.length === 0; })
    };
  }

  /* ---------------------------------------------------------------- 一个检测区 */

  function setup(root) {
    var rounds = parseInt(root.getAttribute('data-rounds'), 10) || 6;
    var auto = root.getAttribute('data-conn-auto') || '';

    var runButton = root.querySelector('[data-conn-run]');
    var progress = root.querySelector('[data-conn-progress]');
    var verdict = root.querySelector('[data-conn-verdict]');
    var verdictTitle = root.querySelector('[data-conn-verdict-title]');
    var verdictNote = root.querySelector('[data-conn-verdict-note]');

    var tiles = toArray(root.querySelectorAll('[data-conn-url]')).map(function (node) {
      var label = node.querySelector('.conntile__label');
      return {
        node: node,
        url: node.getAttribute('data-conn-url') || '',
        group: node.getAttribute('data-conn-group') || '',
        name: label ? label.textContent : (node.getAttribute('data-conn-key') || ''),
        label: label,
        nameLine: null,
        msCell: node.querySelector('[data-conn-ms]'),
        dotsCell: node.querySelector('[data-conn-dots]'),
        stateCell: node.querySelector('[data-conn-state]'),
        detail: null,
        dots: [],
        warm: '',
        roundText: [],
        token: 0,
        samples: [],
        fails: 0,
        lastKind: '',
        slowestFail: -1,
        median: null,
        warmFailed: false,
        skipped: 0,
        csp: false,
        done: false,
        busy: false
      };
    }).filter(function (t) { return t.url && t.msCell && t.dotsCell && t.stateCell; });

    if (!tiles.length) return;

    var sections = toArray(root.querySelectorAll('[data-conn-section]')).map(function (node) {
      var key = node.getAttribute('data-conn-section');
      return {
        key: key,
        sum: node.querySelector('[data-conn-sum]'),
        button: node.querySelector('[data-conn-regroup]'),
        tiles: tiles.filter(function (t) { return t.group === key; })
      };
    });

    var fullRun = false;
    var everRan = false;

    /* -------------------------------------------------------------- 格子 */

    /* 服务端按页面的轮数摆好了圆点；万一和 data-rounds 对不上（缓存的旧 HTML），按轮数重摆 */
    function resetTile(t) {
      t.token++;
      t.warm = '';
      t.roundText = [];
      t.samples = [];
      t.fails = 0;
      t.lastKind = '';
      t.slowestFail = -1;
      t.median = null;
      t.warmFailed = false;
      t.skipped = 0;
      t.csp = false;
      t.done = false;
      t.busy = true;

      if (t.dotsCell.children.length !== rounds) {
        var dots = [];
        for (var i = 0; i < rounds; i++) dots.push(el('i', 'dot'));
        fill(t.dotsCell, dots);
      }
      t.dots = toArray(t.dotsCell.children);
      t.dots.forEach(function (dot) {
        dot.className = 'dot';
        dot.removeAttribute('title');
      });

      t.msCell.className = 'conntile__ms mono conn-live';
      t.msCell.textContent = '—';
      t.node.classList.remove('is-down');
      collapse(t);
      fill(t.stateCell, [el('span', 'conntile__wait', '排队中')]);
    }

    function record(t, round, result) {
      var dot = t.dots[round];
      var label = '第 ' + (round + 1) + ' 轮：';

      if (result.ok) {
        t.samples.push(result.ms);
        t.roundText[round] = result.ms + 'ms';
        if (dot) dot.className = 'dot dot--' + tone(result.ms);
      } else {
        t.fails++;
        t.lastKind = result.kind || 'error';
        t.slowestFail = Math.max(t.slowestFail, result.ms);
        t.roundText[round] = P.failureText(t.lastKind);
        if (dot) dot.className = 'dot dot--fail';
      }
      /* 悬停提示只是桌面上的顺手一瞥；同样的内容在展开的详情里，触屏与键盘也拿得到 */
      if (dot) dot.title = label + t.roundText[round];

      t.median = P.median(t.samples);
      if (t.median !== null) {
        t.msCell.className = 'conntile__ms mono conn-live is-' + tone(t.median);
        t.msCell.textContent = showMs(t.median);
      }
    }

    /* 剩下的轮次不再测：画成空心圆，标明是跳过而不是失败 */
    function skipFrom(t, round, why) {
      for (var i = round; i < t.dots.length; i++) {
        t.roundText[i] = '未测';
        t.dots[i].className = 'dot dot--skip';
        t.dots[i].title = '第 ' + (i + 1) + ' 轮：未测（' + why + '）';
      }
      t.skipped = t.dots.length - round;
    }

    /* -------------------------------------------------------------- 详情

       结论（为什么不可达、哪几轮失败）不能只放在 title 里：触屏上没有悬停，键盘也聚焦不到一个 <span>。
       所以每格测完后，状态标签包进一个真正的 <button>，点击区用 ::after 铺满整格（见 connectivity.css），
       点一下在格子底部展开详情，再点一下收起。详情块挂在格子里、紧挨着它所说明的那一格，
       而不是统一放在分组底下——手机上一组十个格子，底下那块常常在屏幕外。 */

    function detailOf(t) {
      if (!t.detail) {
        detailSeq++;
        t.detail = el('div', 'conntile__detail');
        t.detail.id = 'conn-detail-' + detailSeq;
        t.detail.hidden = true;
        t.node.appendChild(t.detail);
      }
      return t.detail;
    }

    function collapse(t) {
      t.node.classList.remove('is-open');
      if (t.detail) {
        t.detail.hidden = true;
        t.detail.textContent = '';
      }
    }

    function toggle(t, button) {
      var open = button.getAttribute('aria-expanded') !== 'true';
      /* 名字只在被省略号截断时才在详情里重复一遍；截没截断要看此刻的版面（窄屏、两枚标签都会挤它） */
      if (open && t.nameLine) {
        t.nameLine.hidden = !(t.label && t.label.scrollWidth > t.label.clientWidth + 1);
      }
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
      detailOf(t).hidden = !open;
      if (open) t.node.classList.add('is-open');
      else t.node.classList.remove('is-open');
    }

    /* 「预热（不计入）：182ms；各轮：45ms、47ms、超时、未测」 */
    function roundsLine(t) {
      var parts = [];
      for (var i = 0; i < rounds; i++) parts.push(t.roundText[i] || '未测');
      return '预热（不计入）：' + (t.warm || '未测') + '；各轮：' + parts.join('、');
    }

    function finish(t) {
      t.done = true;
      t.busy = false;
      var tags = [];
      var summary;

      if (t.csp) {
        tags.push(tag('CSP 未放行', 'tag--muted'));
        summary = failText('csp');
        t.msCell.className = 'conntile__ms mono conn-live is-fail';
        t.msCell.textContent = '—';
      } else if (!t.samples.length) {
        var tested = rounds - t.skipped;
        var head = t.skipped
          ? '预热与前 ' + tested + ' 轮均失败，其余 ' + t.skipped + ' 轮未测。'
          : rounds + ' 轮全部失败。';
        tags.push(tag('不可达', 'tag--leak'));
        summary = head + failText(t.lastKind, t.slowestFail) + '。';
        t.msCell.className = 'conntile__ms mono conn-live is-fail';
        t.msCell.textContent = t.lastKind === 'timeout' ? '超时' : '失败';
        t.node.classList.add('is-down');
      } else {
        var level = tone(t.median);
        var quality = level === 'good' ? '优' : level === 'ok' ? '良' : '慢';
        tags.push(tag(quality, level === 'slow' ? 'tag--warn' : 'tag--ok'));
        summary = '成功 ' + t.samples.length + '/' + rounds + ' 轮，中位 ' + t.median + 'ms。';
        if (t.fails > 0) {
          tags.push(tag('不稳定', 'tag--warn'));
          summary += '失败 ' + t.fails + ' 轮，最近一次为' + failText(t.lastKind, t.slowestFail) + '。';
        }
      }

      /* 逐轮明细只给连上过的格子：一次没连上的，开头那句「预热与前 2 轮均失败」已经说完了，
         再列一串「失败、失败、未测、未测」只会把手机上的格子撑得更长 */
      var detail = detailOf(t);
      t.nameLine = el('span', 'conntile__line conntile__fullname', t.name);
      t.nameLine.hidden = true;
      fill(detail, [
        t.nameLine,
        el('span', 'conntile__line', summary),
        t.samples.length ? el('span', 'conntile__line', roundsLine(t)) : null,
        el('span', 'conntile__line conntile__url', '探测地址：' + t.url.replace(/^https:\/\//, ''))
      ].filter(Boolean));
      detail.hidden = true;

      var button = el('button', 'conntile__toggle');
      button.type = 'button';
      button.setAttribute('aria-expanded', 'false');
      button.setAttribute('aria-controls', detail.id);
      /* 读屏器只听到「良」不知道是哪一站：把站名带上；展开 / 收起由 aria-expanded 播报 */
      button.setAttribute('aria-label', t.name + '：' + tags.map(function (n) { return n.textContent; }).join('、') + '，详情');
      tags.forEach(function (node) { button.appendChild(node); });
      var chevron = el('span', 'conntile__chev');
      chevron.setAttribute('aria-hidden', 'true');
      button.appendChild(chevron);
      button.addEventListener('click', function () { toggle(t, button); });

      fill(t.stateCell, [button]);
    }

    /* 一个站点：预热一次，再测 rounds 轮。token 变了说明这一格已经被重测接管，旧的这一趟静默收手 */
    function probeTile(t, token) {
      if (t.token !== token) return Promise.resolve();
      fill(t.stateCell, [el('span', 'conntile__wait', '检测中')]);

      return P.timing(t.url, null, TIMEOUT).then(function (warm) {
        if (t.token !== token) return null;

        /* CSP 拦截是确定性的，再测几轮也是同一个结果 */
        if (!warm.ok && warm.kind === 'csp') {
          t.csp = true;
          t.warm = P.failureText('csp');
          skipFrom(t, 0, 'CSP 未放行');
          finish(t);
          return null;
        }

        t.warmFailed = !warm.ok;
        t.warm = warm.ok ? warm.ms + 'ms' : P.failureText(warm.kind || 'error');
        if (!warm.ok) {
          t.lastKind = warm.kind || 'error';
          t.slowestFail = Math.max(t.slowestFail, warm.ms);
        }
        return nextRound(t, token, 0);
      });
    }

    function nextRound(t, token, round) {
      if (t.token !== token) return null;

      if (round >= rounds) {
        finish(t);
        return null;
      }

      if (t.warmFailed && !t.samples.length && t.fails >= GIVE_UP_AFTER) {
        skipFrom(t, round, '已判定不可达');
        finish(t);
        return null;
      }

      var started = P.now();

      return P.timing(t.url, null, TIMEOUT).then(function (result) {
        if (t.token !== token) return null;

        if (!result.ok && result.kind === 'csp') {
          t.csp = true;
          record(t, round, result);
          skipFrom(t, round + 1, 'CSP 未放行');
          finish(t);
          return null;
        }

        record(t, round, result);

        if (round + 1 >= rounds) {
          finish(t);
          return null;
        }

        var wait = Math.max(0, MIN_GAP - (P.now() - started)) + Math.random() * JITTER;
        return P.sleep(wait).then(function () { return nextRound(t, token, round + 1); });
      });
    }

    /* -------------------------------------------------------------- 汇总 */

    function updateProgress() {
      if (!progress || !fullRun) return;
      var done = tiles.filter(function (t) { return t.done; }).length;
      progress.textContent = '检测中：已完成 ' + done + ' / ' + tiles.length + ' 个站点…';
    }

    function updateSection(section) {
      if (!section.sum) return;
      var pending = section.tiles.filter(function (t) { return !t.done; }).length;

      if (pending) {
        section.sum.className = 'connhead__sum conn-live';
        section.sum.textContent = '检测中 ' + (section.tiles.length - pending) + '/' + section.tiles.length;
        return;
      }

      var s = stats(section.tiles);
      if (!s.n) {
        section.sum.className = 'connhead__sum conn-live is-bad';
        section.sum.textContent = 'CSP 未放行';
        return;
      }

      section.sum.className = 'connhead__sum conn-live ' + (s.ratio >= 0.75 ? 'is-good' : s.ratio >= 0.5 ? 'is-warn' : 'is-bad');
      section.sum.textContent = '可达 ' + s.reach + '/' + s.n + (s.mid !== null ? ' · 中位 ' + showMs(s.mid) : '');
    }

    function sectionOf(t) {
      for (var i = 0; i < sections.length; i++) {
        if (sections[i].key === t.group) return sections[i];
      }
      return null;
    }

    function setButtons() {
      var anyBusy = tiles.some(function (t) { return t.busy; });
      if (runButton) {
        runButton.disabled = anyBusy;
        runButton.textContent = fullRun ? '检测中…' : everRan ? '重新检测' : '开始检测';
      }
      sections.forEach(function (section) {
        if (!section.button) return;
        section.button.disabled = fullRun || section.tiles.some(function (t) { return t.busy; });
      });
    }

    /* 把一批格子交给队列。整页检测与分组重测都走这里 */
    function start(list) {
      everRan = true;
      list.forEach(resetTile);
      sections.forEach(function (section) {
        if (section.tiles.some(function (t) { return list.indexOf(t) !== -1; })) updateSection(section);
      });
      setButtons();

      return Promise.all(list.map(function (t) {
        var token = t.token;
        return queue.add(function () { return probeTile(t, token); }).then(null, function () {
          /* 正常情况下走不到这里（timing 从不 reject）；万一 DOM 出了岔子，也别让这一格永远停在「检测中」 */
          if (t.token === token && !t.done) {
            t.lastKind = 'error';
            finish(t);
          }
        }).then(function () {
          var section = sectionOf(t);
          if (section) updateSection(section);
          updateProgress();
        });
      }));
    }

    function runAll() {
      if (tiles.some(function (t) { return t.busy; })) return;
      var began = P.now();
      fullRun = true;
      if (verdict) verdict.hidden = true;
      updateProgress();

      start(tiles).then(function () {
        fullRun = false;
        setButtons();
        if (progress) {
          progress.textContent = '检测完成，用时 ' + Math.max(1, Math.round((P.now() - began) / 1000)) + ' 秒。'
            + '每个站点 ' + rounds + ' 轮，延迟取成功轮次的中位数；点一下站点格子，可以展开每一轮的延迟与失败原因。';
        }
        renderVerdict();
      });
    }

    function rerunSection(section) {
      if (fullRun || section.tiles.some(function (t) { return t.busy; })) return;
      start(section.tiles).then(function () {
        setButtons();
        /* 每一格都至少测完过一次，结论才有意义 */
        if (tiles.every(function (t) { return t.done; })) renderVerdict();
      });
    }

    /* -------------------------------------------------------------- 结论 */

    function renderVerdict() {
      if (!verdict || !verdictTitle || !verdictNote) return;
      var result = verdictFor(tiles);
      verdict.className = 'verdict ' + result.tone;
      verdict.hidden = false;
      verdictTitle.textContent = result.title;
      verdictNote.textContent = result.note;
    }

    if (runButton) runButton.addEventListener('click', runAll);
    sections.forEach(function (section) {
      if (section.button) {
        section.button.addEventListener('click', function () { rerunSection(section); });
      }
    });

    /* 自动开始之前访客已经自己点过「开始检测」的，就不再替他跑第二遍 */
    function autoRun() {
      if (!everRan) runAll();
    }

    if (auto === 'view') {
      whenSettled(function () {
        whenInView(root, function () { whenShown(autoRun); });
      });
    } else if (auto === 'load') {
      whenSettled(function () { whenShown(autoRun); });
    }
  }

  /* ---------------------------------------------------------------- 结论规则

     按顺序取第一条成立的：
       (0) 一个都没连上 / 全被 CSP 拦下
       (a) 国际基本不通、国内正常        → 没开代理，或代理没生效
       (b) 国际正常、AI 基本不通         → 分流规则漏了 AI 域名
       (c) 国内正常但比国外还慢          → 全局模式，国内流量也出境了
       (d) 国际正常、国内基本不通        → 国内流量出境后受阻
       (e) 每组都 ≥75% 可达              → 良好
       否则列出不可达的站点。
     (a)–(d) 只在「看起来是中国大陆网络」时才说：国内站点又全又快（直连境内）、
     或国际站点大面积不通、或系统时区在大陆。境外访客看到的国内站点本来就慢，
     套用这几条只会把正常的物理距离说成「开了全局代理」。 */
  function verdictFor(tiles) {
    var byGroup = {};
    tiles.forEach(function (t) {
      (byGroup[t.group] = byGroup[t.group] || []).push(t);
    });

    var all = stats(tiles);
    var cn = stats(byGroup.cn || []);
    var intl = stats(byGroup.intl || []);
    var ai = stats(byGroup.ai || []);

    var cspCount = tiles.filter(function (t) { return t.csp; }).length;
    var shaky = tiles.filter(function (t) { return t.samples.length && t.fails; }).length;
    var tail = '';
    if (shaky >= 3) {
      tail += '另有 ' + shaky + ' 个站点部分轮次失败（不稳定），线路可能有丢包。';
    }
    if (cspCount) {
      tail += cspCount + ' 个站点被本页的内容安全策略（CSP）拦下，属于本站配置问题，已从统计中排除。';
    }

    if (!all.n) {
      return {
        tone: 'is-bad',
        title: '无法检测：所有站点都被本页的 CSP 拦下',
        note: '这是本站的部署配置问题（connect-src 没有放行这些站点），与你的网络无关。'
      };
    }

    if (!all.reach) {
      return {
        tone: 'is-bad',
        title: '所有站点都连不上',
        note: '包括国内站点在内，一个都没有响应。先确认网络本身是通的；如果别的网页能正常打开，'
          + '多半是浏览器扩展（广告拦截、隐私保护）、安全软件或公司防火墙拦下了这类跨站请求。' + tail
      };
    }

    var cnMs = cn.mid !== null ? showMs(cn.mid) : '—';
    var intlMs = intl.mid !== null ? showMs(intl.mid) : '—';
    var mainland = (cn.ratio >= 0.75 && cn.mid !== null && cn.mid < 80) || intl.ratio < 0.5 || mainlandTz;

    if (mainland) {
      if (intl.ratio < 0.5 && cn.ratio >= 0.75) {
        return {
          tone: 'is-bad',
          title: '国际网站基本不通：没有使用代理，或代理 / 分流没有生效',
          note: '国内站点 ' + cn.reach + '/' + cn.n + ' 可达（中位 ' + cnMs + '），国际站点只有 ' + intl.reach + '/' + intl.n + ' 能连上。'
            + '确认代理客户端在运行、系统代理或 TUN 模式已经打开，并且浏览器没有绕过系统代理。' + tail
        };
      }

      if (intl.ratio >= 0.75 && ai.ratio < 0.5) {
        return {
          tone: 'is-warn',
          title: '国际网站正常，但 AI 服务不通：分流规则可能漏了 AI 域名',
          note: names(ai.down, 5) + ' 连不上，而 Google、GitHub 等国际站点正常。这些服务很可能被分到了直连——'
            + '检查规则里有没有 chatgpt.com、openai.com、anthropic.com、claude.ai、googleapis.com。' + tail
        };
      }

      if (cn.ratio >= 0.75 && cn.mid !== null && cn.mid > Math.max(150, intl.mid !== null ? intl.mid : 0)) {
        return {
          tone: 'is-warn',
          title: '国内网站比国外还慢：国内流量可能也走了代理（全局模式）',
          note: '国内站点中位 ' + cnMs + '，国际站点中位 ' + intlMs + '。国内流量先出境、再绕回来，自然比直连慢一大截，'
            + '国内服务还可能因此把你当成海外用户。切到「规则」或「绕过中国大陆」模式后再测一次。' + tail
        };
      }

      if (cn.ratio < 0.5 && intl.ratio >= 0.75) {
        return {
          tone: 'is-warn',
          title: '国内网站不通：国内流量被送出境后受阻',
          note: '国际站点正常，国内站点只有 ' + cn.reach + '/' + cn.n + ' 能连上。国内流量多半被分到了境外节点，'
            + '回国的线路不通，或者对方拒绝了海外访问。把国内域名设为直连通常就能解决。' + tail
        };
      }
    }

    var groupKeys = Object.keys(byGroup);
    var weak = groupKeys.filter(function (key) {
      var s = stats(byGroup[key]);
      return s.n > 0 && s.ratio < 0.75;
    });

    if (!weak.length) {
      var split = mainland && cn.mid !== null && intl.mid !== null && cn.mid <= intl.mid
        ? '，符合「国内直连、国外走代理」的预期。'
        : '。';
      return {
        tone: 'is-good',
        title: '连通性良好',
        note: '国内站点中位 ' + cnMs + '，国际站点中位 ' + intlMs + split
          + (all.down.length ? '个别站点不可达：' + names(all.down, 5) + '。' : '各组站点都能连上。') + tail
      };
    }

    var weakText = weak.map(function (key) {
      var s = stats(byGroup[key]);
      return '「' + (GROUP_NAMES[key] || key) + '」' + s.reach + '/' + s.n;
    }).join('、');

    return {
      tone: 'is-warn',
      title: all.down.length + ' 个站点不可达',
      note: '不可达：' + names(all.down, 8) + '。可达比例偏低的分组：' + weakText + '。'
        + '单个站点不通，多半是对方故障、被广告拦截扩展拦下，或分流规则漏了个别域名。' + tail
    };
  }

  toArray(roots).forEach(setup);
})(window, document);
