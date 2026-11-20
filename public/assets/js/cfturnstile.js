/* JudgeIP — Cloudflare 节点检测页的「Turnstile 人机验证」：非交互模式、托管模式两张卡片。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'；也不和 cloudflare.js 写在一起——
   两件事互不依赖、同时开跑，Turnstile 加载得再慢也拖不住节点检测。

   每张卡片的一轮：
     1. 渲染组件（appearance: 'always'：要看的正是它会不会请你点一下），从 render() / reset() 那一刻起计时；
     2. Cloudflare 打算请你点击之前会先调 before-interactive-callback——这就是「没能自动通过」的信号；
     3. 拿到 token 记下耗时，把 token 交给本站 /cloudflare/turnstile，由服务端向 Cloudflare siteverify 复核；
     4. 前端（有没有被要求点击）与服务端（复核过没过）两边合成一句结论。
   retry: 'never'，refresh-expired / refresh-timeout: 'manual'：失败就如实报出来，不在看不见的地方静默重试。

   api.js 只在至少一张卡片配好了 sitekey 时才由这里插进页面（layout 只在首页需要人机验证时才加载它）。
   加载失败（error）与 15 秒还没就绪分开说：前者是请求被拦下了；后者可能被拦截，也可能只是网络很慢——
   脚本晚些到了，卡片自己接着测。

   token 只发给本站这一个接口，页面上只显示开头几位与长度。服务端转回来的每一个字段都用 textContent 写入。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

  var root = document.querySelector('[data-ts]');
  if (!root) return;

  var P = window.IpcxProbe;

  var apiUrl = root.getAttribute('data-ts-api') || '';
  var endpoint = root.getAttribute('data-ts-endpoint') || '';

  var LOAD_LIMIT = 15000;
  /* 渲染之后既不放行、也不报错、也没请你点击：60 秒后按「没有结果」收尾，卡片不会永远停在「校验中」 */
  var STALL_LIMIT = 60000;
  /* 服务端等 siteverify 最多 5 秒（连接 3 秒），再留出往返与排队的余量 */
  var VERIFY_TIMEOUT = 12000;
  var TOKEN_PREFIX = 12;

  /* 常见的「没能自动通过」的原因。两处结论都要说，措辞放在一处 */
  var CAUSES = T('常见原因：出口是数据中心、VPN 或代理的地址，隐私类扩展或防指纹浏览器改动了浏览器特征，', ' Common causes: the exit is a data center, VPN or proxy address; privacy extensions or anti-fingerprinting browsers altered browser characteristics;')
    + T('浏览器带有自动化特征，或者本机时钟不准。这不代表被封锁，只是没能「无感」通过。', ' the browser shows automation traits; or the local clock is wrong. This is not a block; you just did not pass invisibly.');

  var cards = [];
  Array.prototype.forEach.call(root.querySelectorAll('[data-ts-card]'), function (node) {
    /* 没配置的卡片服务端已经写好「本站尚未配置这一项」，这里不碰它 */
    var sitekey = node.getAttribute('data-sitekey') || '';
    if (!sitekey) return;

    cards.push({
      mode: node.getAttribute('data-ts-card') || '',
      sitekey: sitekey,
      action: node.getAttribute('data-action') || '',
      mount: node.querySelector('[data-ts-mount]'),
      state: node.querySelector('[data-ts-state]'),
      server: node.querySelector('[data-ts-server]'),
      time: node.querySelector('[data-ts-time]'),
      verdict: node.querySelector('[data-ts-verdict]'),
      verdictTitle: node.querySelector('[data-ts-verdict-title]'),
      verdictNote: node.querySelector('[data-ts-verdict-note]'),
      say: node.querySelector('[data-ts-say]'),
      meta: node.querySelector('[data-ts-meta]'),
      reset: node.querySelector('[data-ts-reset]'),
      cdata: '',
      widget: null,
      theme: '',      /* 组件是按哪套主题画的；和页面对不上时要重新渲染（见 start 与文件末尾的主题监听） */
      run: 0,
      phase: 'idle',
      why: '',
      t0: 0,
      ms: null,
      interactive: false,
      token: '',
      code: '',
      result: null,
      stall: 0
    });
  });

  if (!cards.length) return;

  /* probe.js 没加载上，或者浏览器老到没有 fetch / Promise：说清楚，别留两张「待检测」 */
  if (!P || !window.fetch || !window.Promise) {
    cards.forEach(function (card) {
      if (card.state) card.state.textContent = !P ? T('检测脚本加载失败，请刷新页面重试。', 'Failed to load the check script. Reload the page and try again.') : T('当前浏览器太旧，无法运行这项检测。', 'This browser is too old to run this check.');
    });
    return;
  }

  /* ---------------------------------------------------------------- 小工具（与 cloudflare.js 同一套写法） */

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

  function note(text) {
    return P.el('span', 'cfnote', text);
  }

  function line(nodes) {
    var wrap = P.el('span', 'cfline');
    nodes.forEach(function (node) {
      if (node) wrap.appendChild(node);
    });
    return wrap;
  }

  function show(value) {
    return value === null || value === undefined || value === '' ? '—' : String(value);
  }

  /* cData 只许字母数字与 -_：每张卡片一个随机值，服务端复核时原样还回来，对得上才说明 token 出自这一次渲染。
     这个随机值只在浏览器里，服务端无从比对：由页面自己对照，只列在「响应元数据」里供核对，不计入判定 */
  function nonce() {
    var out = '';
    if (window.crypto && window.crypto.getRandomValues) {
      var bytes = new Uint8Array(8);
      window.crypto.getRandomValues(bytes);
      for (var i = 0; i < bytes.length; i++) out += (bytes[i] + 256).toString(16).slice(1);
    } else {
      out = Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
    }
    return 'ipcx-' + out.slice(0, 16);
  }

  /* ---------------------------------------------------------------- 卡片上的几格 */

  function setState(card, text, tone, hint) {
    fill(card.state, [line([tag(text, tone)]), hint ? note(hint) : null]);
  }

  /* 每张卡片只有结论那一块是 aria-live：结论本身就是要念的内容，加载中、校验中这些过渡状态一概不播报。
     唯一要访客动手、却还没有结论的时刻（请你点击），写进里面那一行只给读屏器的字；出结论或清空时一并抹掉 */
  function say(card, text) {
    if (card.say) card.say.textContent = text;
  }

  function setVerdict(card, tone, title, text) {
    say(card, '');
    card.verdict.className = 'verdict tsverdict ' + tone;
    card.verdict.hidden = false;
    card.verdictTitle.textContent = title;
    card.verdictNote.textContent = text;
  }

  function clearVerdict(card) {
    say(card, '');
    card.verdict.hidden = true;
  }

  function paintTime(card) {
    if (card.ms === null) {
      fill(card.time, [dim('—'), card.token && !card.t0 ? note(T('这一轮是在组件里点「刷新」后重跑的，没有计时起点。', 'This run was restarted with "Refresh" inside the widget, so there is no start time.')) : null]);
      return;
    }
    fill(card.time, [
      line([P.el('span', 'mono', card.ms + ' ms')]),
      card.interactive ? note(T('从开始验证算起，包括等你点击的时间。', 'Measured from the start of verification, including time waiting for your click.')) : null
    ]);
  }

  /* 响应元数据：siteverify 回来的字段逐项列出。token 只露开头——它是一次性的，但整串贴在页面上、进了截图，
     也没有任何用处 */
  function paintMeta(card) {
    var rows = [];
    var d = card.result && card.result.data;

    if (card.token) {
      rows.push(['token', card.token.slice(0, TOKEN_PREFIX) + T('…（共 ', '… (') + card.token.length + T(' 个字符，只显示开头）', ' characters, start shown)')]);
    }
    if (card.code) rows.push([T('前端错误码', 'Client error code'), card.code]);

    if (d && d.ok === true) {
      rows.push(['hostname', show(d.hostname) + (d.hostname_ok === true ? T('（与本站一致）', ' (matches this site)')
        : d.hostname_ok === false ? T('（应为 ', ' (expected ') + show(d.hostname_expected) + T('）', ')') : '')]);
      rows.push(['challenge_ts', show(d.challenge_ts)]);
      rows.push(['action', show(d.action) + (d.action_ok === true ? T('（与本卡片一致）', ' (matches this card)')
        : d.action_ok === false ? T('（应为 ', ' (expected ') + show(d.action_expected) + T('）', ')') : '')]);
      rows.push(['cdata', show(d.cdata) + (d.cdata ? (d.cdata === card.cdata ? T('（与本次渲染一致）', ' (matches this render)') : T('（与本次渲染的不一致）', ' (does not match this render)')) : '')]);
      rows.push(['error-codes', d.error_codes && d.error_codes.length ? d.error_codes.join(', ') : T('无', 'none')]);
      rows.push(['metadata', metaText(d.metadata)]);
    } else if (card.result) {
      rows.push([T('服务端', 'Server'), (d && d.error ? d.error + T('：', ': ') : '') + (d && d.message ? d.message : (card.result.status ? 'HTTP ' + card.result.status : T('没有回应', 'No response')))]);
    }

    fill(card.meta, []);
    if (!rows.length) {
      card.meta.appendChild(P.el('p', 'tsmeta__empty', T('尚未取得。', 'Not available yet.')));
      return;
    }

    var list = P.el('dl', 'tsmeta__list');
    rows.forEach(function (row) {
      list.appendChild(P.el('dt', '', row[0]));
      list.appendChild(P.el('dd', 'mono', row[1]));
    });
    card.meta.appendChild(list);
  }

  function metaText(meta) {
    if (!meta || typeof meta !== 'object') return T('无', 'none');
    var lines = [];
    for (var key in meta) {
      if (Object.prototype.hasOwnProperty.call(meta, key)) lines.push(key + ' = ' + String(meta[key]));
    }
    return lines.length ? lines.join('\n') : T('无', 'none');
  }

  /* ---------------------------------------------------------------- 错误码

     error-callback 的代码按族归类。只说「多见于」「可能」，不替 Cloudflare 下定论；认不出的原样显示代码。
     kind 决定结论的语气：deploy / cf 是本站或 Cloudflare 的问题，不该算到访客头上；
     load / param / unknown 是质询没跑起来或本页认不出，Cloudflare 并没有作出判定，也只给琥珀。
     红色的「未能通过验证」只留给 fail（Cloudflare 判的）与 env（访客这边的环境让验证过不去）。 */
  function explain(code) {
    var c = String(code || '');
    var hit = function (text, kind, state, tone) {
      return { text: text + T('（错误码 ', ' (error ') + c + T('）', ')'), kind: kind, state: state || T('失败', 'Failed'), tone: tone || 'leak' };
    };

    if (c === '110100' || c === '110110') return hit(T('sitekey 无效，这是本站的部署配置问题', 'Invalid sitekey; this is a deployment configuration issue on this site'), 'deploy');
    if (c === '110200') return hit(T('当前域名不在这个 Widget 的允许列表里，这是本站的部署配置问题', 'The current domain is not in this widget\'s allowed list; this is a deployment configuration issue on this site'), 'deploy');
    if (c === '110420' || c === '110430') return hit(T('action 或 cData 参数无效，这是本站的部署问题', 'Invalid action or cData parameter; this is a deployment issue on this site'), 'deploy');
    if (c === '110500') return hit(T('Turnstile 不支持当前浏览器', 'Turnstile does not support this browser'), 'browser', T('浏览器不受支持', 'Browser not supported'));
    if (c === '110510') return hit(T('浏览器前后报出的 User-Agent 不一致，常见于修改 UA 的浏览器扩展', 'The browser reported inconsistent User-Agent values, common with UA-changing extensions'), 'env');
    if (/^11060\d$/.test(c)) return hit(T('质询超时，多见于本机时钟不准或网络很慢', 'Challenge timed out, usually because of a wrong local clock or a slow network'), 'env');
    if (/^11062\d$/.test(c)) return hit(T('交互超时：没有在时限内完成点击', 'Interaction timed out: the click was not completed in time'), 'timeout', T('交互超时', 'Interaction timed out'), 'warn');
    if (/^120\d{3}$/.test(c)) return hit(T('Cloudflare 内部错误，与你的浏览器无关', 'Cloudflare internal error, unrelated to your browser'), 'cf');
    if (c === '200010') return hit(T('浏览器缓存了不该缓存的 Turnstile 资源，清除缓存后重试', 'The browser cached Turnstile resources that should not be cached; clear the cache and try again'), 'env');
    if (c === '200100') return hit(T('本机时钟与真实时间相差太大', 'The local clock is too far from the real time'), 'env');
    /* 和 api.js 被拦是同一类处境，只是晚了一步：脚本到了，它要嵌的那个 iframe 没到 */
    if (c === '200500') return hit(T('Turnstile 的验证框（challenges.cloudflare.com 的 iframe）没能加载，多见于网络连不上 Cloudflare，或扩展、代理规则拦下了它', 'The Turnstile frame (an iframe from challenges.cloudflare.com) failed to load, usually because the network cannot reach Cloudflare or an extension or proxy rule blocked it'), 'load', T('加载失败', 'Failed to load'), 'warn');
    if (/^300\d{3}$/.test(c)) return hit(T('浏览器执行质询时出错，可能是扩展干扰或浏览器环境异常', 'The browser hit an error while running the challenge, possibly extension interference or an unusual browser environment'), 'env');
    if (/^600\d{3}$/.test(c)) return hit(T('质询未通过：Cloudflare 认为当前环境可疑，例如自动化、指纹异常或数据中心 IP', 'Challenge failed: Cloudflare considers this environment suspicious, for example automation, unusual fingerprints or a data center IP'), 'fail');
    /* 文档把 102 / 103 / 104 / 106 归成一族「参数无效」，说的是质询过程中发出的参数，建议重试——
       不一定是本站配错了，所以不套「多半是本站的部署问题」那句 */
    if (/^10[2346]\d{3}$/.test(c)) return hit(T('Turnstile 收到了无效的参数，多见于扩展或代理改动了质询请求，也可能是本站的部署问题', 'Turnstile received invalid parameters, usually because an extension or proxy altered the challenge request; it may also be a deployment issue on this site'), 'param', T('出错', 'Error'), 'warn');
    if (/^105\d{3}$/.test(c)) return hit(T('Turnstile 被以已弃用或无效的方式调用，多半是本站的部署问题', 'Turnstile was called in a deprecated or invalid way, most likely a deployment issue on this site'), 'deploy');
    if (/^(400|100)\d{3}$/.test(c)) return hit(T('组件参数或初始化出错，多半是本站的部署问题', 'Widget parameter or initialization error, most likely a deployment issue on this site'), 'deploy');
    return { text: c ? T('Turnstile 报告了错误码 ', 'Turnstile reported error code ') + c : T('Turnstile 报告了错误，但没有给出错误码', 'Turnstile reported an error without an error code'), kind: 'unknown', state: T('出错', 'Error'), tone: 'warn' };
  }

  /* ---------------------------------------------------------------- 加载 api.js

     整页只有一份 <script>、一张等候名单（apiWaiters）。15 秒的时限只是先给卡片一个交代，并不取消加载：
     从 DOM 里删掉一个还在路上的 <script> 拦不住它执行，再插一份就会让 api.js 执行两次（Turnstile 会对重复加载报警）。
     所以还在路上的那一份一直等下去，「重置」也只是接着等它；它晚些到了，因超时停下的卡片自动重新开始（见 lateArrival）。
     只有它确实失败了——error，或者 load 了却不是 Turnstile——才换一份新的。 */

  var api = 'idle';          /* idle | loading | ready | failed */
  var apiTag = null;
  var apiPending = false;    /* apiTag 还没有 load / error */
  var apiTimer = 0;
  var apiWaiters = [];

  function hasApi() {
    return !!(window.turnstile && typeof window.turnstile.render === 'function');
  }

  /* why 交给 scriptFailed 选措辞：error（请求失败）、invalid（拿到的不是 Turnstile）、timeout（15 秒还没就绪） */
  function settle(ok, why) {
    window.clearTimeout(apiTimer);
    apiTimer = 0;
    if (api !== 'loading') return;
    api = ok ? 'ready' : 'failed';
    var waiters = apiWaiters;
    apiWaiters = [];
    waiters.forEach(function (fn) { fn(ok, why); });
  }

  /* 超时之后脚本才有了下文：等候名单早已清空，停在「长时间未加载」的卡片要在这里接回来 */
  function lateArrival(ok) {
    if (api !== 'failed') return;
    if (ok) {
      api = 'ready';
      cards.forEach(function (card) { if (card.phase === 'nolib') start(card); });
      return;
    }
    /* 等到最后还是没加载上：「可能只是慢」改成确切的「没能加载」 */
    cards.forEach(function (card) { if (card.phase === 'nolib' && card.why === 'timeout') scriptFailed(card, 'error'); });
  }

  function withApi(callback) {
    if (api !== 'ready' && hasApi()) api = 'ready';
    if (api === 'ready') {
      callback(true, '');
      return;
    }

    apiWaiters.push(callback);
    if (api === 'loading') return;
    api = 'loading';

    if (!apiUrl) {
      settle(false, 'error');
      return;
    }

    apiTimer = window.setTimeout(function () { settle(hasApi(), 'timeout'); }, LOAD_LIMIT);
    if (apiPending) return;

    /* 走到这里，旧的那一份（如果有）已经 error 或 load 过，不会再执行：删掉它，换一份新的 */
    if (apiTag && apiTag.parentNode) apiTag.parentNode.removeChild(apiTag);

    var tag = document.createElement('script');
    var done = function (ok, why) {
      apiPending = false;
      if (api === 'loading') settle(ok, why);
      else lateArrival(ok);
    };

    /* load 之后 window.turnstile 应当已经就位；没有就说明拿到的不是 Turnstile（被劫持成别的内容之类） */
    tag.addEventListener('load', function () { done(hasApi(), 'invalid'); });
    tag.addEventListener('error', function () { done(false, 'error'); });
    tag.src = apiUrl;
    tag.async = true;
    apiTag = tag;
    apiPending = true;
    document.head.appendChild(tag);
  }

  /* ---------------------------------------------------------------- 一轮检测 */

  function stopStall(card) {
    if (card.stall) window.clearTimeout(card.stall);
    card.stall = 0;
  }

  function armStall(card, run) {
    stopStall(card);
    card.stall = window.setTimeout(function () {
      if (run !== card.run || card.phase !== 'checking') return;
      card.phase = 'stalled';
      setState(card, T('没有结果', 'No result'), 'warn', T('Turnstile 在 ', 'Turnstile neither passed nor reported an error within ') + STALL_LIMIT / 1000 + T(' 秒内既没有放行，也没有报错。', ' s.'));
      fill(card.server, [dim(T('未进行', 'Not run'))]);
      setVerdict(card, 'is-warn', T('没有得到结果', 'No result'), T('组件迟迟没有给出结论，常见于网络很慢、或连接被代理与扩展中途拦下。点「重置」再试一次。', 'The widget gave no verdict for a long time, usually because of a slow network or a proxy or extension cutting the connection. Click "Reset" to try again.'));
    }, STALL_LIMIT);
  }

  /* 过期、交互超时之后，访客点了组件里自带的「刷新」：Turnstile 自己重跑了一轮，没有经过 start()。
     当成新的一轮接住，只是没有计时起点。「没有结果」之后迟到的回调仍属于原来那一轮，照常计时 */
  function adopt(card) {
    if (card.phase === 'checking' || card.phase === 'interactive' || card.phase === 'stalled') return;
    card.run++;
    card.t0 = 0;
    card.ms = null;
    card.interactive = false;
    card.token = '';
    card.code = '';
    card.result = null;
    clearVerdict(card);
  }

  function options(card) {
    /* 比 flexible 的下限（300px）还窄的屏幕改用 compact，否则组件会探出卡片、复选框被裁掉一半 */
    var width = card.mount.clientWidth;
    return {
      sitekey: card.sitekey,
      action: card.action,
      cData: card.cdata,
      /* 组件的配色在渲染那一刻就定死了，没有事后改的接口（Turnstile 自带的 auto 主题跟的是系统偏好，不是本站的切换按钮）。
         所以访客换主题之后要整个重新渲染一遍，见 start() 与文件末尾的主题监听 */
      theme: pageTheme(),
      language: window.I18N && I18N.lang === 'en' ? 'en' : 'zh-cn',
      size: width && width < 300 ? 'compact' : 'flexible',
      appearance: 'always',
      execution: 'render',
      retry: 'never',
      'refresh-expired': 'manual',
      'refresh-timeout': 'manual',
      'response-field': false,
      callback: function (token) { onToken(card, token); },
      'error-callback': function (code) {
        onError(card, code);
        return true;   /* 告诉 Turnstile 错误已经处理，不必再往控制台抛 */
      },
      'expired-callback': function () { onExpired(card); },
      'timeout-callback': function () { onTimeout(card); },
      'before-interactive-callback': function () { onInteractive(card); },
      'after-interactive-callback': function () { onAfterInteractive(card); },
      'unsupported-callback': function () { onUnsupported(card); }
    };
  }

  function pageTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function start(card) {
    card.run++;
    var run = card.run;
    var ready = api === 'ready' || hasApi();
    /* 只在真要等 api.js 时才禁用「重置」：按钮被禁用的那一刻，浏览器会把它身上的焦点丢回 <body>，
       用键盘按「重置」的人每按一次都得重新找一遍按钮。等完了把焦点还给它（期间焦点被移到了别处就不抢） */
    var refocus = !!card.reset && document.activeElement === card.reset;
    stopStall(card);
    card.phase = 'loading';
    card.why = '';
    card.t0 = 0;
    card.ms = null;
    card.interactive = false;
    card.token = '';
    card.code = '';
    card.result = null;
    if (card.reset && !ready) card.reset.disabled = true;
    clearVerdict(card);
    fill(card.server, [dim(T('待校验', 'Waiting'))]);
    fill(card.time, [dim('—')]);
    paintMeta(card);
    setState(card, ready ? T('校验中', 'Verifying') : T('加载 Turnstile…', 'Loading Turnstile…'), 'muted');
    if (card.widget === null) fill(card.mount, [dim(T('正在加载 Turnstile…', 'Loading Turnstile…'))]);

    withApi(function (ok, why) {
      if (run !== card.run) return;
      if (card.reset) {
        card.reset.disabled = false;
        if (refocus && (!document.activeElement || document.activeElement === document.body)) card.reset.focus();
      }

      if (!ok) {
        scriptFailed(card, why);
        return;
      }

      card.phase = 'checking';
      setState(card, T('校验中', 'Verifying'), 'muted', T('正在后台执行 Cloudflare 的质询…', 'Running Cloudflare\'s challenge in the background…'));
      armStall(card, run);
      card.t0 = P.now();

      try {
        /* 画好之后页面换了主题：reset() 不会换配色，深色卡片里会留着一块浅色的验证框（反过来也一样）。
           拆掉旧的，走下面重新渲染的那一支。remove() 抛了也无妨——下面 fill() 会把挂载点清空 */
        if (card.widget !== null && card.theme !== pageTheme()) {
          try { window.turnstile.remove(card.widget); } catch (ignore) { /* 旧组件已经不在了 */ }
          card.widget = null;
        }

        if (card.widget === null) {
          card.cdata = nonce();
          fill(card.mount, []);
          card.theme = pageTheme();
          card.widget = window.turnstile.render(card.mount, options(card));
          if (card.widget === null || card.widget === undefined) {
            card.widget = null;
            throw new Error('render() 没有返回组件编号');
          }
        } else {
          window.turnstile.reset(card.widget);
        }
      } catch (e) {
        stopStall(card);
        card.phase = 'error';
        setState(card, T('失败', 'Failed'), 'leak', T('组件没能启动：', 'The widget failed to start: ') + (e && e.message ? e.message : T('未知原因', 'unknown reason')) + T('。', '.'));
        fill(card.server, [dim(T('未进行', 'Not run'))]);
        setVerdict(card, 'is-warn', T('无法完成检测', 'Could not complete the check'), T('Turnstile 组件没能启动，多半是本站的配置问题，不代表你的浏览器没通过。点「重置」再试一次。', 'The Turnstile widget failed to start, most likely a configuration issue on this site; it does not mean your browser failed. Click "Reset" to try again.'));
      }
    });
  }

  /* 「没能加载」与「15 秒还没加载完」分开说：后者可能只是慢，不能说成被屏蔽；脚本晚些到了，卡片自己接着测（见 lateArrival） */
  function scriptFailed(card, why) {
    card.phase = 'nolib';
    card.why = why;
    fill(card.server, [dim(T('未进行', 'Not run'))]);

    if (why === 'timeout') {
      setState(card, T('长时间未加载', 'Not loaded after a long time'), 'warn', LOAD_LIMIT / 1000 + T(' 秒内没能从 challenges.cloudflare.com 加载 Turnstile（可能被拦截或网络很慢）。', ' s passed without Turnstile loading from challenges.cloudflare.com (possibly blocked, or a slow network).'));
      fill(card.mount, [dim(T('Turnstile 还没有加载完成', 'Turnstile has not finished loading'))]);
      setVerdict(card, 'is-warn', T('Turnstile 长时间未加载', 'Turnstile not loaded after a long time'),
        T('可能被拦截或网络很慢：所在网络屏蔽了 challenges.cloudflare.com、广告拦截或代理规则拦下了它，或者只是到那里的链路很慢。', 'It may be blocked or the network may be slow: your network blocks challenges.cloudflare.com, an ad blocker or proxy rule blocked it, or the link to it is just slow.')
        + T('脚本晚些到达时，这里会自动开始检测；也可以点「重置」再等 ', ' If the script arrives later, the check starts here automatically; you can also click "Reset" and wait another ') + LOAD_LIMIT / 1000 + T(' 秒。', ' s.'));
      return;
    }

    setState(card, T('脚本加载失败', 'Script failed to load'), 'warn', T('没能从 challenges.cloudflare.com 加载 Turnstile：请求被拦下，或者拿回来的不是 Turnstile。', 'Could not load Turnstile from challenges.cloudflare.com: the request was blocked, or the response was not Turnstile.'));
    fill(card.mount, [dim(T('没能加载 Turnstile', 'Could not load Turnstile'))]);
    setVerdict(card, 'is-warn', T('无法加载 Turnstile', 'Cannot load Turnstile'),
      T('浏览器没能加载 Cloudflare 的验证组件：所在网络连不上或屏蔽了 challenges.cloudflare.com，或者广告拦截、隐私扩展、代理规则拦下了它。', 'The browser could not load Cloudflare\'s verification widget: your network cannot reach or blocks challenges.cloudflare.com, or an ad blocker, privacy extension or proxy rule blocked it.')
      + T('这时任何使用 Turnstile 的网站都会卡在验证这一步。点「重置」重新加载。', ' In that case every site that uses Turnstile will get stuck at verification. Click "Reset" to reload.'));
  }

  /* 非交互卡片却请你点击：这个 sitekey 在控制台里配成了别的模式。这一轮测的其实是托管模式，
     回答不了「能不能无感通过」，也不该再拿 CAUSES 去解释访客的环境——几处结论都先过这一关 */
  function niMisconfigured(card) {
    return card.mode === 'ni' && card.interactive;
  }

  function niMisconfig(card, what) {
    setVerdict(card, 'is-warn', T('本站的非交互 Widget 配置有误', 'This site\'s non-interactive widget is misconfigured'),
      T('非交互模式本不该出现点击框，这个 sitekey 在 Cloudflare 控制台里多半设成了 Managed。', 'Non-interactive mode should never show a checkbox; this sitekey is probably set to Managed in the Cloudflare dashboard. ') + what + T('这一轮测不出非交互模式能否自动通过。', ' This run cannot tell whether non-interactive mode passes automatically.'));
  }

  function onInteractive(card) {
    /* 60 秒的「没有结果」之后才请你点击：那条「点「重置」再试一次」和服务端那格的「未进行」都不再成立，先撤掉 */
    var wasStalled = card.phase === 'stalled';
    adopt(card);
    /* 访客正在操作：时限交给 Turnstile 自己的 timeout-callback，这里的兜底先撤掉 */
    stopStall(card);
    clearVerdict(card);
    if (wasStalled) fill(card.server, [dim(T('待校验', 'Waiting'))]);
    card.interactive = true;
    card.phase = 'interactive';
    var hint = card.mode === 'ni'
      ? T('非交互模式本不该出现点击框，这个 sitekey 在控制台里多半不是 Non-interactive。点击上方组件里的复选框可以继续。', 'Non-interactive mode should never show a checkbox; this sitekey is probably not set to Non-interactive in the dashboard. Click the checkbox in the widget above to continue.')
      : T('Cloudflare 没能自动判定，请点击上方组件里的复选框完成验证。', 'Cloudflare could not decide automatically. Click the checkbox in the widget above to complete verification.');
    setState(card, T('需要点击确认', 'Click needed'), 'warn', hint);
    say(card, T('需要点击确认。', 'Click needed. ') + hint);
  }

  function onAfterInteractive(card) {
    if (card.phase !== 'interactive') return;
    /* 点过之后又回到后台校验：兜底重新挂上，免得卡片永远停在「校验中」 */
    card.phase = 'checking';
    armStall(card, card.run);
    say(card, '');
    setState(card, T('校验中', 'Verifying'), 'muted', T('已收到你的确认，正在完成验证…', 'Got your confirmation, finishing verification…'));
  }

  function onToken(card, token) {
    adopt(card);
    var run = card.run;
    stopStall(card);
    card.ms = card.t0 ? Math.round(P.now() - card.t0) : null;
    card.token = String(token || '');
    card.phase = 'verifying';
    clearVerdict(card);
    setState(card, T('校验成功', 'Verified'), 'ok', !card.interactive ? T('没有要求任何交互，后台静默完成。', 'No interaction required; completed silently in the background.')
      : niMisconfigured(card) ? T('你点击确认之后才拿到 token；非交互模式本不该出现点击框。', 'You only got the token after clicking; non-interactive mode should never show a checkbox.') : T('你点击确认之后才拿到 token。', 'You only got the token after clicking.'));
    paintTime(card);
    fill(card.server, [dim(T('复核中…', 'Verifying on server…'))]);
    paintMeta(card);
    verify(card, run);
  }

  function onError(card, code) {
    adopt(card);
    stopStall(card);
    var elapsed = card.t0 ? Math.round(P.now() - card.t0) : null;
    var info = explain(code);
    /* 11062x 本身就说明 Cloudflare 请你点过：即便没先收到 before-interactive，也按「要求了点击」算，不判成没通过 */
    if (info.kind === 'timeout') card.interactive = true;
    card.phase = 'error';
    card.code = String(code || '');
    setState(card, info.state, info.tone, info.text + T('。', '.'));
    fill(card.server, [dim(T('未进行', 'Not run'))]);
    fill(card.time, [elapsed !== null ? dim(elapsed + T(' ms 后失败', ' ms, then failed')) : dim('—')]);
    paintMeta(card);

    if (info.kind === 'deploy' || info.kind === 'cf') {
      setVerdict(card, 'is-warn', T('无法完成检测', 'Could not complete the check'), info.text + T('。', '.') + (info.kind === 'cf' ? T('稍后点「重置」再试。', ' Click "Reset" later to try again.') : T('这不代表你的浏览器没通过。', ' This does not mean your browser failed.')));
    } else if (info.kind === 'browser') {
      setVerdict(card, 'is-bad', T('浏览器不受支持', 'Browser not supported'), info.text + T('。使用 Turnstile 的网站在这个浏览器上都会卡在验证这一步，换用较新的 Chrome、Edge、Firefox 或 Safari 即可。', '. Every site that uses Turnstile will get stuck at verification in this browser; use a recent Chrome, Edge, Firefox or Safari.'));
    } else if (info.kind === 'load') {
      setVerdict(card, 'is-warn', T('无法加载 Turnstile', 'Cannot load Turnstile'), info.text + T('。质询没能开始，这不代表 Cloudflare 判你没通过。点「重置」再试一次。', '. The challenge could not start; this does not mean Cloudflare failed you. Click "Reset" to try again.'));
    } else if (info.kind === 'param') {
      setVerdict(card, 'is-warn', T('无法完成检测', 'Could not complete the check'), info.text + T('。点「重置」再试一次。', '. Click "Reset" to try again.'));
    } else if (info.kind === 'unknown') {
      setVerdict(card, 'is-warn', T('无法完成检测', 'Could not complete the check'), info.text + T('。本页认不出这个错误码，不能据此判断你的浏览器是否通过。点「重置」再试一次。', '. This page does not recognize this error code, so it cannot tell whether your browser passed. Click "Reset" to try again.'));
    } else if (niMisconfigured(card)) {
      niMisconfig(card, info.text + T('。', '.'));
    } else if (info.kind === 'timeout') {
      setVerdict(card, 'is-warn', T('需要手动确认', 'Manual confirmation needed'), T('Cloudflare 没能自动判定、请你点击确认，但这一轮没有在时限内完成。', 'Cloudflare could not decide automatically and asked you to click, but this run did not finish in time.') + CAUSES);
    } else if (info.kind === 'fail') {
      /* 只有 600xxx 是 Cloudflare 作出的判定；时钟、缓存、超时这些 env 错误轮不到它「满不满意」 */
      setVerdict(card, 'is-bad', T('未能通过验证', 'Verification failed'), info.text + T('。', '.')
        + (card.mode === 'ni' ? T('非交互模式不会给出点击框，Cloudflare 不满意就直接判失败。', ' Non-interactive mode never shows a checkbox; if Cloudflare is not satisfied it simply fails.') : '')
        + T('这是 Cloudflare 基于它能看到的信号作出的判断，不一定准确。', ' This is Cloudflare\'s judgment based on the signals it can see, and may not be accurate.') + CAUSES);
    } else {
      setVerdict(card, 'is-bad', T('未能通过验证', 'Verification failed'), info.text + T('。点「重置」再试一次。', '. Click "Reset" to try again.'));
    }
  }

  function onTimeout(card) {
    stopStall(card);
    card.phase = 'timeout';
    setState(card, T('交互超时', 'Interaction timed out'), 'warn', T('Cloudflare 请你点击确认，但没有在时限内完成。点「重置」重新检测。', 'Cloudflare asked you to click, but it was not completed in time. Click "Reset" to check again.'));
    fill(card.server, [dim(T('未进行', 'Not run'))]);
    fill(card.time, [dim('—')]);
    if (niMisconfigured(card)) niMisconfig(card, T('请你点击确认之后，这一轮没有在时限内完成。', 'After you were asked to click, this run did not finish in time.'));
    else setVerdict(card, 'is-warn', T('需要手动确认', 'Manual confirmation needed'), T('Cloudflare 没能自动判定、请你点击确认，但这一轮没有在时限内完成。', 'Cloudflare could not decide automatically and asked you to click, but this run did not finish in time.') + CAUSES);
  }

  function onUnsupported(card) {
    stopStall(card);
    card.phase = 'unsupported';
    setState(card, T('浏览器不受支持', 'Browser not supported'), 'leak', T('Turnstile 不支持当前浏览器。', 'Turnstile does not support this browser.'));
    fill(card.server, [dim(T('未进行', 'Not run'))]);
    setVerdict(card, 'is-bad', T('浏览器不受支持', 'Browser not supported'), T('使用 Turnstile 的网站在这个浏览器上都会卡在验证这一步，换用较新的 Chrome、Edge、Firefox 或 Safari 即可。', 'Every site that uses Turnstile will get stuck at verification in this browser; use a recent Chrome, Edge, Firefox or Safari.'));
  }

  /* token 过期（300 秒）：这一轮的结论早已得出，不动它，只把状态标出来 */
  function onExpired(card) {
    if (card.phase !== 'done' && card.phase !== 'verifying') return;
    card.phase = 'expired';
    setState(card, T('token 已过期', 'Token expired'), 'muted', T('token 的有效期是 300 秒，上面的结论不受影响；点「重置」重新检测。', 'Tokens are valid for 300 seconds. The result above is unaffected; click "Reset" to check again.'));
  }

  /* ---------------------------------------------------------------- 服务端复核 */

  function verify(card, run) {
    var body = 'mode=' + encodeURIComponent(card.mode) + '&token=' + encodeURIComponent(card.token)
      + '&action=' + encodeURIComponent(card.action || '') + (window.I18N && I18N.lang === 'en' ? '&lang=en' : '');

    /* 凭据与来源页沿用 probe.js 的默认（不带 Cookie、no-referrer）：这个接口不看 Cookie，也用不着 Referer。
       同源检查（TurnstileProbe::sameOrigin）看的是 Origin——fetch 默认是 cors 模式，POST 照样带着本站的 Origin。
       表单编码而不是 JSON：$_POST 直接可读，也不会触发预检。 */
    P.text(endpoint, {
      method: 'POST',
      body: body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }, VERIFY_TIMEOUT).then(function (res) {
      var data = null;
      try { data = JSON.parse(res.text); } catch (e) { data = null; }
      return { status: res.response.status, data: data && typeof data === 'object' ? data : null };
    }, function (failure) {
      return { status: 0, data: null, kind: failure && failure.kind };
    }).then(function (answer) {
      if (run !== card.run) return;
      card.result = answer;
      if (card.phase === 'verifying') card.phase = 'done';
      paintServer(card, answer);
      conclude(card);
      paintMeta(card);
    });
  }

  function paintServer(card, answer) {
    var d = answer.data;

    /* siteverify 的耗时只在它真的回答了时才显示；没连上时那个数只是「多久之后放弃」，摆出来反而像是它回答过 */
    if (d && d.ok === true) {
      var ms = typeof d.verify_ms === 'number' ? P.el('span', 'tsaside', 'siteverify ' + d.verify_ms + ' ms') : null;
      fill(card.server, [line([tag(d.pass ? 'PASS' : 'FAIL', d.pass ? 'ok' : 'leak'), ms]), d.pass ? null : note(show(d.message))]);
      return;
    }

    var why;
    if (d && d.message) {
      why = String(d.message);
    } else if (answer.status === 0) {
      why = answer.kind === 'timeout' ? T('本站服务器 ', 'This site\'s server did not respond within ') + VERIFY_TIMEOUT / 1000 + T(' 秒内没有回应。', ' s.') : T('没能连上本站服务器。', 'Could not reach this site\'s server.');
    } else {
      why = T('本站服务器返回了 HTTP ', 'This site\'s server returned HTTP ') + answer.status + T('。', '.');
    }
    fill(card.server, [line([tag(T('未完成', 'Incomplete'), 'warn')]), note(why)]);
  }

  function conclude(card) {
    var d = card.result && card.result.data;
    var checked = !!(d && d.ok === true);

    if (checked && !d.pass) {
      setVerdict(card, 'is-bad', T('服务端复核未通过', 'Server verification failed'), T('前端拿到了 token，但复核没有通过：', 'The page received a token, but verification failed: ') + show(d.message));
    } else if (niMisconfigured(card)) {
      niMisconfig(card, T('你点击确认之后才拿到 token', 'You only got the token after clicking') + (checked ? T('，服务端复核也通过了', ', and server verification also passed') : T('，本站这一次没能向 Cloudflare 复核它', ', and this site could not verify it with Cloudflare this time')) + T('。', '.'));
    } else if (card.interactive) {
      setVerdict(card, 'is-warn', T('需要手动确认', 'Manual confirmation needed'), T('Cloudflare 没能自动判定，请你点击确认后才放行', 'Cloudflare could not decide automatically and only let you through after you clicked')
        + (checked ? T('（服务端复核通过）', ' (server verification passed)') : '') + T('。', '.') + CAUSES);
    } else if (!checked) {
      setVerdict(card, 'is-warn', T('前端已无感通过，服务端未能复核', 'Passed invisibly in the page, server could not verify'),
        T('浏览器没有被要求任何交互就拿到了 token，但本站这一次没能向 Cloudflare 复核它（见「服务端验证」），结论仅供参考。点「重置」可以再测一次。', 'The browser got a token without being asked to interact, but this site could not verify it with Cloudflare this time (see "Server verification"), so treat the result as indicative. Click "Reset" to test again.'));
    } else {
      setVerdict(card, 'is-good', T('自动通过', 'Passed automatically'), card.mode === 'mg'
        ? T('托管模式下 Cloudflare 自动判定为真人，没有要求点击，服务端复核也已通过。', 'In managed mode Cloudflare decided automatically that you are human, did not ask for a click, and server verification also passed.')
        : T('没有要求任何交互，后台静默校验成功，服务端复核也已通过。', 'No interaction required; verification completed silently in the background, and server verification also passed.'));
    }
  }

  /* ---------------------------------------------------------------- 启动 */

  cards.forEach(function (card) {
    if (!card.reset) return;
    card.reset.addEventListener('click', function () {
      /* 脚本没加载上时，任意一张的「重置」都把两张一起重来——它们等的是同一份 api.js */
      if (card.phase === 'nolib') {
        cards.forEach(function (other) {
          if (other.phase === 'nolib') start(other);
        });
        return;
      }
      start(card);
    });
  });

  /* 打开页面即开始，与 cloudflare.js 的节点检测同时进行 */
  cards.forEach(start);

  /* 访客点了导航条上的主题按钮（或系统偏好变了、别的标签页换了主题）：<html data-theme> 一变，
     已经画出来的组件就和页面对不上了。把这样的卡片重新跑一轮——start() 会拆掉旧组件、按新主题重画。
     这等于替访客按了一次「重置」，会多花一次服务端复核；换主题不是高频动作，限流桶（每小时 60 次）够用。
     还没渲染出组件的卡片（在等 api.js、脚本没加载上）不用管：轮到它渲染时读的就是当时的主题。 */
  if (window.MutationObserver) {
    new MutationObserver(function () {
      cards.forEach(function (card) {
        if (card.widget !== null && card.theme !== pageTheme()) start(card);
      });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  }
})();
