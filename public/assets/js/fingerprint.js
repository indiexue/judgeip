/* JudgeIP — 浏览器指纹检测。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   三种算法并列，默认跑 v3；切到另外两个时重新计算，不复用上一次的结果——
   指纹本来就该是「此时此刻这台浏览器算出来是什么」，缓存反而会掩盖
   「同一台机器两次算出来不一样」这条最有价值的信息（说明反指纹保护正在生效）。 */
(function () {
  'use strict';

  var T = window.T || function (zh) { return zh; };

  var root = document.getElementById('fingerprint');
  if (!root) return;

  var tabs = Array.prototype.slice.call(root.querySelectorAll('[data-fp-method]'));
  var descEl = root.querySelector('[data-fp-desc]');
  var eyebrowEl = root.querySelector('[data-fp-eyebrow]');
  var hashEl = root.querySelector('[data-fp-hash]');
  var metaEl = root.querySelector('[data-fp-meta]');
  var rowsEl = root.querySelector('[data-fp-rows]');
  var panel = root.querySelector('#fp-panel');

  /* 每次切换算法自增。异步回调回来时对不上号，说明用户已经切走了，结果直接丢弃——
     否则慢的那一次会在快的那一次之后落地，把面板改回旧算法的结果。 */
  var token = 0;

  var EYEBROW = { v3: 'visitorId', v2: 'murmur x64 128', ja3: 'JA3 Hash' };

  /* 组件名的中文对照。没收录的键原样显示——宁可露出一个英文键，
     也好过为了整齐把一个不认识的信号硬翻成中文。 */
  var LABELS = {
    fonts: T('字体列表', 'Fonts'), domBlockers: T('广告拦截器', 'Ad blockers'), fontPreferences: T('字体度量', 'Font metrics'),
    audio: T('音频指纹', 'Audio'), screenFrame: T('屏幕边框', 'Screen frame'), canvas: T('Canvas 渲染', 'Canvas rendering'),
    osCpu: T('系统 CPU', 'OS CPU'), languages: T('语言', 'Languages'), colorDepth: T('色深', 'Color depth'),
    deviceMemory: T('设备内存', 'Device memory'), screenResolution: T('屏幕分辨率', 'Screen resolution'), hardwareConcurrency: T('CPU 线程数', 'CPU threads'),
    timezone: T('时区', 'Time zone'), sessionStorage: 'sessionStorage', localStorage: 'localStorage',
    indexedDB: 'IndexedDB', openDatabase: 'WebSQL', cpuClass: T('CPU 类型', 'CPU class'),
    platform: T('平台', 'Platform'), plugins: T('插件列表', 'Plugins'), touchSupport: T('触摸支持', 'Touch support'),
    vendor: T('浏览器厂商', 'Vendor'), vendorFlavors: T('厂商特征', 'Vendor flavors'), cookiesEnabled: T('Cookie 可用', 'Cookies enabled'),
    colorGamut: T('色域', 'Color gamut'), invertedColors: T('反色模式', 'Inverted colors'), forcedColors: T('强制配色', 'Forced colors'),
    monochrome: T('单色显示', 'Monochrome'), contrast: T('对比度偏好', 'Contrast preference'), reducedMotion: T('减少动效', 'Reduced motion'),
    reducedTransparency: T('减少透明', 'Reduced transparency'), hdr: 'HDR', math: T('数学函数特征', 'Math functions'),
    pdfViewerEnabled: T('PDF 阅读器', 'PDF viewer'), architecture: T('指令集架构', 'Architecture'), applePay: 'Apple Pay',
    privateClickMeasurement: T('私密点击度量', 'Private Click Measurement'), webGlBasics: T('WebGL 基本信息', 'WebGL basics'),
    webGlExtensions: T('WebGL 扩展', 'WebGL extensions'), userAgent: 'User-Agent', webdriver: T('自动化标志', 'Automation flag'),
    language: T('语言', 'Languages'), deviceMemoryMB: T('设备内存', 'Device memory'), pixelRatio: T('像素比', 'Pixel ratio'),
    availableScreenResolution: T('可用分辨率', 'Available resolution'), timezoneOffset: T('时区偏移', 'Time zone offset'),
    adBlock: T('广告拦截', 'Ad block'), hasLiedLanguages: T('语言伪装', 'Spoofed languages'), hasLiedResolution: T('分辨率伪装', 'Spoofed resolution'),
    hasLiedOs: T('系统伪装', 'Spoofed OS'), hasLiedBrowser: T('浏览器伪装', 'Spoofed browser'), webgl: T('WebGL 指纹', 'WebGL fingerprint'),
    webglVendorAndRenderer: T('WebGL 显卡', 'WebGL GPU'), enumerateDevices: T('媒体设备', 'Media devices'),
    addBehavior: 'IE addBehavior', doNotTrack: 'Do Not Track', canvasHash: T('Canvas 哈希', 'Canvas hash')
  };

  /* ---------------------------------------------------------------- 渲染工具 */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* Canvas 的值是一整串 data:image/png;base64,…，几万个字符。
     全量渲染会把页面撑爆，也没人会去读——留个头就够看出它变没变。 */
  function brief(value) {
    var text;

    if (value === null || value === undefined) {
      text = '—';
    } else if (typeof value === 'object') {
      try { text = JSON.stringify(value); } catch (e) { text = String(value); }
    } else {
      text = String(value);
    }

    return text.length > 160 ? text.slice(0, 160) + T(' …（共 ', ' … (') + text.length + T(' 字符）', ' characters total)') : text;
  }

  function row(label, value) {
    var node = el('div', 'row');
    node.appendChild(el('div', 'row__label', label));
    var cell = el('div', 'row__value');
    cell.appendChild(el('span', 'mono', value));
    node.appendChild(cell);
    return node;
  }

  function setRows(nodes) {
    rowsEl.textContent = '';
    if (!nodes.length) {
      rowsEl.appendChild(row(T('状态', 'Status'), T('本次没有取到任何信号', 'No signals collected this time')));
      return;
    }
    for (var i = 0; i < nodes.length; i++) rowsEl.appendChild(nodes[i]);
  }

  function busy(method) {
    eyebrowEl.textContent = EYEBROW[method] || T('指纹', 'Fingerprint');
    hashEl.textContent = T('计算中…', 'Computing…');
    metaEl.textContent = '';
    setRows([row(T('状态', 'Status'), T('正在采集…', 'Collecting…'))]);
  }

  function fail(message) {
    hashEl.textContent = T('计算失败', 'Failed');
    metaEl.textContent = message;
    setRows([row(T('状态', 'Status'), message)]);
  }

  /* ---------------------------------------------------------------- 三种算法 */

  /* v3：monitoring 必须显式关掉。开源版默认会向 openfpcdn.io 发一个统计信标，
     本站 CSP 的 connect-src 只有 'self'，那个请求注定失败并在控制台留一条红字。 */
  function runV3(mine) {
    if (!window.FingerprintJS) { fail(T('FingerprintJS v3 未能加载。', 'FingerprintJS v3 failed to load.')); return; }

    window.FingerprintJS.load({ monitoring: false })
      .then(function (agent) { return agent.get(); })
      .then(function (result) {
        if (!mine()) return;

        hashEl.textContent = result.visitorId;
        metaEl.textContent = T('算法 FingerprintJS v', 'Algorithm FingerprintJS v') + result.version +
          T('　置信度 ', '   Confidence ') + Math.round((result.confidence && result.confidence.score || 0) * 100) + '%' +
          T('　共 ', '   ') + Object.keys(result.components).length + T(' 项信号', ' signals');

        var nodes = Object.keys(result.components).sort().map(function (key) {
          var component = result.components[key];
          return row(LABELS[key] || key, component.error ? T('采集失败', 'Failed') : brief(component.value));
        });
        setRows(nodes);
      })
      .catch(function (e) { if (mine()) fail(T('计算失败：', 'Failed: ') + (e && e.message ? e.message : e)); });
  }

  /* v2：回调式 API，且拿到的是组件数组，哈希要自己算 */
  function runV2(mine) {
    if (!window.Fingerprint2) { fail(T('FingerprintJS2 未能加载。', 'FingerprintJS2 failed to load.')); return; }

    try {
      window.Fingerprint2.get(function (components) {
        if (!mine()) return;

        var values = components.map(function (c) { return String(c.value); });
        hashEl.textContent = window.Fingerprint2.x64hash128(values.join(''), 31);
        metaEl.textContent = T('算法 FingerprintJS2 v2.1.4　共 ', 'Algorithm FingerprintJS2 v2.1.4   ') + components.length + T(' 项信号', ' signals');

        setRows(components.map(function (c) {
          return row(LABELS[c.key] || c.key, brief(c.value));
        }));
      });
    } catch (e) {
      if (mine()) fail(T('计算失败：', 'Failed: ') + (e && e.message ? e.message : e));
    }
  }

  /* JA3 / JA4：不在 JS 这一层。指纹来自 TLS 握手的第一个报文，
     只有拿得到握手原始字节的服务端才算得出来——本站的 Web 服务器读不到那一层，
     所以这一项由浏览器直接向第三方 TLS 回显服务取，请求不经过本站。
     页面上已经把这件事写明白了，选了这一项就是同意发这次请求。 */
  var TLS_ENDPOINTS = [
    { url: 'https://tls.peet.ws/api/all', parse: parsePeet },
    { url: 'https://tls.browserleaks.com/json', parse: parseBrowserLeaks }
  ];

  function parsePeet(data) {
    var tls = data.tls || {};
    return {
      hash: tls.ja3_hash || '',
      rows: [
        ['JA3 Hash', tls.ja3_hash],
        ['JA3', tls.ja3],
        ['JA4', tls.ja4],
        [T('JA4 全量', 'JA4 raw'), tls.ja4_r],
        [T('HTTP/2 指纹', 'HTTP/2 fingerprint'), data.http2 && data.http2.akamai_fingerprint],
        [T('HTTP 版本', 'HTTP version'), data.http_version],
        [T('TLS 协商版本', 'Negotiated TLS version'), tls.tls_version_negotiated]
      ]
    };
  }

  function parseBrowserLeaks(data) {
    return {
      hash: data.ja3_hash || '',
      rows: [
        ['JA3 Hash', data.ja3_hash],
        ['JA3', data.ja3_text],
        ['JA3N Hash', data.ja3n_hash],
        [T('HTTP/2 指纹', 'HTTP/2 fingerprint'), data.akamai_text],
        [T('HTTP/2 哈希', 'HTTP/2 hash'), data.akamai_hash]
      ]
    };
  }

  function runJa3(mine, index) {
    index = index || 0;

    if (index >= TLS_ENDPOINTS.length) {
      fail(T('未能取到 TLS 指纹：所有回显服务都没有响应。', 'Could not get a TLS fingerprint: no echo service responded.'));
      return;
    }

    var endpoint = TLS_ENDPOINTS[index];

    fetch(endpoint.url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function (data) {
        if (!mine()) return;

        var parsed = endpoint.parse(data);
        if (!parsed.hash) throw new Error(T('返回内容里没有指纹字段', 'No fingerprint field in the response'));

        hashEl.textContent = parsed.hash;
        metaEl.textContent = T('来源 ', 'Source ') + endpoint.url.replace(/^https:\/\//, '') + T('　指纹取自 TLS ClientHello，与 IP 无关', '   From the TLS ClientHello, unrelated to IP');

        setRows(parsed.rows
          .filter(function (pair) { return pair[1]; })
          .map(function (pair) { return row(pair[0], brief(pair[1])); }));
      })
      .catch(function () {
        /* 单个回显服务挂掉不是结论，换下一个再试；全试完才认输 */
        if (mine()) runJa3(mine, index + 1);
      });
  }

  /* ---------------------------------------------------------------- 切换 */

  var RUNNERS = { v3: runV3, v2: runV2, ja3: runJa3 };

  function select(method, tab) {
    token += 1;
    var current = token;
    var mine = function () { return token === current; };

    tabs.forEach(function (item) {
      var active = item === tab;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    panel.setAttribute('aria-labelledby', tab.id);
    descEl.textContent = tab.getAttribute('data-fp-note') || descEl.textContent;
    busy(method);

    (RUNNERS[method] || runV3)(mine);
  }

  tabs.forEach(function (tab) {
    /* 说明文字跟着页签走。服务端已经把三段文案渲染好放在 data 属性里，
       这里只是取出来换上，不在 JS 里再抄一份中文。 */
    tab.addEventListener('click', function () {
      select(tab.getAttribute('data-fp-method'), tab);
    });
  });

  /* 首屏默认跑 v3。Fingerprint2 官方建议等浏览器空下来再采集——
     采集期间会做大量 DOM 与 Canvas 操作，抢在首屏渲染里跑会明显卡顿。 */
  function boot() {
    var first = tabs[0];
    if (first) select(first.getAttribute('data-fp-method'), first);
  }

  if (window.requestIdleCallback) {
    window.requestIdleCallback(boot, { timeout: 800 });
  } else {
    window.setTimeout(boot, 120);
  }
})();
