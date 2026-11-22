/* JudgeIP — 浏览器端探测的公共工具。连通性、Cloudflare、CDN、分流、AI、首页「本机网络」共用。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   全站其余脚本都是不留全局变量的 IIFE，这里是唯一的例外：只挂一个命名空间 window.IpcxProbe。
   六个页面都要做同样几件事——限时请求、只测延迟的 no-cors 请求、解析 /cdn-cgi/trace、
   限并发的队列、IATA 机房代码换城市——各抄一份的话，修一个 bug 要改六处，迟早有一处漏改。
   页面脚本一律在本文件之后加载（Seo 里的 scripts 顺序），用之前不必判空。

   探测结果只留在当前页面里，不回传本站。 */
(function (window, document) {
  'use strict';

  var T = function (zh, en) { return window.T ? window.T(zh, en) : zh; };

  var P = {};

  P.now = function () {
    return window.performance && performance.now ? performance.now() : Date.now();
  };

  P.sleep = function (ms) {
    return new Promise(function (resolve) { window.setTimeout(resolve, ms); });
  };

  /* ------------------------------------------------------------ CSP 拦截记录

     connect-src 没放行的源，fetch 会被浏览器直接拒绝——在页面上和「网络不通」长得一模一样。
     securitypolicyviolation 事件能告诉我们是哪个源被拦了（跨源时 blockedURI 只有 origin，没有路径），
     记下来，探测失败时据此标成「CSP 未放行」，部署漏改 nginx 时一眼就能看出来，而不是误报成网站不通。 */
  var cspBlocked = {};

  document.addEventListener('securitypolicyviolation', function (event) {
    /* 只记 connect-src：探测请求只受它管。页面上的图片（站点图标走 img-src）被拦与探测无关，
       混进来会把一个本来只是不通的站点误标成「CSP 未放行」 */
    var directive = event.effectiveDirective || event.violatedDirective || '';
    if (directive && directive.indexOf('connect-src') !== 0) return;
    var origin = P.origin(event.blockedURI || '');
    if (origin) {
      cspBlocked[origin] = true;
      if (window.console && console.warn) console.warn('[JudgeIP] CSP 未放行：' + origin);
    }
  });

  P.origin = function (url) {
    var m = /^(https?:\/\/[^\/?#]+)/i.exec(String(url || ''));
    return m ? m[1].toLowerCase() : '';
  };

  P.cspBlocked = function (url) {
    return cspBlocked[P.origin(url)] === true;
  };

  /* ------------------------------------------------------------ 请求

     限时 fetch。成功 resolve({response, ms})；失败 reject({kind, ms})：
       kind = 'timeout' 超时 | 'csp' 被本页 CSP 拦下 | 'error' 其余网络错误（DNS、重置、证书、跨域被拒）。
     凭据一律不带（credentials:'omit'）：既不把访客在这些站点上的 Cookie 送出去，
     也让对方的 Access-Control-Allow-Origin: * 生效（带凭据的请求不认通配）。
     不带任何自定义请求头：一加就会触发 CORS 预检，不少站点的 OPTIONS 直接 404，探测就白做了。 */
  P.request = function (url, options, timeoutMs) {
    var opts = {};
    var key;
    for (key in options || {}) opts[key] = options[key];
    if (!opts.cache) opts.cache = 'no-store';
    if (!opts.credentials) opts.credentials = 'omit';
    if (!opts.referrerPolicy) opts.referrerPolicy = 'no-referrer';

    var limit = timeoutMs || 6000;
    var controller = window.AbortController ? new AbortController() : null;
    if (controller) opts.signal = controller.signal;

    var started = P.now();

    return new Promise(function (resolve, reject) {
      var settled = false;

      var timer = window.setTimeout(function () {
        if (settled) return;
        settled = true;
        if (controller) controller.abort();
        reject({ kind: 'timeout', ms: Math.round(P.now() - started) });
      }, limit);

      window.fetch(url, opts).then(function (response) {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        resolve({ response: response, ms: Math.round(P.now() - started) });
      }, function () {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        var ms = Math.round(P.now() - started);
        /* violation 事件与 fetch 的拒绝谁先到不确定，等一拍再查 */
        window.setTimeout(function () {
          reject({ kind: P.cspBlocked(url) ? 'csp' : 'error', ms: ms });
        }, 30);
      });
    });
  };

  /* 只测延迟：no-cors 拿到的是不透明响应，读不到任何内容，但「有响应」本身就说明连上了——
     404、500 一样算到达，只有网络错误与超时算失败。
     默认 HEAD：不下载响应体，比 GET 一个图标更省；no-cors 允许 HEAD。
     不要设 redirect:'manual'：它和 no-cors 互斥，请求会在发出之前就被浏览器拒绝（见 dnsleak.js）。
     resolve 永不 reject：{ok:true, ms} 或 {ok:false, ms, kind}。 */
  P.timing = function (url, options, timeoutMs) {
    var opts = { method: 'HEAD', mode: 'no-cors' };
    var key;
    for (key in options || {}) opts[key] = options[key];

    return P.request(url, opts, timeoutMs || 3000).then(function (result) {
      return { ok: true, ms: result.ms };
    }, function (failure) {
      return { ok: false, ms: failure.ms, kind: failure.kind };
    });
  };

  /* 读响应正文（CORS）。resolve({text, ms, response})，失败照 P.request 的约定 reject。
     时限覆盖到读完正文为止：响应头到了、正文卡住（代理、中间设备、扩展把连接挂着不放）一样算超时——
     否则 response.text() 永远不结束，调用方那一行就永远停在「检测中」。ms 仍是到响应头的耗时。 */
  P.text = function (url, options, timeoutMs) {
    var limit = timeoutMs || 6000;
    var started = P.now();

    return P.request(url, options || {}, limit).then(function (result) {
      var remaining = Math.max(500, limit - (P.now() - started));

      return new Promise(function (resolve, reject) {
        var settled = false;
        var timer = window.setTimeout(function () {
          if (settled) return;
          settled = true;
          /* 取消正文流，让底层连接随之释放 */
          try { if (result.response.body && result.response.body.cancel) result.response.body.cancel(); } catch (e) { /* 已经读完或不支持 */ }
          reject({ kind: 'timeout', ms: Math.round(P.now() - started) });
        }, remaining);

        result.response.text().then(function (text) {
          if (settled) return;
          settled = true;
          window.clearTimeout(timer);
          resolve({ text: text, ms: result.ms, response: result.response });
        }, function () {
          if (settled) return;
          settled = true;
          window.clearTimeout(timer);
          reject({ kind: 'error', ms: Math.round(P.now() - started) });
        });
      });
    });
  };

  /* ------------------------------------------------------------ Cloudflare trace

     任何一个走 Cloudflare 的站点，/cdn-cgi/trace 都会回一段 key=value 文本，并带 Access-Control-Allow-Origin: *：
       fl=… h=… ip=出口地址 ts=边缘时间 visit_scheme uag colo=机房 sliver http=协议 loc=国家
       tls=版本 sni=plaintext|encrypted warp=off|on|plus gateway=off|on rbi=off|on kex=密钥交换
     这是本站读「Cloudflare 看到的你」的唯一入口：colo 就是你命中的节点，ip/loc 就是这一站看到的出口。 */
  P.parseTrace = function (text) {
    var out = {};
    String(text || '').split('\n').forEach(function (line) {
      var at = line.indexOf('=');
      if (at > 0) out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    });
    return out;
  };

  /* resolve({data, ms, text})；data 里没有 colo 或 ip 时按失败处理（被劫持到一张 HTML 页面之类）。 */
  P.trace = function (host, timeoutMs) {
    return P.text('https://' + host + '/cdn-cgi/trace', {}, timeoutMs || 6000).then(function (result) {
      var data = P.parseTrace(result.text);
      if (!data.colo || !data.ip) {
        return Promise.reject({ kind: 'error', ms: result.ms });
      }
      return { data: data, ms: result.ms, text: result.text };
    });
  };

  /* ------------------------------------------------------------ 调度

     限并发队列。add(task) 里 task 是一个返回 Promise 的函数，add 返回该 Promise 的结果。
     几十个探测同时发出去会互相抢连接，测出来的延迟比真实值高一截——所以都走这里排队。 */
  P.queue = function (lanes) {
    var running = 0;
    var waiting = [];

    var next = function () {
      if (running >= lanes || !waiting.length) return;
      var job = waiting.shift();
      running++;
      var done = function () { running--; next(); };
      Promise.resolve().then(job.task).then(function (value) {
        done();
        job.resolve(value);
      }, function (error) {
        done();
        job.reject(error);
      });
    };

    return {
      add: function (task) {
        return new Promise(function (resolve, reject) {
          waiting.push({ task: task, resolve: resolve, reject: reject });
          next();
        });
      }
    };
  };

  /* 中位数：偶数个取中间两个的平均并取整。空数组返回 null。 */
  P.median = function (list) {
    if (!list || !list.length) return null;
    var sorted = list.slice().sort(function (a, b) { return a - b; });
    var mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  };

  /* ------------------------------------------------------------ 机房代码 → 城市

     /assets/data/iata.json：{"colos":{"HKG":["香港","Hong Kong","HK",22.31,113.92], …}}
     数组依次是 中文名、英文名、国家代码、纬度、经度；中文名为空时显示英文名。
     页面根元素用 data-iata 给出带指纹的地址（View::asset），一页只取一次。 */
  var iataCache = {};

  P.iata = function (url) {
    if (!url) return Promise.resolve({});
    if (!iataCache[url]) {
      iataCache[url] = P.text(url, { cache: 'default', credentials: 'same-origin' }, 8000).then(function (result) {
        var data = JSON.parse(result.text);
        return data && data.colos ? data.colos : {};
      }).catch(function () {
        return {};
      });
    }
    return iataCache[url];
  };

  /* 查一个机房代码。查不到返回 {code, city: code, …}：未知代码原样显示，不报错。 */
  P.colo = function (colos, code) {
    var key = String(code || '').toUpperCase().trim();
    var row = colos && colos[key];
    if (!row) return { code: key, city: key, cityEn: '', cc: '', lat: null, lon: null, known: false };
    /* 英文页 city 直接给英文城市名，调用方不必区分语言 */
    var city = window.I18N && I18N.lang === 'en' ? (row[1] || row[0] || key) : (row[0] || row[1] || key);
    return { code: key, city: city, cityEn: row[1] || '', cc: row[2] || '', lat: row[3], lon: row[4], known: true };
  };

  /* ------------------------------------------------------------ 国家 / 国旗 / 距离 */

  var regionNames = null;
  try {
    if (window.Intl && Intl.DisplayNames) regionNames = new Intl.DisplayNames([window.I18N ? I18N.locale : 'zh-CN'], { type: 'region' });
  } catch (e) { regionNames = null; }

  /* 这四个不用 Intl 的名字：完整 ICU 给 HK 的是「中国香港特别行政区」，太长，塞不进窄列；
     给 TW 的是不带「中国」的「台湾」，与同页其余写法不一致。全站统一成下面这一套，各页面不再各自覆盖。 */
  var SHORT_NAMES = { CN: T('中国大陆', 'Mainland China'), HK: T('中国香港', 'Hong Kong'), MO: T('中国澳门', 'Macau'), TW: T('中国台湾', 'Taiwan') };

  P.flag = function (cc) {
    if (!/^[A-Za-z]{2}$/.test(cc || '') || !String.fromCodePoint) return '';
    cc = cc.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  };

  P.countryName = function (cc) {
    if (!/^[A-Za-z]{2}$/.test(cc || '')) return '';
    cc = cc.toUpperCase();
    if (SHORT_NAMES[cc]) return SHORT_NAMES[cc];
    try { return (regionNames && regionNames.of(cc)) || cc; } catch (e) { return cc; }
  };

  /* 「🇯🇵 日本」 */
  P.country = function (cc) {
    var name = P.countryName(cc);
    if (!name) return '';
    var flag = P.flag(cc);
    return flag ? flag + ' ' + name : name;
  };

  /* 球面距离（公里），任一坐标缺失返回 null */
  P.distance = function (lat1, lon1, lat2, lon2) {
    if ([lat1, lon1, lat2, lon2].some(function (v) { return typeof v !== 'number' || isNaN(v); })) return null;
    var rad = Math.PI / 180;
    var dLat = (lat2 - lat1) * rad;
    var dLon = (lon2 - lon1) * rad;
    var a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
      + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return Math.round(6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
  };

  /* ------------------------------------------------------------ 节点远近

     /cloudflare、/cdn、首页共用同一套远近分档，同一个节点在几页上不会得到不同的结论：
       就近接入  ≤1000 km；或节点在出口的「周边节点」表里；或与出口同国且 ≤3000 km
       区域内    ≤3000 km；或与出口同国（美国、俄罗斯、巴西这样的大国，境内跨几千公里不算绕到别的地区）
       跨区接入  其余
     没有距离（访客坐标或节点坐标缺失）时只看国家与周边表：命中算就近，否则 unknown，由页面显示中性的「已识别」。

     「周边节点」：出口在这些地区时，命中表里的节点也算就近。
     中国大陆的境外网络落点最好也就是香港、台北、东京、首尔、新加坡——它们离得不算近，但已经是能给到的最优解；
     境内节点（中国网络）按国家相同直接算就近，不必列在这里。 */
  P.NEAR_KM = 1000;
  P.REGION_KM = 3000;

  var NEARBY = {
    CN: ['HKG', 'TPE', 'NRT', 'KIX', 'ICN', 'SIN'],
    HK: ['HKG', 'SZX', 'CAN', 'MFM'],
    MO: ['MFM', 'HKG'],
    TW: ['TPE', 'KHH', 'HKG'],
    JP: ['NRT', 'KIX', 'FUK', 'OKA'],
    KR: ['ICN', 'NRT'],
    SG: ['SIN', 'KUL', 'CGK'],
    MY: ['KUL', 'SIN']
  };

  /* colo 是 P.colo() 的结果（要用 code 与 cc），loc 是出口所在国家代码，km 是距离（可为 null）。
     返回 'near' | 'region' | 'far' | 'unknown'。 */
  P.distanceClass = function (colo, loc, km) {
    var code = String(loc || '').toUpperCase();
    var nodeCode = colo && colo.code ? String(colo.code).toUpperCase() : '';
    var nearby = !!nodeCode && (NEARBY[code] || []).indexOf(nodeCode) !== -1;
    var sameCountry = !!(colo && colo.cc) && colo.cc === code;

    if (typeof km === 'number' && !isNaN(km)) {
      if (km <= P.NEAR_KM || nearby || (sameCountry && km <= P.REGION_KM)) return 'near';
      if (km <= P.REGION_KM || sameCountry) return 'region';
      return 'far';
    }

    return sameCountry || nearby ? 'near' : 'unknown';
  };

  /* 各档的文字与语气（对应 .tag--ok / --muted / --warn），各页统一用这一套 */
  P.DISTANCE_LABELS = {
    near: [T('就近接入', 'Nearby'), 'ok'],
    region: [T('区域内', 'In region'), 'muted'],
    far: [T('跨区接入', 'Cross-region'), 'warn'],
    unknown: [T('已识别', 'Identified'), 'muted']
  };

  /* ------------------------------------------------------------ IP */

  P.isIPv6 = function (ip) {
    return String(ip || '').indexOf(':') !== -1;
  };

  /* IPv6 的写法不唯一（前导零、:: 的位置），比较前展开成 8 组 4 位 */
  P.ipKey = function (value) {
    var ip = String(value || '').trim().toLowerCase();
    if (ip.indexOf(':') === -1) return /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip) ? ip : '';
    if (ip.indexOf('.') !== -1) {
      var last = ip.lastIndexOf(':');
      var bytes = ip.slice(last + 1).split('.').map(Number);
      if (bytes.length !== 4 || bytes.some(function (b) { return !Number.isInteger(b) || b < 0 || b > 255; })) return '';
      ip = ip.slice(0, last + 1) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
    }
    var halves = ip.split('::');
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    var count = head.length + tail.length;
    if (halves.length > 2 || !head.concat(tail).every(function (g) { return /^[0-9a-f]{1,4}$/.test(g); }) || (halves.length === 2 ? count >= 8 : count !== 8)) return '';
    var fill = [];
    if (halves.length > 1) {
      for (var n = head.length + tail.length; n < 8; n++) fill.push('0');
    }
    return head.concat(fill, tail).map(function (g) { return ('0000' + g).slice(-4); }).join(':');
  };

  P.sameIp = function (a, b) {
    var key = P.ipKey(a);
    return !!key && key === P.ipKey(b);
  };

  /* 「出口」的统一口径：IPv4 按地址，IPv6 按 /64。隐私地址会定期更换后 64 位，
     不少代理也按连接从一个 /64 里随机挑源地址——逐个地址比较，一条线路能被算成好几个出口 */
  P.exitKey = function (ip) {
    var key = P.ipKey(ip);
    if (!key) return '';
    if (!P.isIPv6(ip)) return '4|' + key;
    return '6|' + key.split(':').slice(0, 4).join(':');
  };

  P.samePrefix64 = function (a, b) {
    return !!P.ipKey(a) && !!P.ipKey(b) && P.isIPv6(a) && P.isIPv6(b) && P.exitKey(a) === P.exitKey(b);
  };

  function comparisonIp(ip) {
    var key = P.ipKey(ip);
    if (key.indexOf('0000:0000:0000:0000:0000:ffff:') === 0) {
      var groups = key.split(':');
      var a = parseInt(groups[6], 16), b = parseInt(groups[7], 16);
      return [a >> 8, a & 255, b >> 8, b & 255].join('.');
    }
    return key ? ip : '';
  }

  P.compareExit = function (ip, knownIps) {
    ip = comparisonIp(ip);
    if (!ip) return 'uncompared';
    var sameFamily = knownIps.map(comparisonIp).filter(function (known) { return known && P.isIPv6(known) === P.isIPv6(ip); });
    if (sameFamily.some(function (known) { return P.sameIp(ip, known) || P.samePrefix64(ip, known); })) return 'match';
    return sameFamily.length ? 'different' : 'uncompared';
  };

  /* 长 IPv6 在窄列里收成「2001:db8…7334」，完整值放进 title */
  P.compactIp = function (ip) {
    ip = String(ip || '');
    if (ip.length <= 22 || !P.isIPv6(ip)) return ip;
    var parts = ip.split(':');
    return parts.slice(0, 2).join(':') + '…' + parts[parts.length - 1];
  };

  /* ------------------------------------------------------------ DOM */

  P.el = function (tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  };

  /* 失败原因的中文说明，三处共用同一套措辞 */
  P.failureText = function (kind) {
    if (kind === 'csp') return T('CSP 未放行', 'Blocked by CSP');
    if (kind === 'timeout') return T('超时', 'Timed out');
    return T('连接失败', 'Connection failed');
  };

  window.IpcxProbe = P;
})(window, document);
